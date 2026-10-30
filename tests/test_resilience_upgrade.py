import asyncio
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
from engine.gamelan import Gamelan
from engine.watchdog import WatchdogFailToWire
from kelir.session import SessionRegistry, Session
from kelir.scoring import SessionScorer
from kelir.proxy import Kelir
from shadows.modbus_shadow import ShadowDevice
from sim_attacker.real_sim import RealDeviceSim


def test_bounded_lru_cache_and_session_pruning():
    """Uji Komponen B: Bounded LRU OrderedDict mencegah ledakan RAM saat pemindaian massal."""
    reg = SessionRegistry(idle_s=300.0, prefix="test", max_sessions=5)

    # Tambahkan 5 sesi awal
    for i in range(1, 6):
        reg.get(f"192.168.1.{i}")
    assert len(reg.by_id) == 5

    # Tandai sesi #2 sebagai PINNED (sedang disadap di panggung bayangan)
    s2_id = list(reg.by_id.keys())[1]
    reg.by_id[s2_id].pinned = True

    # Tambahkan sesi ke-6 (harus memicu LRU pruning)
    reg.get("192.168.1.6")

    # Kapasitas tetap terjaga tidak melebihi batas
    assert len(reg.by_id) <= 5
    # Sesi #2 yang PINNED harus terlindungi dari pembersihan
    assert s2_id in reg.by_id
    # Sesi terbaru #6 harus ada
    assert "192.168.1.6" in reg.by_src


def test_operator_priority_isolation_and_qos_dedicated_pool():
    """Uji Komponen C: Alokasi koneksi terisolasi untuk operator sah (QoS Anti-Starvation)."""
    async def go():
        bus = Gamelan()
        reg = SessionRegistry()
        scorer = SessionScorer(whitelist={"10.0.0.1"})
        sh = ShadowDevice("d", "K", 1, reg, bus)
        real = RealDeviceSim()
        r = await real.serve("127.0.0.1", 0)
        real_port = r.sockets[0].getsockname()[1]

        k = Kelir("KODAM", ("127.0.0.1", real_port), sh, reg, scorer, bus)
        # Set kapasitas kecil untuk pengujian cepat
        k.max_global_conns = 10
        k.reserved_operator_slots = 3   # 3 slot eksklusif operator
        k.max_per_ip_conns = 4

        # Simulasi 7 koneksi penyerang asing (mencapai batas kapasitas unlisted: 10 - 3 = 7)
        k.active_conns = 7
        k.active_operator_conns = 0

        # Cek degradasi load percentage: 7 / 7 = 100%
        assert k.load_percentage >= 98.0
        assert k.degradation_tier == 4

        # Penyerang ke-8 mencoba koneksi: ditolak oleh governor pool
        class DummyWriter:
            def __init__(self, ip):
                self.ip = ip
                self.closed = False
            def get_extra_info(self, key):
                return (self.ip, 12345)
            def close(self):
                self.closed = True

        w_attacker = DummyWriter("198.51.100.99")
        await k.handle_client(None, w_attacker)
        assert w_attacker.closed
        assert k.stats["conns_rejected_pool"] == 1

        r.close()

    asyncio.run(go())


def test_multi_tier_degradation_ladder_transitions():
    """Uji Komponen A: Transisi tangga degradasi cerdas (Tier 1 -> Tier 2 -> Tier 3 -> Tier 4)."""
    reg = SessionRegistry()
    scorer = SessionScorer()
    sh = ShadowDevice("d", "K", 1, reg)
    k = Kelir("KODAM", ("127.0.0.1", 502), sh, reg, scorer, Gamelan())
    k.max_global_conns = 100
    k.reserved_operator_slots = 20  # unlisted cap = 80

    # 1. Beban 50% (< 75%) -> Tier 1 (High-Interaction Normal)
    k.active_conns = 40
    k.active_operator_conns = 0
    assert k.load_percentage == 50.0
    assert k.degradation_tier == 1

    # 2. Beban 80% (75-90%) -> Tier 2 (Stateless Mirror Decoy)
    k.active_conns = 64
    assert k.load_percentage == 80.0
    assert k.degradation_tier == 2

    # 3. Beban 95% (90-98%) -> Tier 3 (OT Tarpit)
    k.active_conns = 76
    assert k.load_percentage == 95.0
    assert k.degradation_tier == 3

    # 4. Beban 100% (>= 98%) -> Tier 4 (Kernel Drop)
    k.active_conns = 80
    assert k.load_percentage == 100.0
    assert k.degradation_tier == 4


def test_watchdog_fail_to_wire_relay():
    """Uji Komponen D: Hardware Watchdog & Fail-to-Wire Relay."""
    relay_events = []
    def relay_action(state: bool):
        relay_events.append(state)

    watchdog = WatchdogFailToWire("KODAM", heartbeat_interval_s=0.1, miss_threshold=3,
                                  relay_actuator=relay_action)

    assert not watchdog.is_bypass_active

    # Simulasi 2 detak jantung gagal (belum melampaui ambang batas 3)
    watchdog.record_heartbeat(False)
    watchdog.record_heartbeat(False)
    assert not watchdog.is_bypass_active
    assert len(relay_events) == 0

    # Detak jantung gagal ke-3: memicu fail-to-wire bypass!
    watchdog.record_heartbeat(False)
    assert watchdog.is_bypass_active
    assert len(relay_events) == 1
    assert relay_events[-1] is True  # Relai tertutup (bypass langsung ke PLC)

    # Detak jantung pulih 3x berturut-turut: disengage bypass
    watchdog.record_heartbeat(True)
    watchdog.record_heartbeat(True)
    assert watchdog.is_bypass_active  # Masih menunggu stabil
    watchdog.record_heartbeat(True)
    assert not watchdog.is_bypass_active
    assert relay_events[-1] is False  # Relai terbuka kembali ke proxy


def test_sweep_1000_registers():
    """Uji Sapuan 1.000 Register: Memastikan peta peralatan realistis dan celah alamat mengembalikan Exception 02."""
    from shadows import modbus_proto as mp
    reg = SessionRegistry()
    sh = ShadowDevice("d", "K", 1, reg)
    s = reg.get("192.168.1.100")
    s.engine.depth = 2

    valid_input_addrs = {0, 1, 2, 3, 4, 5, 6, 7, 8, 10,
                         100, 101, 102, 103, 104, 110, 111, 112, 113, 120, 121,
                         200, 201, 202, 203, 210,
                         300, 301, 302, 303, 304, 305, 310}

    valid_holding_addrs = {0, 1, 2, 10, 11, 20, 21,
                           100, 105, 110, 115,
                           200, 202, 210,
                           300, 301, 305}

    # Sapuan 1.000 register (0 hingga 999)
    for addr in range(1000):
        # 1. Input Registers
        if addr in valid_input_addrs:
            res = sh._read(s, "input", addr, 1)
            assert len(res) == 1
            assert isinstance(res[0], int)
        else:
            with pytest.raises(mp.ProtoError) as exc:
                sh._read(s, "input", addr, 1)
            assert exc.value.code == mp.ILLEGAL_ADDRESS

        # 2. Holding Registers
        if addr in valid_holding_addrs:
            res = sh._read(s, "holding", addr, 1)
            assert len(res) == 1
            assert isinstance(res[0], int)
        else:
            with pytest.raises(mp.ProtoError) as exc:
                sh._read(s, "holding", addr, 1)
            assert exc.value.code == mp.ILLEGAL_ADDRESS


def test_diverted_write_operational_alert():
    """Uji Peringatan Operasional Penulisan yang Dialihkan: Memastikan operator jaga mendapat peringatan langsung."""
    async def go():
        from sim_attacker.modbus_client import ModbusClient
        from engine.pipeline import Pipeline
        from evidence.hashchain import HashChain
        from evidence.session_store import SessionStore
        from engine.attck_map import AttckMapper
        from engine.autonomy import Autonomy
        from engine.approval import ApprovalQueue
        from console.bot import BotDalang, ConsoleChannel

        bus = Gamelan()
        reg = SessionRegistry()
        scorer = SessionScorer()
        sh = ShadowDevice("d", "K", 1, reg, bus)
        real = RealDeviceSim()
        r = await real.serve("127.0.0.1", 0)
        real_port = r.sockets[0].getsockname()[1]

        import tempfile
        tmp_dir = tempfile.mkdtemp()
        store = SessionStore()
        chain = HashChain()
        channel = ConsoleChannel()
        autonomy = Autonomy()
        from engine.autonomy import Blocklist
        blocklist = Blocklist()
        approvals = ApprovalQueue(tmp_dir, blocklist)
        bot = BotDalang(channel, approvals, autonomy)
        pipeline = Pipeline("KODAM", reg, store, chain, AttckMapper(), autonomy, approvals, bot=bot)
        bus.subscribe(pipeline.on_event)

        k = Kelir("KODAM", ("127.0.0.1", real_port), sh, reg, scorer, bus)
        server = await k.serve("127.0.0.1", 0)
        kport = server.sockets[0].getsockname()[1]

        # Penyerang atau teknisi belum terdaftar mengirim perintah tulis
        async with ModbusClient("127.0.0.1", kport, local_addr="192.168.1.88") as c:
            await c.write_reg(11, 0)

        # 1. Pastikan nilai tulis TIDAK sampai ke PLC riil
        assert len(real.writes) == 0

        # 2. Pastikan alert penulisan dialihkan diterbitkan
        write_alerts = [a for a in pipeline.alerts if a["kind"] == "diverted_write"]
        assert len(write_alerts) >= 1
        assert "dialihkan ke bayangan" in write_alerts[0]["text"]

        # 3. Pastikan Bot Dalang mengirim pesan peringatan darurat ke kanal operator
        bot_msgs = [m for m in channel.messages if "PERINGATAN OPERASIONAL" in m["text"]]
        assert len(bot_msgs) >= 1
        assert "PERINTAH TULIS DIBUANG DARI PLC RIIL" in bot_msgs[0]["text"]

        server.close()
        r.close()

    asyncio.run(go())


def test_watchdog_failover_latency_measured():
    """Uji Pengukuran Waktu Pulih Failover Watchdog: Mengukur latensi aktivasi fail-to-wire bypass."""
    async def go():
        failover_times = []
        bypass_trigger_time = 0.0

        def relay_action(state: bool):
            nonlocal bypass_trigger_time
            if state:
                bypass_trigger_time = asyncio.get_event_loop().time()

        # Interval 25 ms, ambang batas 3 missed beats
        watchdog = WatchdogFailToWire("KODAM", heartbeat_interval_s=0.025, miss_threshold=3,
                                      relay_actuator=relay_action)

        proxy_healthy = True
        def probe():
            return proxy_healthy

        watchdog.start(probe)

        # Berjalan normal 2 detak jantung
        await asyncio.sleep(0.06)
        assert not watchdog.is_bypass_active

        # Simulasi crash / freeze mendadak pada proxy Kelir
        freeze_time = asyncio.get_event_loop().time()
        proxy_healthy = False

        # Tunggu sampai bypass aktif
        for _ in range(20):
            if watchdog.is_bypass_active:
                break
            await asyncio.sleep(0.01)

        watchdog.stop()
        assert watchdog.is_bypass_active

        failover_ms = (bypass_trigger_time - freeze_time) * 1000
        # 3 interval x 25 ms = ~75 ms
        assert 50 <= failover_ms <= 150, f"Failover time {failover_ms} ms di luar toleransi yang diharapkan"

    asyncio.run(go())
