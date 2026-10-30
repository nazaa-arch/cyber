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
