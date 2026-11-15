"""Tes Gerbang Bypass: jalur normal lewat Kelir, bypass aman khusus operator, baca-saja,
deteksi Kelir membeku sungguhan, pemulihan, dan kunci anti-flapping."""
import asyncio
import struct
import time

from engine.watchdog import WatchdogFailToWire
from node import SatuanNode
from shadows import modbus_proto as mp
from sim_attacker.modbus_client import ModbusClient, values
from sim_attacker.real_sim import RealDeviceSim


async def _make(tmp_path, whitelist):
    real = RealDeviceSim()
    rs = await real.serve("127.0.0.1", 0)
    n = SatuanNode("U-gerbang", 3, ("127.0.0.1", rs.sockets[0].getsockname()[1]),
                   str(tmp_path), set(whitelist), time_scale=60, lab_mode=True, bypass=True)
    await n.start(with_hmi=False)
    return real, rs, n


async def _wait(cond, timeout=3.0):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if cond():
            return True
        await asyncio.sleep(0.02)
    return False


async def _read_or_none(port):
    try:
        async with ModbusClient("127.0.0.1", port, timeout=1.5) as c:
            return values(await c.read(3, 0, 2))
    except (OSError, asyncio.TimeoutError, AttributeError):
        return None


def test_normal_path_goes_through_kelir_with_real_ip(tmp_path):
    async def go():
        real, rs, n = await _make(tmp_path, {"127.0.0.1"})
        try:
            assert n.ports["kelir"] != n.ports["kelir_internal"]
            assert await _read_or_none(n.ports["kelir"]) is not None
            # Kelir mengenali klien sebagai operator -> IP asli terbawa lewat header PROXY
            assert n.kelir.stats["forwarded_operator"] >= 1
            assert n.gerbang.status()["mode"] == "NORMAL"
            # Port internal Kelir menolak koneksi tanpa header PROXY
            assert await _read_or_none(n.ports["kelir_internal"]) is None
        finally:
            await n.stop(); rs.close()
    asyncio.run(go())


def test_bypass_is_operator_only_and_read_only(tmp_path):
    async def go():
        real, rs, n = await _make(tmp_path, {"127.0.0.1"})
        try:
            n.simulate_proxy_fault(30)
            assert await _wait(lambda: n.gerbang.bypass)
            port = n.ports["kelir"]
            before = len(real.writes)
            async with ModbusClient("127.0.0.1", port) as c:
                assert values(await c.read(3, 0, 2)) is not None          # baca lolos
                resp = await c.call(struct.pack(">BHH", 6, 0, 0xDEAD))      # tulis ditahan
                assert resp == mp.exception_pdu(6, mp.ILLEGAL_FUNCTION)
            assert len(real.writes) == before                                # PLC tak tersentuh
            st = n.gerbang.status()
            assert st["stats"]["bypass_reads"] >= 1 and st["stats"]["bypass_writes_blocked"] == 1

            n.whitelist.discard("127.0.0.1")                                 # kini bukan operator
            assert await _read_or_none(port) is None
            assert n.gerbang.stats["bypass_dropped"] >= 1
            n.whitelist.add("127.0.0.1")

            n.simulate_proxy_fault(0)                                        # Kelir "pulih"
            assert await _wait(lambda: not n.gerbang.bypass)
            assert await _read_or_none(port) is not None
            await asyncio.sleep(0.1)
            acts = [a["kind"] for a in n.pipeline.alerts]
            assert "bypass" in acts
        finally:
            await n.stop(); rs.close()
    asyncio.run(go())


def test_real_event_loop_freeze_triggers_bypass(tmp_path, monkeypatch):
    monkeypatch.setenv("WAYANG_BYPASS_STALL_S", "0.5")
    async def go():
        real, rs, n = await _make(tmp_path, {"127.0.0.1"})
        try:
            assert n.bypass_stall_s == 0.5
            assert not n.gerbang.bypass
            time.sleep(2.0)               # bekukan event loop Kelir sungguhan (bukan simulasi)
            assert n.gerbang.bypass       # Gerbang di thread sendiri sudah mengambil alih
            assert await _wait(lambda: not n.gerbang.bypass)   # loop jalan lagi -> pulih
        finally:
            await n.stop(); rs.close()
    asyncio.run(go())


def test_flapping_locks_bypass_until_operator_confirms():
    t = [0.0]
    switched = []
    wd = WatchdogFailToWire("U", miss_threshold=1, flap_limit=2, flap_window_s=600,
                            relay_actuator=switched.append, clock=lambda: t[0])
    for _ in range(2):                    # dua kali jatuh-bangun
        wd.record_heartbeat(False); t[0] += 1
        wd.record_heartbeat(True); t[0] += 1
    assert wd.is_bypass_active and wd.locked
    for _ in range(5):
        wd.record_heartbeat(True)
    assert wd.is_bypass_active            # sehat pun tetap terkunci
    wd.healthy_beats = 0
    ok, _ = wd.confirm_restore("Pa Jaga")
    assert not ok and wd.is_bypass_active  # proxy belum terbukti sehat -> ditolak
    wd.record_heartbeat(True)
    ok, _ = wd.confirm_restore("Pa Jaga")
    assert ok and not wd.is_bypass_active and not wd.locked
    assert switched[-1] is False
