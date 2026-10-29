import asyncio
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from shadows import modbus_proto as mp
from engine.gamelan import Gamelan
from kelir.session import SessionRegistry
from kelir.scoring import SessionScorer
from kelir.proxy import Kelir
from kelir.mirror import StateMirror
from shadows.modbus_shadow import ShadowDevice
from sim_attacker.real_sim import RealDeviceSim


class Client:
    def __init__(self, host, port):
        self.host, self.port, self.tid = host, port, 0

    async def __aenter__(self):
        self.r, self.w = await asyncio.open_connection(self.host, self.port)
        return self

    async def __aexit__(self, *a):
        self.w.close()

    async def call(self, pdu, unit=1):
        self.tid += 1
        self.w.write(mp.build_mbap(self.tid, unit, pdu))
        await self.w.drain()
        fr = await asyncio.wait_for(mp.read_frame(self.r), 3)
        return None if fr is None else fr[2]

    async def read(self, fc, addr, qty=1, unit=1):
        return await self.call(mp.build_read_request(fc, addr, qty), unit)

    async def write_reg(self, addr, val, unit=1):
        import struct
        return await self.call(struct.pack(">BHH", 6, addr, val), unit)


async def make_stack(whitelist=("127.0.0.2",), level=2):
    from engine.autonomy import Autonomy
    real = RealDeviceSim()
    rs = await real.serve("127.0.0.1", 0)
    rport = rs.sockets[0].getsockname()[1]
    bus, events = Gamelan(), []
    bus.subscribe(events.append)
    reg = SessionRegistry()
    shadow = ShadowDevice("depo_bbm_01", "Kodim-DEMO-03", 3, reg, bus, time_scale=60)
    mirror = StateMirror(("127.0.0.1", rport))
    await mirror.poll_once()
    k = Kelir("Kodim-DEMO-03", ("127.0.0.1", rport), shadow, reg,
              SessionScorer(set(whitelist)), bus, Autonomy(level), mirror=mirror)
    ks = await k.serve("127.0.0.1", 0)
    kport = ks.sockets[0].getsockname()[1]
    return real, k, shadow, events, kport, (rs, ks)


def test_proto_roundtrip_and_errors():
    r = mp.parse_pdu(mp.build_read_request(3, 10, 2))
    assert (r.fc, r.addr, r.qty) == (3, 10, 2)
    import pytest
    with pytest.raises(mp.ProtoError):
        mp.parse_pdu(bytes([0x7F, 0, 0]))
    with pytest.raises(mp.ProtoError):
        mp.parse_pdu(mp.build_read_request(3, 0, 0))


def test_shadow_divert_never_touches_real_and_state_continues():
    async def go():
        real, k, shadow, events, kport, servers = await make_stack()
        try:
            async with Client("127.0.0.1", kport) as c:
                before = await c.read(4, 0, 2)                  # unlisted read -> real
                assert before[0] == 4
                w = await c.write_reg(11, 0)                     # write -> divert
                assert w[0] == 6                                 # penyerang merasa berhasil
                after = await c.read(4, 0, 2)
            assert not real.writes                               # aset asli tidak tersentuh
            assert any(e["action"] == "shadow_divert" for e in events)
            # nilai tidak melompat: kontinu dari cermin (selisih kecil)
            v0 = int.from_bytes(before[2:4], "big")
            v1 = int.from_bytes(after[2:4], "big")
            assert abs(v0 - v1) <= 30
            # pinned: permintaan berikut tidak mencapai aset asli
            n = len(real.frames)
            async with Client("127.0.0.1", kport) as c:
                await c.read(4, 0, 2)
            assert len(real.frames) == n
        finally:
            for s in servers:
                s.close()
    asyncio.run(go())


def test_whitelist_passes_to_real_including_writes():
    async def go():
        real, k, shadow, events, kport, servers = await make_stack(whitelist=("127.0.0.1",))
        try:
            async with Client("127.0.0.1", kport) as c:
                await c.write_reg(11, 0)
            assert len(real.writes) == 1
            assert not events
        finally:
            for s in servers:
                s.close()
    asyncio.run(go())


def test_l0_does_not_divert_only_records():
    async def go():
        real, k, shadow, events, kport, servers = await make_stack(level=0)
        try:
            async with Client("127.0.0.1", kport) as c:
                await c.write_reg(11, 0)
            assert any(e["action"] == "would_divert" for e in events)
            assert not any(e["action"] == "shadow_divert" for e in events)
        finally:
            for s in servers:
                s.close()
    asyncio.run(go())


def test_depth_reveals_registers_and_fake_effect():
    # bayangan langsung (tanpa Kelir)
    async def go2():
        bus = Gamelan(); ev = []; bus.subscribe(ev.append)
        reg = SessionRegistry()
        sh = ShadowDevice("d", "K", 5, reg, bus, time_scale=60)
        srv = await sh.serve("127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            async with Client("127.0.0.1", port) as c:
                r = await c.read(4, 3, 1)
                assert r[0] == 0x84
                for a in range(0, 6):                            # enumerasi -> depth 2
                    await c.read(4, a, 1)
                r = await c.read(4, 3, 1)
                assert r[0] == 4
                w = await c.write_reg(11, 0)                     # depth 3: efek palsu
                assert w[0] == 6
                assert reg.get("127.0.0.1").engine.depth >= 3
                assert (await c.read(3, 11, 1))[2:4] == b"\x00\x00"
        finally:
            srv.close()
    asyncio.run(go2())


def test_consistency_probe_freezes_depth():
    bus = Gamelan(); reg = SessionRegistry()
    sh = ShadowDevice("d", "K", 5, reg, bus, time_scale=60)
    for _ in range(9):
        sh.handle("9.9.9.9", 1, mp.build_read_request(4, 0, 1))
    s = reg.get("9.9.9.9")
    assert s.engine.high_tier and s.engine.frozen
    d = s.engine.depth
    sh.handle("9.9.9.9", 1, bytes([6, 0, 11, 0, 0]))
    assert s.engine.depth == d


def test_blocklist_and_l3():
    async def go():
        real, k, shadow, events, kport, servers = await make_stack(level=3)
        try:
            for _ in range(3):
                s = k.sessions
                async with Client("127.0.0.1", kport) as c:
                    await c.write_reg(11, 0)
                # sesi baru untuk tiap pengulangan
                for sess in list(s.by_src.values()):
                    sess.last -= 10_000
            assert k.blocklist.is_blocked("127.0.0.1")
        finally:
            for s in servers:
                s.close()
    asyncio.run(go())
