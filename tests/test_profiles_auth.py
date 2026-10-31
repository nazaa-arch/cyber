import asyncio
import struct
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import httpx
import pytest

from console.api import make_console_app
from console.pusat import Link, Pusat
from engine.gamelan import Gamelan
from kelir.session import SessionRegistry
from node import SatuanNode
from shadows import modbus_proto as mp
from shadows.modbus_shadow import ShadowDevice
from sim_attacker.real_sim import RealDeviceSim


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _val(resp):
    return mp.parse_response_values(resp)[0]


def _attack_profile(kind, write_addr, reg_addr):
    clk = FakeClock()
    sh = ShadowDevice("x", "S", 7, SessionRegistry(), Gamelan(), clock=clk,
                      time_scale=1.0, kind=kind)
    src = "203.0.113.9"
    for a in range(0, 4):                                   # pengintaian -> enumerasi
        sh.handle(src, 1, mp.build_read_request(4, a, 1))
        clk.t += 0.2
    before = _val(sh.handle(src, 1, mp.build_read_request(4, reg_addr, 1))[0])
    sh.handle(src, 1, struct.pack(">BHH", 6, write_addr, 0))
    sh.handle(src, 1, struct.pack(">BHH", 6, write_addr, 0))
    s = sh.sessions.get(src, clk.t)
    s.engine.depth = 3
    clk.t += 60.0
    after = _val(sh.handle(src, 1, mp.build_read_request(4, reg_addr, 1))[0])
    return sh, s, before, after


def test_genset_profile_trip_effect_and_gap():
    sh, s, before, after = _attack_profile("genset", 20, 10)
    assert before > 20 and after <= 1                       # daya jatuh ke ~0 kW
    assert not s.pump_on and s.writes
    out = sh.handle("203.0.113.9", 1, mp.build_read_request(4, 500, 1))[0]
    assert out[0] == 0x84 and out[1] == mp.ILLEGAL_ADDRESS   # celah alamat -> Exception 02
    assert sh.idobj[0] == "DeepSea Electronics"


def test_gate_profile_unlock_opens_gate():
    sh, s, before, after = _attack_profile("cctv", 30, 0)
    assert before == 0 and after >= 85                      # palang terbuka ~90 derajat
    assert not s.pump_on


def test_gateway_profile_uplink_drop():
    sh, s, before, after = _attack_profile("gateway", 40, 0)
    assert before > 1000 and after < 200


def test_twinscreen_reads_real_mirror_per_kind(tmp_path):
    async def go():
        pusat = Pusat(); link = Link(pusat)
        nodes, closers = {}, []
        for kind in ("genset", "cctv", "gateway", "bbm"):
            real = RealDeviceSim(kind=kind)
            rs = await real.serve("127.0.0.1", 0)
            closers.append(rs)
            n = SatuanNode(f"U-{kind}", 3, ("127.0.0.1", rs.sockets[0].getsockname()[1]),
                           str(tmp_path / kind), set(), time_scale=60, transport=link,
                           lab_mode=True, kind=kind)
            pusat.register_unit(n.satuan, -6.9, 107.6)
            await n.start(with_hmi=False)
            await n.mirror.poll_once()
            nodes[n.satuan] = n
        try:
            app = make_console_app(nodes, pusat)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="http://c") as c:
                g = (await c.get("/api/twinscreen/U-genset")).json()
                assert g["asset_type"] == "genset" and g["aset_asli"]["power_load_kw"] == 46.8
                assert "StateMirror" in g["aset_asli"]["sumber"]
                k = (await c.get("/api/twinscreen/U-cctv")).json()
                assert k["asset_type"] == "cctv" and k["aset_asli"]["gate_is_open"] is False
                w = (await c.get("/api/twinscreen/U-gateway")).json()
                assert w["asset_type"] == "gateway" and w["aset_asli"]["throughput_gbps"] == 1.25
                assert "TERVERIFIKASI" in w["aset_asli"]["hashchain_status"]
                b = (await c.get("/api/twinscreen/U-bbm")).json()
                assert b["asset_type"] == "bbm" and b["aset_asli"]["tangki_level_l"] == 14250
        finally:
            for n in nodes.values():
                await n.stop()
            for rs in closers:
                rs.close()
    asyncio.run(go())


def test_console_auth_flow(tmp_path):
    async def go():
        pusat = Pusat()
        real = RealDeviceSim(); rs = await real.serve("127.0.0.1", 0)
        n = SatuanNode("U-auth", 3, ("127.0.0.1", rs.sockets[0].getsockname()[1]),
                       str(tmp_path), set(), time_scale=60, lab_mode=True)
        pusat.register_unit("U-auth", -6.9, 107.6)
        try:
            app = make_console_app({n.satuan: n}, pusat, admin_token="s3cr3t-token")
            tr = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=tr, base_url="http://c") as c:
                assert (await c.get("/")).status_code == 200                 # UI statis publik
                assert (await c.get("/api/map")).status_code == 401
                assert (await c.post("/api/killswitch")).status_code == 401
                assert (await c.post("/api/tactical/campaign/resolve", json={})).status_code == 401
                st = (await c.get("/api/auth/status")).json()
                assert st == {"required": True, "authed": False}
                h = {"X-Wayang-Token": "s3cr3t-token"}
                assert (await c.get("/api/map", headers=h)).status_code == 200
                assert (await c.get("/api/map", headers={"X-Wayang-Token": "salah"})).status_code == 401
                bad = await c.post("/api/auth/login", json={"token": "salah"})
                assert bad.status_code == 401
                ok = await c.post("/api/auth/login", json={"token": "s3cr3t-token"})
                assert ok.status_code == 200 and "wayang_token" in ok.headers.get("set-cookie", "")
                assert "httponly" in ok.headers["set-cookie"].lower()
                assert (await c.get("/api/map")).status_code == 200          # cookie sesi dipakai
                assert (await c.get("/api/auth/status")).json()["authed"] is True
        finally:
            rs.close()
    asyncio.run(go())


def test_console_login_rate_limited(tmp_path):
    async def go():
        pusat = Pusat()
        real = RealDeviceSim(); rs = await real.serve("127.0.0.1", 0)
        n = SatuanNode("U-rl", 3, ("127.0.0.1", rs.sockets[0].getsockname()[1]),
                       str(tmp_path), set(), time_scale=60, lab_mode=True)
        try:
            app = make_console_app({n.satuan: n}, pusat, admin_token="abc")
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="http://c") as c:
                codes = [(await c.post("/api/auth/login", json={"token": "x"})).status_code
                         for _ in range(7)]
                assert codes[:5] == [401] * 5 and codes[5] == 429
                good = await c.post("/api/auth/login", json={"token": "abc"})
                assert good.status_code == 429                                # terkunci sementara
        finally:
            rs.close()
    asyncio.run(go())


def test_auth_disabled_by_default_for_library_use(tmp_path):
    async def go():
        pusat = Pusat()
        real = RealDeviceSim(); rs = await real.serve("127.0.0.1", 0)
        n = SatuanNode("U-open", 3, ("127.0.0.1", rs.sockets[0].getsockname()[1]),
                       str(tmp_path), set(), time_scale=60, lab_mode=True)
        pusat.register_unit("U-open", -6.9, 107.6)
        try:
            app = make_console_app({n.satuan: n}, pusat)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="http://c") as c:
                assert (await c.get("/api/map")).status_code == 200
        finally:
            rs.close()
    asyncio.run(go())
