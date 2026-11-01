import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from console import bot as botmod
from console.bot import TelegramChannel
from console.pusat import Pusat
from evidence.session_store import SessionStore
from node import SatuanNode


def test_telegram_send_retries_until_success(monkeypatch):
    ch = TelegramChannel("123:abc", 1)
    calls = []

    def fake_send(payload):
        calls.append(1)
        return 0 if len(calls) < 3 else 77

    monkeypatch.setattr(ch, "_send_sync", fake_send)
    monkeypatch.setattr(botmod.time, "sleep", lambda s: None)
    assert ch._send_retry({"text": "x"}) == 77
    assert len(calls) == 3


def test_telegram_send_gives_up_after_attempts(monkeypatch):
    ch = TelegramChannel("123:abc", 1)
    monkeypatch.setattr(ch, "_send_sync", lambda p: 0)
    monkeypatch.setattr(botmod.time, "sleep", lambda s: None)
    assert ch._send_retry({"text": "x"}, attempts=3) == 0


def test_campaign_resolve_and_reset_lifecycle():
    p = Pusat()
    p.register_unit("A", -6.0, 106.0)
    p.register_unit("B", -7.0, 110.0)
    p.campaign_list = [{"id": "k1", "satuan": ["A", "B"], "bukti": "x",
                        "urutan_sentuh": [{"satuan": "A", "first_wall": 1.0},
                                          {"satuan": "B", "first_wall": 2.0}]}]
    p.corr.sessions[("A", "s1")] = {"satuan": "A"}
    assert p.status("A") == "Kampanye Terdeteksi"
    assert p.get_campaign_vectors()
    assert p.resolve_campaigns("k1") == ["k1"]
    assert p.status("A") == "Aman" and p.status("B") == "Aman"
    assert p.get_campaign_vectors() == []
    p.reset_incidents()
    assert p.campaign_list == [] and not p.corr.sessions and not p.resolved_campaigns


def test_persistent_store_survives_restart_with_unique_session_ids(tmp_path):
    db = str(tmp_path / "sessions.db")
    n1 = SatuanNode("U-persist", 3, ("127.0.0.1", 1), str(tmp_path), set(), db_path=db)
    n1.store.put_session({"satuan": "U-persist", "session": "persist-1", "src": "1.2.3.4",
                          "stage": "recon", "depth": 1, "diverted": False, "techniques": [],
                          "event_count": 1, "high_tier": False, "first_wall": 1.0})
    n2 = SatuanNode("U-persist", 3, ("127.0.0.1", 1), str(tmp_path), set(), db_path=db)
    assert any(s["session"] == "persist-1" for s in n2.store.sessions())
    assert "-" in n2.sessions.prefix and len(n2.sessions.prefix.split("-")) >= 2   # ada cap waktu
    mem = SatuanNode("U-mem", 3, ("127.0.0.1", 1), str(tmp_path / "m"), set())
    assert mem.sessions.prefix == "mem"                                          # mode memori tak berubah


def test_simulate_per_satuan_dpi_docx_and_sandbox_reset(tmp_path):
    import asyncio, httpx
    from console.api import make_console_app
    from console.pusat import Link, Pusat
    from sim_attacker.real_sim import RealDeviceSim

    async def go():
        pusat = Pusat(bot=None)
        pusat.corr.k = 2
        link = Link(pusat)
        nodes, reals, servers = {}, {}, []
        for idx, kind in enumerate(("bbm", "genset", "cctv", "gateway")):
            real = RealDeviceSim(kind=kind)
            rs = await real.serve("127.0.0.1", 0)
            servers.append(rs)
            name = f"U-{kind}"
            n = SatuanNode(name, 10 + idx, ("127.0.0.1", rs.sockets[0].getsockname()[1]),
                           str(tmp_path / name), set(), time_scale=60, transport=link,
                           lab_mode=True, kind=kind)
            pusat.register_unit(name, -6.2 - idx * 0.3, 106.8 + idx * 0.5)
            await n.start(with_hmi=False)
            await n.mirror.poll_once()
            nodes[name] = n
            reals[name] = real

        try:
            app = make_console_app(nodes, pusat, admin_token="tok-uji")
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://c") as c:
                lg = await c.post("/api/auth/login", json={"token": "tok-uji"})
                assert lg.status_code == 200
                assert "samesite=lax" in lg.headers.get("set-cookie", "").lower()

                # 1. Simulasi T2 mengikuti masing-masing satuan dan memicu efek bayangan spesifik
                for name in ("U-genset", "U-cctv", "U-gateway", "U-bbm"):
                    r = await c.post("/api/simulate/t2", json={"satuan": name})
                    assert r.status_code == 200 and r.json()["satuan"] == name
                    assert reals[name].writes == []

                tw_g = (await c.get("/api/twinscreen/U-genset")).json()
                assert tw_g["panggung_bayangan"]["trip"] is True
                assert tw_g["panggung_bayangan"]["perintah_bahaya_ditangkap"] >= 1
                assert tw_g["aset_asli"]["perintah_bahaya_diterima"] == 0

                tw_c = (await c.get("/api/twinscreen/U-cctv")).json()
                assert tw_c["panggung_bayangan"]["gate_is_open"] is True

                tw_w = (await c.get("/api/twinscreen/U-gateway")).json()
                assert "DIPUTUS" in tw_w["panggung_bayangan"]["consensus_nodes"]

                tw_b = (await c.get("/api/twinscreen/U-bbm")).json()
                assert "MATI" in tw_b["panggung_bayangan"]["pompa_status"]

                # 2. DPI Hex menampilkan rekonstruksi frame nyata (FC 6 / FC 43), bukan statis FC 3
                pkts = (await c.get("/api/packets/recent")).json()
                fcs = {p["pdu"]["function_code"] for p in pkts}
                assert 6 in fcs and 43 in fcs
                assert any(p["anomaly_level"] == "CRITICAL" for p in pkts)

                # 3. Reset Tampilan memulihkan panggung bayangan ke Siaga TANPA menghapus bukti forensik
                rst = await c.post("/api/tactical/incidents/reset")
                assert rst.status_code == 200
                tw_g_after = (await c.get("/api/twinscreen/U-genset")).json()
                assert tw_g_after["panggung_bayangan"]["trip"] is False
                assert tw_g_after["panggung_bayangan"]["status"] == "STANDBY SIAGA"

                # Bukti forensik & unduhan BAP-FD (.docx) tetap tersedia dan ringan (< 120 KB)
                assert len((await c.get("/api/sessions")).json()) >= 4
                docx_res = await c.get("/api/report/latest.docx")
                assert docx_res.status_code == 200
                assert 5_000 < len(docx_res.content) < 120_000

                # 4. Kampanye dapat dipicu berulang kali setelah dinetralisir
                await c.post("/api/simulate/campaign")
                assert len((await c.get("/api/campaigns")).json()) >= 1
                await c.post("/api/tactical/campaign/resolve", json={})
                assert (await c.get("/api/campaigns")).json() == []
                await c.post("/api/simulate/campaign")
                assert len((await c.get("/api/campaigns")).json()) >= 1
        finally:
            for n in nodes.values():
                await n.stop()
            for rs in servers:
                rs.close()

    asyncio.run(go())
