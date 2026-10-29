import asyncio
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import httpx
import docx

from console.api import make_console_app
from console.pusat import Link, Pusat
from node import SatuanNode
from sim_attacker import scenarios as sc
from sim_attacker.real_sim import RealDeviceSim


def test_console_api_and_report(tmp_path):
    async def go():
        pusat = Pusat(); link = Link(pusat)
        real = RealDeviceSim(); rs = await real.serve("127.0.0.1", 0)
        n = SatuanNode("Kodim-DEMO-03", 3, ("127.0.0.1", rs.sockets[0].getsockname()[1]),
                       str(tmp_path), set(), time_scale=60, transport=link, lab_mode=True)
        pusat.register_unit("Kodim-DEMO-03", -6.9, 107.6)
        await n.start(with_hmi=False)
        try:
            app = make_console_app({n.satuan: n}, pusat)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="http://c") as c:
                assert (await c.get("/api/map")).json()[0]["status"] == "Aman"
                await sc.t2_targeted("127.0.0.1", n.ports["kelir"], None)
                n.sync()
                assert (await c.get("/api/map")).json()[0]["status"] == "Tipuan Disentuh"
                ses = (await c.get("/api/sessions")).json()
                assert ses and ses[0]["diverted"]
                sid = ses[0]["session"]
                rp = (await c.get(f"/api/replay/{n.satuan}/{sid}")).json()
                assert rp[0]["t"] == 0 and any(x["action"] == "shadow_divert" for x in rp)
                assert (await c.get("/api/heatmap")).json()["T0855"]["count"] >= 1
                dec = (await c.get("/api/decisions")).json()
                assert dec and dec[0]["status"] == "pending"
                r = await c.post(f"/api/decisions/{n.satuan}/{dec[0]['id']}/approve")
                assert r.json()["status"] == "approved"
                assert (await c.post(f"/api/decisions/{n.satuan}/{dec[0]['id']}/approve")).status_code == 409
                assert (await c.get("/api/blocklist")).json()
                assert (await c.get(f"/api/chain/{n.satuan}")).json()["ok"] is True
                rep = await c.get(f"/api/report/{n.satuan}/{sid}.docx")
                assert rep.status_code == 200
                out = tmp_path / "x.docx"; out.write_bytes(rep.content)
                text = "\n".join(p.text for p in docx.Document(out).paragraphs)
                assert "DRAF OTOMATIS" in text and "LULUS" in text
                assert "Berita Acara" in (await c.get(f"/api/report/{n.satuan}/{sid}.html")).text
                lv = (await c.post("/api/autonomy", json={"level": 3})).json()
                assert lv[n.satuan]["level"] == 3
                assert (await c.post("/api/autonomy", json={"level": 9})).status_code == 422
                assert (await c.post("/api/killswitch")).json()[n.satuan]["level"] == 0
                assert "WAYANG" in (await c.get("/")).text
                assert (await c.get("/static/..%2f..%2fnode.py")).status_code == 404
        finally:
            await n.stop(); rs.close()
    asyncio.run(go())
