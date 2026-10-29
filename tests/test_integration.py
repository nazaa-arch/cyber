import asyncio
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import httpx

from console.pusat import Pusat, Link
from engine.fingerprint import Correlator
from node import SatuanNode
from sim_attacker.modbus_client import ModbusClient, values
from sim_attacker.real_sim import RealDeviceSim
from shadows import modbus_proto as mp


def test_end_to_end_night_scenario(tmp_path):
    async def go():
        pusat = Pusat(Correlator(k_satuan=3, window_s=3600))
        link = Link(pusat)
        real3, real5 = RealDeviceSim(), RealDeviceSim()
        r3 = await real3.serve("127.0.0.1", 0)
        r5 = await real5.serve("127.0.0.1", 0)
        n3 = SatuanNode("Kodim-DEMO-03", 3, ("127.0.0.1", r3.sockets[0].getsockname()[1]),
                        str(tmp_path / "n3"), {"10.0.0.5"}, time_scale=60, transport=link, lab_mode=True)
        n5 = SatuanNode("Kodim-DEMO-05", 5, ("127.0.0.1", r5.sockets[0].getsockname()[1]),
                        str(tmp_path / "n5"), {"10.0.0.5"}, time_scale=60, transport=link, lab_mode=True)
        pusat.register_unit("Kodim-DEMO-03", -6.2, 106.8)
        pusat.register_unit("Kodim-DEMO-05", -7.2, 107.6)
        await n3.start(); await n5.start()
        try:
            # 02:10 pemindaian berurutan menyentuh bayangan langsung
            async with ModbusClient("127.0.0.1", n3.ports["shadow"]) as c:
                for a in range(0, 8):
                    await c.read(4, a, 1)
            assert n3.pipeline.alerts and n3.pipeline.alerts[0]["kind"] == "info"
            # 02:14 penulisan lewat Kelir (sumber tak terdaftar) -> dialihkan
            async with ModbusClient("127.0.0.1", n3.ports["kelir"]) as c:
                await c.read(4, 0, 2)
                w = await c.write_reg(11, 0)
                assert w[0] == 6
            assert not real3.writes
            div = [e for e in n3.store.all_events() if e["action"] == "shadow_divert"]
            assert div and "tulis register" in div[0]["reason"]
            assert n3.pipeline.verify_chain()
            props = n3.approvals.pending()
            assert props
            assert "DRAF" in props[0].bundle["nftables"]
            assert any("TIPUAN DISENTUH" in m["text"] for m in n3.channel.messages)
            # perwira jaga menyetujui blokir lewat bot
            msg = n3.bot.handle_callback(f"approve:{props[0].id}")
            assert "disetujui" in msg and n3.blocklist.is_blocked(props[0].src)

            # 02:20 HMI: kredensial bawaan lalu unduh konfigurasi umpan
            transport = httpx.ASGITransport(app=n3.hmi_app, client=("203.0.113.77", 4444))
            async with httpx.AsyncClient(transport=transport, base_url="http://x",
                                         follow_redirects=True) as h:
                assert (await h.get("/config/backup.cfg")).status_code == 404
                await h.post("/login", data={"user": "admin", "pw": "admin"})
                page = await h.get("/panel")
                assert "Cadangan konfigurasi" in page.text
                cfg = await h.get("/config/backup.cfg")
                assert cfg.status_code == 200 and "password = HT" in cfg.text
            token = [l.split("= ")[1] for l in cfg.text.splitlines() if l.startswith("password")][0]
            n3.sync()

            # 02:40 token dipakai di Kodim-05
            transport = httpx.ASGITransport(app=n5.hmi_app, client=("203.0.113.77", 5555))
            async with httpx.AsyncClient(transport=transport, base_url="http://x") as h:
                await h.post("/login", data={"user": "svc_backup", "pw": token})
            n5.sync()
            camps = pusat.campaign_list
            assert camps and set(camps[0]["satuan"]) == {"Kodim-DEMO-03", "Kodim-DEMO-05"}
            assert camps[0]["urutan_sentuh"][0]["satuan"] == "Kodim-DEMO-03"
            assert pusat.status("Kodim-DEMO-05") == "Kampanye Terdeteksi"
            assert not real3.writes and not real5.writes
        finally:
            await n3.stop(); await n5.stop()
            r3.close(); r5.close()
    asyncio.run(go())


def test_edge_sync_survives_link_down(tmp_path):
    async def go():
        pusat = Pusat(); link = Link(pusat)
        real = RealDeviceSim(); rs = await real.serve("127.0.0.1", 0)
        n = SatuanNode("Kodim-DEMO-03", 3, ("127.0.0.1", rs.sockets[0].getsockname()[1]),
                       str(tmp_path), set(), time_scale=60, transport=link, lab_mode=True)
        await n.start(with_hmi=False)
        try:
            link.up = False
            async with ModbusClient("127.0.0.1", n.ports["kelir"]) as c:
                await c.write_reg(11, 0)
            assert n.sync() == 0 and n.edge.pending() >= 1
            link.up = True
            assert n.sync() >= 1 and n.edge.pending() == 0
            assert pusat.received >= 1
        finally:
            await n.stop(); rs.close()
    asyncio.run(go())

