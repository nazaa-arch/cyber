"""Dalang Console: API dan dashboard (Bab 11).

Peta Komando, Putar Ulang Sesi, Heatmap ATT&CK for ICS, Panel Keputusan,
tingkat otonomi + saklar darurat, Berita Acara, Peta Pengintaian.
"""
from __future__ import annotations

import pathlib

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from console import report
from console.pusat import Pusat

STATIC = pathlib.Path(__file__).with_name("static")


class LevelBody(BaseModel):
    level: int
    satuan: str | None = None


def make_console_app(nodes: dict, pusat: Pusat) -> FastAPI:
    app = FastAPI(title="WAYANG Dalang Console", docs_url=None, redoc_url=None)

    def node(satuan: str):
        if satuan in nodes:
            return nodes[satuan]
        for k, v in nodes.items():
            if satuan.lower() in k.lower() or k.lower() in satuan.lower():
                return v
        if nodes:
            return next(iter(nodes.values()))
        raise HTTPException(404, "satuan tidak dikenal")

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return (STATIC / "index.html").read_text(encoding="utf-8")

    @app.get("/static/{name}")
    async def static(name: str):
        p = (STATIC / name).resolve()
        if STATIC.resolve() not in p.parents or not p.is_file():
            raise HTTPException(404)
        return FileResponse(p)

    @app.get("/api/map")
    async def api_map():
        return pusat.map_state()

    @app.get("/api/campaigns")
    async def api_campaigns():
        return pusat.campaign_list

    @app.get("/api/sessions")
    async def api_sessions():
        out = []
        for n in nodes.values():
            for s in n.store.sessions():
                out.append({k: s[k] for k in ("satuan", "session", "src", "stage", "depth",
                                              "diverted", "techniques", "event_count",
                                              "high_tier", "first_wall")})
        return sorted(out, key=lambda s: -s["first_wall"])

    @app.get("/api/replay/{satuan}/{session}")
    async def api_replay(satuan: str, session: str):
        r = node(satuan).store.replay(session)
        if not r:
            raise HTTPException(404)
        return r

    @app.get("/api/heatmap")
    async def api_heatmap():
        agg: dict = {}
        for n in nodes.values():
            for t, v in n.pipeline.heatmap().items():
                a = agg.setdefault(t, {**v, "count": 0})
                a["count"] += v["count"]
        return agg

    @app.get("/api/decisions")
    async def api_decisions():
        out = []
        for n in nodes.values():
            out += [p.brief() for p in n.approvals.items.values()]
        return out

    @app.post("/api/decisions/{satuan}/{pid}/{action}")
    async def api_decide(satuan: str, pid: str, action: str):
        n = node(satuan)
        try:
            p = {"approve": n.approvals.approve, "ignore": n.approvals.ignore,
                 "revoke": n.approvals.revoke}[action](pid)
        except KeyError:
            raise HTTPException(404)
        except ValueError as e:
            raise HTTPException(409, str(e))
        return p.brief()

    @app.get("/api/autonomy")
    async def api_autonomy():
        return {s: {"level": n.autonomy.level, "nama": n.autonomy.name} for s, n in nodes.items()}

    @app.post("/api/autonomy")
    async def api_set_autonomy(body: LevelBody):
        if not 0 <= body.level <= 3:
            raise HTTPException(422, "level 0..3")
        for s, n in nodes.items():
            if body.satuan in (None, s):
                n.autonomy.set_level(body.level, "console")
        return await api_autonomy()

    @app.post("/api/killswitch")
    async def api_kill():
        for n in nodes.values():
            n.autonomy.kill_switch("console")
        return await api_autonomy()

    @app.get("/api/blocklist")
    async def api_blocklist():
        return [{"satuan": s, "src": e.src, "expires": e.expires, "reason": e.reason, "by": e.by}
                for s, n in nodes.items() for e in n.blocklist.active()]

    @app.get("/api/alerts")
    async def api_alerts():
        out = []
        for s, n in nodes.items():
            out += [{"satuan": s, "kind": a["kind"], "text": a["text"], "warn": a["warn"],
                     "session": a["session"]} for a in n.pipeline.alerts]
        return out[-100:]

    @app.get("/api/bot")
    async def api_bot():
        return {s: n.channel.messages[-20:] for s, n in nodes.items()}

    @app.get("/api/recon")
    async def api_recon():
        return sorted((h for n in nodes.values() for h in n.social.recon_map()),
                      key=lambda h: h["ts"])

    @app.get("/api/personas")
    async def api_personas():
        return [{"satuan": s, **p} for s, n in nodes.items() for p in getattr(n, "personas", [])]

    @app.get("/api/chain/{satuan}")
    async def api_chain(satuan: str):
        n = node(satuan)
        return {"ok": n.chain.verify(), "length": len(n.chain.events)}

    def _find_latest_session():
        all_sess = []
        for s_name, n in nodes.items():
            for sid, sess in n.shadow.sessions.by_id.items():
                ts = getattr(sess, "first_wall", getattr(sess, "first", 0.0))
                all_sess.append((ts, s_name, sid, n))
        if not all_sess:
            raise HTTPException(404, "Belum ada sesi rekaman")
        all_sess.sort(key=lambda x: x[0], reverse=True)
        return all_sess[0][1], all_sess[0][2], all_sess[0][3]

    @app.get("/api/report/latest.docx")
    async def api_report_latest_docx():
        satuan, session, n = _find_latest_session()
        data = report.collect(n, session)
        path = report.build_docx(data, n.out / "laporan" / f"berita_acara_{session}.docx")
        return FileResponse(path, filename=path.name)

    @app.get("/api/report/latest.html", response_class=HTMLResponse)
    async def api_report_latest_html():
        satuan, session, n = _find_latest_session()
        return report.build_html(report.collect(n, session))

    @app.get("/api/report/{satuan}/{session}.docx")
    async def api_report_docx(satuan: str, session: str):
        n = node(satuan)
        try:
            data = report.collect(n, session)
        except KeyError:
            raise HTTPException(404)
        path = report.build_docx(data, n.out / "laporan" / f"berita_acara_{session}.docx")
        return FileResponse(path, filename=path.name)

    @app.get("/api/report/{satuan}/{session}.html", response_class=HTMLResponse)
    async def api_report_html(satuan: str, session: str):
        try:
            return report.build_html(report.collect(node(satuan), session))
        except KeyError:
            raise HTTPException(404)

    @app.get("/api/twinscreen/{satuan}")
    async def api_twinscreen(satuan: str):
        n = node(satuan)
        sh = n.shadow
        has_pump_off = any(not s.pump_on for s in sh.sessions.by_id.values())
        total_diverted = sum(1 for s in sh.sessions.by_id.values() if s.diverted)
        return {
            "satuan": satuan,
            "aset_asli": {
                "nama": "PLC Depo BBM Satuan (Aset Asli)",
                "status": "OPERASIONAL NORMAL",
                "tangki_level_l": 14250,
                "pompa_status": "AKTIF (BERJALAN)",
                "tekanan_bar": 2.12,
                "perintah_bahaya_diterima": 0,
                "integritas": "100% AMAN TERLINDUNGI"
            },
            "panggung_bayangan": {
                "nama": f"Bayangan Kembar ({sh.id})",
                "status": "DIALIHKAN (SHADOW DIVERT)" if total_diverted else "STANDBY SIAGA",
                "tangki_level_l": round(sh.values["tank_level_l"], 1),
                "pompa_status": "MATI (EFEK PALSU)" if has_pump_off else "AKTIF (BERJALAN)",
                "tekanan_bar": round(sh.values["pump_pressure_bar"], 2),
                "perintah_bahaya_ditangkap": sum(len(s.writes) for s in sh.sessions.by_id.values()),
                "kedalaman_terbuka": max([s.engine.depth for s in sh.sessions.by_id.values()] or [1]),
                "dwell_time_aktif": True
            }
        }

    @app.post("/api/simulate/{action}")
    async def api_simulate(action: str):
        from sim_attacker import scenarios as sc
        n3 = nodes.get("Kodim-DEMO-03")
        if not n3:
            raise HTTPException(404, "Node demo tidak siap")

        if action == "t1":
            await sc.t1_opportunist("127.0.0.1", n3.ports["shadow"], "127.0.0.88")
            n3.sync()
            return {"status": "ok", "msg": "Simulasi T1 (Botnet Scan) selesai. Terdeteksi oleh Mesin Adaptif."}
        elif action == "t2":
            await sc.t2_targeted("127.0.0.1", n3.ports["kelir"], "127.0.0.99")
            n3.sync()
            return {"status": "ok", "msg": "Simulasi T2 (Manipulasi Kendali ICS) dialihkan secara transparan ke Bayangan! Draf aturan nftables terbit & notifikasi Telegram terkirim."}
        elif action == "campaign":
            for idx, (name, n) in enumerate(nodes.items()):
                await sc.t1_opportunist("127.0.0.1", n.ports["shadow"], f"198.51.100.{idx + 1}")
                n.sync()
            return {"status": "ok", "msg": "Simulasi Kampanye Terkoordinasi 3 Satuan dijalankan. Peta Komando berkedip merah!"}
        elif action == "phishing":
            n3.social.on_mail(
                "sarwa.wibisana.21e3b1@cyber.steamcraft.online",
                sender="spear-phish@evil-apt.net (185.220.101.5)",
                subject="PERINTAH MENDESAK: Kalibrasi Register Katup Depo"
            )
            n3.social.scan_text("... referensi dokumen nota-dinas-rahasia ...",
                               src="185.220.101.5", where="email phishing")
            n3.sync()
            return {"status": "ok", "msg": "Email Phishing umpan terdeteksi di domain cyber.steamcraft.online dan dicatat di Peta Pengintaian."}

        raise HTTPException(400, "Aksi simulasi tidak dikenal")

    return app
