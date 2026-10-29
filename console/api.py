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
        if satuan not in nodes:
            raise HTTPException(404, "satuan tidak dikenal")
        return nodes[satuan]

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

    return app
