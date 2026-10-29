"""Bayangan HMI Web: halaman login dan panel SCADA palsu (Bab 6.2, 7, 9.2).

Kredensial bawaan admin/admin adalah umpan. Kedalaman mengikuti Mesin Adaptif:
tag tersembunyi (L2), berkas konfigurasi ber-honeytoken (L4).
"""
from __future__ import annotations

import time

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from jinja2 import Environment

from engine.honeytoken import looks_like_token, make_token
from shadows.modbus_shadow import ShadowDevice
from telemetry.generator_teks import generate

_env = Environment(autoescape=True)
LOGIN = _env.from_string(
    "<html><head><title>{{ asset }} - Login</title></head><body>"
    "<h2>{{ asset }}</h2><p>Sistem Pemantauan Depo</p>"
    "<form method='post' action='/login'>Pengguna <input name='user'> "
    "Sandi <input type='password' name='pw'> <button>Masuk</button></form>"
    "{% if err %}<p style='color:red'>{{ err }}</p>{% endif %}"
    "<small>GX-HTTPD 1.0</small></body></html>")
PANEL = _env.from_string(
    "<html><head><title>{{ asset }}</title></head><body><h2>{{ asset }}</h2>"
    "<table border=1><tr><td>Level tangki</td><td>{{ v.tank }} L</td></tr>"
    "<tr><td>Tekanan pompa</td><td>{{ v.p }} bar</td></tr>"
    "{% if depth >= 2 %}<tr><td>Aliran</td><td>{{ v.flow }} L/jam</td></tr>"
    "<tr><td>Suhu</td><td>{{ v.t }} C</td></tr>{% endif %}</table>"
    "{% if depth >= 2 %}<p><a href='/api/tags'>Daftar tag</a> | "
    "<a href='/config/backup.cfg'>Cadangan konfigurasi</a></p>{% endif %}"
    "<pre>{{ log }}</pre></body></html>")


def make_hmi_app(shadow: ShadowDevice, secret: bytes, asset: str = "Depo BBM Satuan") -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    authed: set[str] = set()

    def _sess(req: Request):
        src = req.client.host if req.client else "0.0.0.0"
        return src, shadow.sessions.get(src, shadow.clock())

    def _emit(s, action: str, target=None, **extra):
        if shadow.bus is None:
            return
        s.events += 1
        shadow.bus.publish({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "t_mono": shadow.clock(), "satuan": shadow.satuan, "shadow": shadow.id,
            "proto": "http", "src": s.src, "session": s.id, "action": action,
            "target": target, "stage": s.stage, "depth": s.engine.depth,
            "via": "direct", **extra})

    def _observe(s, action: str) -> int:
        s.observe(shadow.clock(), action)
        s.proto_features.add(f"http:{action}")
        return s.engine.settle(s.stage)

    def _vals(s):
        v = shadow._session_values(s)
        return {"tank": int(v["tank_level_l"]), "p": round(v["pump_pressure_bar"], 2),
                "flow": int(v["flow_lph"]), "t": round(v["temp_c"], 1)}

    @app.middleware("http")
    async def _banner(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["Server"] = "GX-HTTPD/1.0"
        return resp

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request):
        src, s = _sess(request)
        s.observe(shadow.clock(), "http_root")
        _emit(s, "http_root")
        return LOGIN.render(asset=asset, err=None)

    @app.post("/login")
    async def login(request: Request, user: str = Form(""), pw: str = Form("")):
        src, s = _sess(request)
        if looks_like_token(pw):
            _observe(s, "http_login_honeytoken")
            _emit(s, "http_login_honeytoken", {"user": user}, honeytoken_used=pw)
            authed.add(src)
            r = RedirectResponse("/panel", status_code=302)
            return r
        if (user, pw) == ("admin", "admin"):
            s.note_default_cred()
            depth = _observe(s, "http_login_default_cred")
            _emit(s, "http_login_default_cred", {"user": user}, depth=depth)
            authed.add(src)
            return RedirectResponse("/panel", status_code=302)
        s.note_default_cred() if (user, pw) in (("admin", "1234"), ("root", "root"),
                                                ("admin", "password")) else None
        _emit(s, "http_login_failed", {"user": user})
        return HTMLResponse(LOGIN.render(asset=asset, err="Pengguna atau sandi salah"), 401)

    @app.get("/panel", response_class=HTMLResponse)
    async def panel(request: Request):
        src, s = _sess(request)
        if src not in authed:
            return RedirectResponse("/", status_code=302)
        depth = _observe(s, "http_panel")
        _emit(s, "http_panel", depth=depth)
        log = generate("operator_log", seed=int(shadow.start_hour * 100) + shadow.touch_count // 50,
                       hour=shadow.hour(), n=5)
        return PANEL.render(asset=asset, v=_vals(s), depth=depth, log=log)

    @app.get("/api/tags")
    async def tags(request: Request):
        src, s = _sess(request)
        if src not in authed or s.engine.depth < 2:
            return JSONResponse({"error": "not found"}, 404)
        depth = _observe(s, "http_tags")
        v = _vals(s)
        _emit(s, "http_tags", depth=depth)
        return {"tags": [{"nama": "TANK_LEVEL", "nilai": v["tank"], "satuan": "L"},
                         {"nama": "PUMP_PRESSURE", "nilai": v["p"], "satuan": "bar"},
                         {"nama": "FLOW", "nilai": v["flow"], "satuan": "L/jam"},
                         {"nama": "TEMP", "nilai": v["t"], "satuan": "C"}]}

    @app.get("/config/backup.cfg")
    async def config(request: Request):
        src, s = _sess(request)
        if src not in authed or s.engine.depth < 2:
            return PlainTextResponse("Not Found", 404)
        depth = _observe(s, "http_config_download")
        if depth < 4:
            _emit(s, "http_config_denied", depth=depth)
            return PlainTextResponse("Forbidden", 403)
        token = make_token(secret, shadow.satuan, s.id)
        s.honeytokens_planted.add(token)
        body = generate("config_backup", seed=1, asset=asset, location="Pangkalan (fiktif)",
                        vendor="Generik", model=shadow.idobj[1], fw=shadow.idobj[2],
                        svc_user="svc_backup", vpn_user="vpn_cadangan", token=token)
        _emit(s, "http_config_download", {"path": "/config/backup.cfg"},
              honeytoken_planted=token, depth=depth)
        return PlainTextResponse(body)

    return app
