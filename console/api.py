"""Dalang Console: Realtime C4ISR API dan Dashboard Pertahanan Siber TNI AD (Bab 11).

Menyediakan:
- Streaming WebSocket real-time untuk telemetri hidup dan kejadian serangan (0ms)
- Peta Taktis Wilayah Operasi C4ISR dengan vektor serangan kampanye
- Tactical Twin-Screen komparasi visual fluida dan kontrol SCADA/PLC
- Penilaian, persetujuan blokir (Bayangan ke Benteng), STIX 2.1, Sigma, nftables
- Pembuatan Berita Acara Pemeriksaan Forensik Digital (BAP-FD) resmi
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import pathlib
import secrets
import time
import uuid
from typing import Set
from urllib.parse import urlsplit

log = logging.getLogger("wayang.console")

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi import Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from console import report
from console.pusat import Pusat

STATIC = pathlib.Path(__file__).with_name("static")


class LevelBody(BaseModel):
    level: int
    satuan: str | None = None


LOGIN_MAX_FAILS = 5
LOGIN_WINDOW_S = 60.0
COOKIE_NAME = "wayang_token"
SESSION_TTL_S = 12 * 3600


def make_console_app(nodes: dict, pusat: Pusat, admin_token: str | None = None) -> FastAPI:
    """admin_token: None -> baca env WAYANG_ADMIN_TOKEN (kosong = tanpa autentikasi, mode uji);
    string kosong -> autentikasi dimatikan eksplisit; string lain -> wajib untuk seluruh /api/*."""
    app = FastAPI(title="WAYANG Dalang C4ISR Console", docs_url=None, redoc_url=None)
    token = admin_token if admin_token is not None else os.environ.get("WAYANG_ADMIN_TOKEN", "")
    fails: dict[str, list[float]] = {}

    # Penyimpanan sesi server-side: sid acak -> waktu kedaluwarsa. Dapat dicabut (logout)
    # dan punya TTL, menggantikan tanda tangan statis yang tak pernah berubah/rotasi.
    sessions_live: dict[str, float] = {}

    # Hanya percaya header IP dari proxy bila dinyatakan eksplisit; jika tidak, header
    # X-Forwarded-For/CF-Connecting-IP dapat dipalsukan untuk melewati rate-limit.
    trust_proxy = os.environ.get("WAYANG_TRUST_PROXY", "").strip().lower() in ("1", "true", "yes", "on")

    # Origin yang diizinkan untuk permintaan pengubah-state & WebSocket (anti-CSRF/CSWSH).
    allowed_origins = {o.strip().rstrip("/").lower()
                       for o in os.environ.get("WAYANG_ALLOWED_ORIGINS", "").split(",") if o.strip()}

    def _new_session() -> str:
        now = time.time()
        for k in [k for k, exp in sessions_live.items() if exp < now]:
            sessions_live.pop(k, None)
        sid = secrets.token_urlsafe(32)
        sessions_live[sid] = now + SESSION_TTL_S
        return sid

    def _session_valid(sid: str) -> bool:
        exp = sessions_live.get(sid)
        if not exp:
            return False
        if exp < time.time():
            sessions_live.pop(sid, None)
            return False
        return True

    def _client_ip(request) -> str:
        if trust_proxy:
            h = request.headers
            fwd = (h.get("cf-connecting-ip")
                   or (h.get("x-forwarded-for") or "").split(",")[0].strip())
            if fwd:
                return fwd
        return request.client.host if request.client else "?"

    def _same_origin(request, origin: str) -> bool:
        if not origin:
            return True  # klien non-browser (curl/API) tidak mengirim Origin
        o = origin.rstrip("/").lower()
        if o in allowed_origins:
            return True
        host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").lower()
        try:
            return bool(host) and urlsplit(o).netloc == host
        except ValueError:
            return False

    def _authed(headers, cookies) -> bool:
        if not token:
            return True
        given = headers.get("x-wayang-token") or ""
        bearer = headers.get("authorization") or ""
        if bearer.lower().startswith("bearer "):
            given = given or bearer[7:].strip()
        if given and hmac.compare_digest(given.encode(), token.encode()):
            return True
        ck = cookies.get(COOKIE_NAME) or ""
        return bool(ck) and _session_valid(ck)

    # Content-Security-Policy: membatasi sumber agar XSS tak bisa memuat/mengirim data keluar.
    # script-src memakai nonce per-request (bukan 'unsafe-inline') — hanya blok <script>
    # bawaan yang membawa nonce cocok yang boleh jalan; skrip sisipan penyerang ditolak.
    # style-src masih 'unsafe-inline' karena atribut style inline tak bisa diberi nonce.
    def _csp(nonce: str) -> str:
        return ("default-src 'self'; "
                "img-src 'self' data: https://server.arcgisonline.com; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                f"script-src 'self' 'nonce-{nonce}'; "
                "connect-src 'self'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")

    MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        path = request.url.path
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        # Tolak akses langsung ke /static/index.html
        if path == "/static/index.html":
            return JSONResponse({"detail": "Not Found"}, status_code=404)

        # Anti-CSRF: permintaan pengubah-state harus berasal dari Origin yang sah.
        # Login/logout dikecualikan (belum/akan membentuk sesi) dan dilindungi token+rate-limit.
        if (token and request.method in MUTATING
                and not path.startswith("/api/auth/")
                and not _same_origin(request, request.headers.get("origin", ""))):
            log.warning("CSRF ditolak: method=%s path=%s origin=%s ip=%s",
                        request.method, path, request.headers.get("origin"), _client_ip(request))
            return JSONResponse({"detail": "Origin tidak sah"}, status_code=403)

        if (not token or path == "/" or path.startswith("/static/")
                or path.startswith("/api/auth/")):
            response = await call_next(request)
        elif _authed(request.headers, request.cookies):
            response = await call_next(request)
        else:
            response = JSONResponse({"detail": "Autentikasi diperlukan"}, status_code=401)

        # Header Keamanan (Anti-MIME Sniffing, Clickjacking, kebijakan konten & isolasi)
        response.headers["Content-Security-Policy"] = _csp(nonce)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response

    @app.get("/api/auth/status")
    async def auth_status(request: Request):
        return {"required": bool(token), "authed": _authed(request.headers, request.cookies)}

    @app.post("/api/auth/login")
    async def auth_login(request: Request, body: dict):
        ip = _client_ip(request)
        now = time.time()
        recent = [t for t in fails.get(ip, []) if now - t < LOGIN_WINDOW_S]
        if len(recent) >= LOGIN_MAX_FAILS:
            fails[ip] = recent
            return JSONResponse({"detail": "Terlalu banyak percobaan. Coba lagi sebentar."},
                                status_code=429)
        given = str((body or {}).get("token", ""))
        if not token or hmac.compare_digest(given.encode(), token.encode()):
            resp = JSONResponse({"ok": True})
            if token:
                sid = _new_session()
                secure = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
                resp.set_cookie(COOKIE_NAME, sid, httponly=True, samesite="lax",
                                secure=secure, max_age=SESSION_TTL_S)
            fails.pop(ip, None)
            return resp
        recent.append(now)
        fails[ip] = recent
        log.warning("Login gagal dari ip=%s", ip)
        return JSONResponse({"detail": "Token salah"}, status_code=401)

    @app.post("/api/auth/logout")
    async def auth_logout(request: Request):
        sid = request.cookies.get(COOKIE_NAME)
        if sid:
            sessions_live.pop(sid, None)  # cabut sesi di sisi server
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE_NAME)
        return resp
    active_websockets: Set[WebSocket] = set()

    def node(satuan: str):
        if satuan in nodes:
            return nodes[satuan]
        for k, v in nodes.items():
            if satuan.lower() in k.lower() or k.lower() in satuan.lower():
                return v
        # Tidak ada fallback diam-diam ke node sembarang: satuan tak dikenal -> 404,
        # agar endpoint tidak beroperasi pada target yang salah.
        raise HTTPException(404, "Satuan tidak dikenal")

    async def broadcast_ws(payload: dict):
        dead = []
        for ws in list(active_websockets):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            active_websockets.discard(ws)

    # Hubungkan event bus Gamelan dari semua node ke siaran WebSocket
    def on_bus_event(evt):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(broadcast_ws({
                    "type": "event",
                    "event": {
                        "ts": time.time(),
                        "action": evt.get("action", "unknown"),
                        "satuan": evt.get("satuan", "Pusat"),
                        "src": evt.get("src", "N/A"),
                        "target": evt.get("target", {}),
                        "techniques": list(evt.get("techniques", [])),
                        "diverted": evt.get("diverted", False)
                    }
                }))
        except Exception:
            log.exception("Gagal menyiarkan event bus ke WebSocket")

    for n in set(nodes.values()):
        if hasattr(n, "bus"):
            n.bus.subscribe(on_bus_event)

    # Background task untuk streaming telemetri hidup
    async def telemetry_stream_loop():
        while True:
            try:
                await asyncio.sleep(1.0)
                if not active_websockets:
                    continue
                units_telemetry = {}
                for name, n in nodes.items():
                    sh = getattr(n, "shadow", None)
                    if not sh:
                        continue
                    # Baca nilai hidup dari model (generik per jenis aset)
                    val = sh.values
                    has_pump_off = any(not s.pump_on for s in sh.sessions.by_id.values())
                    total_diverted = sum(1 for s in sh.sessions.by_id.values() if s.diverted)
                    units_telemetry[name] = {
                        **{k: round(float(x), 2) for k, x in val.items()},
                        "kind": getattr(n, "kind", "bbm"),
                        "pump_on": not has_pump_off,
                        "diverted": total_diverted > 0,
                        "depth": max([s.engine.depth for s in sh.sessions.by_id.values()] or [1])
                    }
                await broadcast_ws({
                    "type": "telemetry_tick",
                    "ts": time.time(),
                    "units": units_telemetry
                })
            except asyncio.CancelledError:
                break
            except Exception:
                log.exception("Loop telemetri gagal sesaat; melanjutkan")
                await asyncio.sleep(1.0)

    @app.on_event("startup")
    async def startup_event():
        app.state.bg_telemetry = asyncio.create_task(telemetry_stream_loop())

    @app.on_event("shutdown")
    async def shutdown_event():
        if hasattr(app.state, "bg_telemetry"):
            app.state.bg_telemetry.cancel()

    @app.websocket("/ws/live")
    async def websocket_live(websocket: WebSocket):
        # Anti-CSWSH: tolak koneksi lintas-situs. Origin pada WS tak tunduk SameSite,
        # jadi halaman jahat bisa membuka WS dengan cookie korban bila tak diperiksa.
        if not _same_origin(websocket, websocket.headers.get("origin", "")):
            await websocket.close(code=1008)
            return
        if not _authed(websocket.headers, websocket.cookies):
            await websocket.close(code=1008)
            return
        await websocket.accept()
        active_websockets.add(websocket)
        try:
            # Kirim initial snapshot langsung saat terhubung
            await websocket.send_json({
                "type": "init",
                "map": pusat.map_state(),
                "campaigns": pusat.campaign_list,
                "vectors": pusat.get_campaign_vectors()
            })
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            active_websockets.discard(websocket)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        content = (STATIC / "index.html").read_text(encoding="utf-8")
        nonce = getattr(request.state, "csp_nonce", "")
        content = content.replace("__CSP_NONCE__", nonce)
        return HTMLResponse(content=content, headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        })

    @app.get("/static/{name}")
    async def static_file(name: str):
        p = (STATIC / name).resolve()
        if STATIC.resolve() not in p.parents or not p.is_file():
            raise HTTPException(404)
        return FileResponse(p)

    @app.get("/api/map")
    async def api_map():
        return pusat.map_state()

    @app.get("/api/map/vectors")
    async def api_map_vectors():
        return pusat.get_campaign_vectors()

    @app.get("/api/campaigns")
    async def api_campaigns():
        return [c for c in pusat.campaign_list if c["id"] not in pusat.resolved_campaigns]

    def _reset_live_sandboxes(target_satuans: set[str] | None = None):
        """Pulihkan sesi bayangan aktif di RAM ke posisi siaga tanpa menghapus bukti SQLite/HashChain."""
        for n in set(nodes.values()):
            if target_satuans is None or n.satuan in target_satuans:
                n.sessions.by_id.clear()
                n.sessions.by_src.clear()

    @app.post("/api/tactical/campaign/resolve")
    async def api_resolve_campaign(body: dict | None = None):
        cid = body.get("id") if body else None
        affected: set[str] | None = None
        if cid:
            affected = set()
            for c in pusat.campaign_list:
                if c.get("id") == cid:
                    affected.update(c.get("satuan", []))
        resolved = pusat.resolve_campaigns(cid)
        _reset_live_sandboxes(affected)
        return {"ok": True, "resolved": resolved, "msg": "Seluruh kampanye ancaman berhasil dinetralisir dan panggung bayangan dipulihkan ke Siaga."}

    @app.post("/api/tactical/incidents/reset")
    async def api_reset_incidents():
        pusat.reset_incidents()
        _reset_live_sandboxes(None)
        return {"ok": True, "msg": "Tampilan insiden & panggung bayangan direset ke status Aman. Bukti forensik tetap tersimpan utuh."}

    @app.get("/api/events/recent")
    async def api_events_recent():
        return list(pusat.events_log)

    @app.get("/api/sessions")
    async def api_sessions():
        out = []
        for n in set(nodes.values()):
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
        for n in set(nodes.values()):
            for t, v in n.pipeline.heatmap().items():
                a = agg.setdefault(t, {**v, "count": 0})
                a["count"] += v["count"]
        return agg

    @app.get("/api/decisions")
    async def api_decisions():
        out = []
        for n in set(nodes.values()):
            out += [p.brief() for p in n.approvals.items.values()]
        return out

    @app.post("/api/decisions/{satuan}/{pid}/{action}")
    async def api_decide(satuan: str, pid: str, action: str):
        n = node(satuan)
        try:
            p = {"approve": n.approvals.approve, "ignore": n.approvals.ignore,
                 "revoke": n.approvals.revoke}[action](pid)
            if action == "approve":
                # Otomatis netralisir status kampanye bila draf blokir disetujui komando
                for c in pusat.campaign_list:
                    if satuan in c["satuan"]:
                        pusat.resolve_campaigns(c["id"])
        except KeyError:
            raise HTTPException(404)
        except ValueError as e:
            raise HTTPException(409, str(e))
        return p.brief()

    @app.get("/api/autonomy")
    async def api_autonomy():
        return {s: {"level": n.autonomy.level, "nama": n.autonomy.name}
                for s, n in nodes.items()}

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
        for n in set(nodes.values()):
            n.autonomy.kill_switch("console")
        pusat.resolve_campaigns()
        return await api_autonomy()

    @app.get("/api/blocklist")
    async def api_blocklist():
        return [{"satuan": s, "src": e.src, "expires": e.expires, "reason": e.reason, "by": e.by}
                for s, n in nodes.items() for e in n.blocklist.active()]

    @app.get("/api/alerts")
    async def api_alerts():
        out = []
        for n in set(nodes.values()):
            out += [{"satuan": n.satuan, "kind": a["kind"], "text": a["text"], "warn": a["warn"],
                     "session": a["session"]} for a in n.pipeline.alerts]
        return out[-100:]

    @app.get("/api/bot")
    async def api_bot():
        return {n.satuan: n.channel.messages[-20:] for n in set(nodes.values())}

    @app.get("/api/recon")
    async def api_recon():
        return sorted((h for n in set(nodes.values()) for h in n.social.recon_map()),
                      key=lambda h: h["ts"])

    @app.get("/api/personas")
    async def api_personas():
        return [{"satuan": n.satuan, **p} for n in set(nodes.values()) for p in getattr(n, "personas", [])]

    @app.get("/api/chain/{satuan}")
    async def api_chain(satuan: str):
        n = node(satuan)
        return {"ok": n.chain.verify(), "length": len(n.chain.events)}

    @app.get("/api/chain/{satuan}/merkle")
    async def api_chain_merkle(satuan: str):
        from evidence.merkle import MilitaryAuditProof
        n = node(satuan)
        proof_mgr = MilitaryAuditProof(n.satuan, n.secret)
        events_dicts = list(n.chain.events)
        return proof_mgr.generate_dossier(events_dicts)

    def _reconstruct_mbap_frame(ev: dict, tid: int) -> bytes:
        import struct
        from shadows import modbus_proto as mp
        action = str(ev.get("action") or "")
        target = ev.get("target") if isinstance(ev.get("target"), dict) else {}
        unit = int(ev.get("unit") or target.get("unit") or 1) & 0xFF
        fc = ev.get("fc")
        if fc is None:
            fc_map = {
                "read_device_identification": 43,
                "write_single_register": 6,
                "diverted_write_alert": 6,
                "policy_violation_divert": 6,
                "write_single_coil": 5,
                "write_multiple_registers": 16,
                "read_input_registers": 4,
                "read_holding_registers": 3,
                "read_discrete_inputs": 2,
                "read_coils": 1,
            }
            fc = fc_map.get(action, 3)
        fc = int(fc) & 0xFF
        addr = ev.get("addr")
        if addr is None:
            reg = target.get("register")
            if isinstance(reg, int) and reg >= 1:
                addr = (reg % 10000) - 1 if reg >= 10000 else reg
            else:
                addr = 0
        addr = max(0, int(addr)) & 0xFFFF
        qty = max(1, int(ev.get("qty") or 1)) & 0xFFFF
        raw_val = ev.get("val")
        if isinstance(raw_val, (list, tuple)):
            raw_val = raw_val[0] if raw_val else 0
        val = int(0 if raw_val is None else raw_val) & 0xFFFF

        if fc == 43:
            pdu = bytes([43, 0x0E, 0x01, 0x00])
        elif fc == 6:
            pdu = struct.pack(">BHH", 6, addr, val)
        elif fc == 5:
            pdu = struct.pack(">BHH", 5, addr, 0xFF00 if val else 0x0000)
        elif fc == 16:
            pdu = struct.pack(">HHB", addr, 1, 2) + struct.pack(">H", val)
            pdu = bytes([16]) + pdu
        elif fc in (1, 2, 3, 4):
            pdu = struct.pack(">BHH", fc, addr, qty)
        else:
            pdu = struct.pack(">BHH", fc, addr, 1)
        return mp.build_mbap(tid & 0xFFFF, unit, pdu)

    @app.get("/api/packets/recent")
    async def api_packets_recent(satuan: str | None = None):
        from kelir.dpi import OffensiveToolFingerprinter
        candidates = []
        target_nodes = [node(satuan)] if satuan else list(set(nodes.values()))
        for n in target_nodes:
            evs = list(n.chain.events)[-60:]
            for idx, rec in enumerate(evs):
                p = rec.get("payload", rec) if isinstance(rec, dict) else {}
                act = str(p.get("action") or "")
                if act in ("shadow_divert", "auto_block"):
                    continue
                src = str(p.get("src") or "0.0.0.0")
                sess_id = str(p.get("session") or "ses-00001")
                tid = (idx + 1) & 0xFFFF
                raw_frame = _reconstruct_mbap_frame(p, tid)
                inspected = OffensiveToolFingerprinter.inspect_frame(raw_frame, src)
                prio = 2 if inspected["pdu"].get("function_code") in (5, 6, 15, 16, 43) else 1
                candidates.append((prio, idx, {
                    "id": f"PKT-{rec.get('event_id', idx + 1) if isinstance(rec, dict) else idx + 1}",
                    "satuan": p.get("satuan", n.satuan),
                    "session": sess_id,
                    "src": src,
                    "action": act or "modbus_frame",
                    "ts": p.get("ts", ""),
                    **inspected,
                }))
        candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return [c[2] for c in candidates[:30]]

    def _find_latest_session():
        all_sess = []
        for n in set(nodes.values()):
            for s in n.store.sessions():
                all_sess.append((float(s.get("first_wall", 0.0)), n.satuan, s["session"], n))
            for sid, sess in n.shadow.sessions.by_id.items():
                ts = float(getattr(sess, "first_wall", getattr(sess, "first", 0.0)))
                all_sess.append((ts, n.satuan, sid, n))
        if not all_sess:
            raise HTTPException(404, "Belum ada sesi rekaman")
        all_sess.sort(key=lambda x: x[0], reverse=True)
        return all_sess[0][1], all_sess[0][2], all_sess[0][3]

    def _generate_docx_sync(n, session: str):
        data = report.collect(n, session)
        return report.build_docx(data, n.out / "laporan" / f"berita_acara_{session}.docx")

    @app.get("/api/report/latest.docx")
    async def api_report_latest_docx():
        satuan, session, n = _find_latest_session()
        path = await asyncio.to_thread(_generate_docx_sync, n, session)
        return FileResponse(path, filename=path.name)

    @app.get("/api/report/latest.html", response_class=HTMLResponse)
    async def api_report_latest_html():
        satuan, session, n = _find_latest_session()
        data = await asyncio.to_thread(report.collect, n, session)
        return report.build_html(data)

    @app.get("/api/report/{satuan}/{session}.docx")
    async def api_report_docx(satuan: str, session: str):
        n = node(satuan)
        try:
            path = await asyncio.to_thread(_generate_docx_sync, n, session)
        except KeyError:
            raise HTTPException(404)
        return FileResponse(path, filename=path.name)

    @app.get("/api/report/{satuan}/{session}.html", response_class=HTMLResponse)
    async def api_report_html(satuan: str, session: str):
        try:
            return report.build_html(report.collect(node(satuan), session))
        except KeyError:
            raise HTTPException(404)

    def _attacker_view(sh):
        """Sesi penyerang terbaru yang pernah menulis; menentukan apa yang 'dilihat' penyerang."""
        best, bt = None, -1.0
        for sess in sh.sessions.by_id.values():
            if sess.writes and sess.writes[-1][0] > bt:
                best, bt = sess, sess.writes[-1][0]
        return best

    @app.get("/api/twinscreen/{satuan}")
    async def api_twinscreen(satuan: str):
        n = node(satuan)
        sh = n.shadow
        kind = getattr(n, "kind", "bbm")
        snap = n.mirror.snapshot() or {}
        src_tag = "StateMirror (PLC riil, baca-saja)" if snap else "nilai awal (mirror belum tersambung)"
        view = _attacker_view(sh)
        v = sh._session_values(view) if view else dict(sh.values)
        compromised = bool(view and not view.pump_on)
        total_diverted = sum(1 for x in sh.sessions.by_id.values() if x.diverted)
        writes_caught = sum(len(x.writes) for x in sh.sessions.by_id.values())
        depth = max([x.engine.depth for x in sh.sessions.by_id.values()] or [1])
        status_sh = "DIALIHKAN (SHADOW DIVERT)" if total_diverted else "STANDBY SIAGA"
        base = {"satuan": satuan, "nama_satuan": n.satuan, "asset_type": kind,
                "data_source": src_tag}
        common_real = {"status": "OPERASIONAL NORMAL", "perintah_bahaya_diterima": 0,
                       "integritas": "100% AMAN TERLINDUNGI", "sumber": src_tag}
        common_sh = {"status": status_sh, "perintah_bahaya_ditangkap": writes_caught,
                     "kedalaman_terbuka": depth, "dwell_time_aktif": True}

        if kind == "genset":
            pk = snap.get("power_load_kw", 46.8)
            return {**base, "role": "Sistem Daya Listrik Darurat (ATS/UPS & Genset Pangkalan)",
                    "aset_asli": {**common_real, "nama": "Schneider Electric ATS Controller (380V 50Hz)",
                                  "power_source": "PLN UTAMA (MAINS ON LOAD)",
                                  "power_load_kw": round(pk, 1), "power_max_kw": 80.0,
                                  "power_load_pct": round(pk / 80.0 * 100, 1),
                                  "frequency_hz": round(snap.get("frequency_hz", 50.02), 2),
                                  "voltage_v": round(snap.get("voltage_v", 382.4), 1),
                                  "engine_temp_c": round(snap.get("engine_temp_c", 78.5), 1),
                                  "ats_status": "NORMAL (GRID ACTIVE)"},
                    "panggung_bayangan": {**common_sh,
                        "nama": f"Bayangan DSE7320 Genset Controller ({sh.id})",
                        "trip": compromised,
                        "power_source": "GENSET TRIP / MATI (EFEK PALSU)" if compromised else "PLN UTAMA (SIMULASI)",
                        "power_load_kw": round(min(v["power_load_kw"], 2.4) if compromised else v["power_load_kw"], 1), "power_max_kw": 80.0,
                        "power_load_pct": round((min(v["power_load_kw"], 2.4) if compromised else v["power_load_kw"]) / 80.0 * 100, 1),
                        "frequency_hz": round(min(v["frequency_hz"], 12.5) if compromised else v["frequency_hz"], 2),
                        "voltage_v": round(min(v["voltage_v"], 48.0) if compromised else v["voltage_v"], 1),
                        "engine_temp_c": round(v["engine_temp_c"], 1),
                        "ats_status": "TRIP TERPUTUS (EFEK PALSU)" if compromised else "NORMAL (SIMULASI)"}}

        if kind == "cctv":
            ang = snap.get("gate_angle_deg", 0.0)
            cams = int(snap.get("cams_online", 4))
            sh_open = compromised or (v["gate_angle_deg"] > 5)
            sh_ang = max(v["gate_angle_deg"], 90.0 if compromised else 0.0)
            return {**base, "role": "Komando Perimeter & Gerbang CCTV Pangkalan",
                    "aset_asli": {**common_real, "nama": "Perimeter Barrier Gate & Video Surveillance Gateway",
                                  "gate_status": "TERBUKA" if ang > 5 else f"TERTUTUP / TERKUNCI ({ang:.0f}°)",
                                  "gate_is_open": ang > 5,
                                  "cctv_feed_status": f"{cams} FEED AKTIF (1080p 30fps H.265)",
                                  "perimeter_beam": "INFRARED BEAM AKTIF (AMAN)" if snap.get("beam_ok", 1) >= 1 else "BEAM TERPUTUS",
                                  "anpr_verified": f"{int(snap.get('vehicles_today', 14))} KENDARAAN TERVERIFIKASI"},
                    "panggung_bayangan": {**common_sh,
                        "nama": f"Bayangan HikVision NVR & Gate Decoy ({sh.id})",
                        "gate_status": f"TERBUKA (EFEK PALSU {sh_ang:.0f}°)" if sh_open else "TERTUTUP (SIMULASI 0°)",
                        "gate_is_open": sh_open,
                        "cctv_feed_status": "LOOPED STATIC DECOY FEED (PALSU)",
                        "perimeter_beam": "BYPASS TERDETEKSI (SIMULASI)" if sh_open else "NORMAL (SIMULASI)",
                        "anpr_verified": "LOGIN ADMIN DECOY CAPTURED"}}

        if kind == "gateway":
            all_nodes = set(nodes.values())
            blocks = sum(len(x.chain.events) for x in all_nodes)
            chain_ok = all(x.chain.verify() for x in all_nodes)
            total_units = len(pusat.units)
            return {**base, "role": "Pusat Komando & Pengendali Siber Operasi Terpadu (C4ISR)",
                    "aset_asli": {**common_real, "nama": "Gateway Dalang AI & Validator Kriptografis Hash-Chain",
                                  "throughput_gbps": round(snap.get("throughput_mbps", 1250.0) / 1000.0, 2),
                                  "hashchain_status": "INTEGRITAS RANTAI TERVERIFIKASI (SHA-256)" if chain_ok else "RANTAI TIDAK VALID!",
                                  "ledger_blocks": blocks,
                                  "consensus_nodes": f"{total_units}/{total_units} SATUAN TERDAFTAR",
                                  "ai_autonomy_level": f"L{n.autonomy.level} ({n.autonomy.name})"},
                    "panggung_bayangan": {**common_sh,
                        "nama": f"Bayangan C4ISR HoneyGrid & Deception Gateway ({sh.id})",
                        "throughput_gbps": round(v["throughput_mbps"] / 1000.0, 2),
                        "hashchain_status": "TRAP TOKEN INJEKSI AKTIF" if total_diverted else "STANDBY",
                        "ledger_blocks": blocks,
                        "consensus_nodes": "UPLINK DIPUTUS (EFEK PALSU)" if compromised else "DECOY PEER GRID AKTIF",
                        "ai_autonomy_level": "DECEPTION TRAP"}}

        return {**base, "role": "Depo Bahan Bakar Minyak (BBM) Taktis Satuan",
                "aset_asli": {**common_real, "nama": f"PLC Depo BBM Satuan {n.satuan} (Aset Fisik Asli)",
                              "tangki_level_l": round(snap.get("tank_level_l", 14250.0)),
                              "tangki_kapasitas_l": 20000,
                              "pompa_status": "AKTIF (BERJALAN)",
                              "tekanan_bar": round(snap.get("pump_pressure_bar", 2.12), 2),
                              "suhu_c": round(snap.get("temp_c", 27.2), 1)},
                "panggung_bayangan": {**common_sh,
                    "nama": f"Bayangan Kembar Digital ({sh.id})",
                    "tangki_level_l": round(v["tank_level_l"], 1), "tangki_kapasitas_l": 20000,
                    "pompa_status": "MATI (EFEK PALSU)" if compromised else "AKTIF (BERJALAN)",
                    "tekanan_bar": round(v["pump_pressure_bar"], 2),
                    "suhu_c": round(v["temp_c"], 1)}}

    # Tactical Export Endpoints
    @app.get("/api/tactical/rules/stix.json")
    async def api_tactical_stix():
        from engine import rulegen
        objects = []
        for n in set(nodes.values()):
            for s in n.store.sessions():
                b = rulegen.ioc_bundle(s)
                objects.extend(b.get("objects", []))
        if not objects:
            now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
            objects.append({
                "type": "indicator", "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(rulegen._NS, 'wayang-grid-active')}",
                "created": now, "modified": now, "valid_from": now,
                "name": "WAYANG C4ISR Deception Grid Monitoring Active",
                "pattern": "[network-traffic:dst_port = 502]", "pattern_type": "stix",
                "labels": ["wayang-grid-active"]
            })
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects
        }

    @app.get("/api/tactical/rules/sigma.yml", response_class=PlainTextResponse)
    async def api_tactical_sigma():
        import yaml
        from engine import rulegen
        rules = []
        for n in set(nodes.values()):
            for s in n.store.sessions():
                rules.extend(rulegen.sigma_rules(s))
        return yaml.dump_all(rules, sort_keys=False) if rules else "# Tidak ada aturan Sigma aktif."

    @app.get("/api/tactical/rules/nftables.conf", response_class=PlainTextResponse)
    async def api_tactical_nftables():
        lines = [
            "#!/usr/sbin/nft -f",
            "# =====================================================================",
            "# WAYANG TACTICAL FIREWALL DRAFT RULES (TNI AD IT/OT DEFENSE)",
            "# Generated automatically via Bayangan-ke-Benteng Closed Loop",
            "# =====================================================================",
            "table inet wayang_filter {",
            "    chain input {",
            "        type filter hook input priority 0; policy accept;",
        ]
        total_rules = 0
        for n in set(nodes.values()):
            for e in n.blocklist.active():
                lines.append(f'        ip saddr {e.src} tcp dport {{ 502, 80, 443 }} drop comment "Blokir ancaman {e.reason}"')
                total_rules += 1
        if total_rules == 0:
            lines.append('        # Belum ada IP berbahaya yang disetujui untuk pemblokiran.')
        lines.append("    }")
        lines.append("}")
        return "\n".join(lines)

    @app.get("/api/tactical/rules/suricata.rules", response_class=PlainTextResponse)
    async def api_tactical_suricata():
        from engine import rulegen
        out = ["# =====================================================================",
               "# WAYANG -> SURICATA: DRAF RULE DARI SUMBER PENYENTUH BAYANGAN",
               "# Mode IDS: biarkan 'alert'. Mode IPS inline: ganti ke 'drop' setelah disetujui Dalang.",
               "# Wajib: vars.address-groups.OT_NET dan app-layer modbus aktif di suricata.yaml.",
               "# ====================================================================="]
        seen = set()
        for n in set(nodes.values()):
            lab = getattr(n.approvals, "lab_mode", False)
            for s in n.store.sessions():
                key = (s.get("satuan"), s.get("src"))
                if key in seen:
                    continue
                seen.add(key)
                try:
                    out.append(rulegen.suricata_rules(s, whitelist=n.whitelist,
                                                      allow_loopback=lab, with_header=False))
                except ValueError as e:
                    out.append(f"# dilewati {s.get('src')}: {e}")
        if len(out) == 5:
            out.append("# Belum ada sumber yang menyentuh bayangan.")
        return "\n".join(out) + "\n"

    @app.get("/api/integrations")
    async def api_integrations():
        return {n.satuan: n.integrations_status() for n in set(nodes.values())
                if hasattr(n, "integrations_status")}

    @app.post("/api/tactical/lockdown/{satuan}")
    async def api_lockdown(satuan: str):
        n = node(satuan)
        n.autonomy.set_level(3, "tactical_lockdown")
        return {"status": "ok", "msg": f"Pangkalan {n.satuan} berhasil di-LOCKDOWN! Otonomi ditingkatkan ke L3 (Blokir Otomatis)."}

    sim_seq = {"n": 10}

    @app.post("/api/simulate/{action}")
    async def api_simulate(action: str, request: Request):
        from sim_attacker import scenarios as sc
        try:
            body = await request.json()
        except Exception:
            body = {}
        req_sat = (body or {}).get("satuan") if isinstance(body, dict) else None
        if req_sat:
            target_node = node(req_sat)
        else:
            target_node = nodes.get("KODAM-IV-Diponegoro") or nodes.get("Kodim-DEMO-03") or next(iter(nodes.values()))

        spec = getattr(target_node.shadow, "spec", None)
        act_addr = spec.actuator_addr if spec else 11
        sim_seq["n"] = (sim_seq["n"] % 200) + 1
        seq = sim_seq["n"]

        if action == "t1":
            await sc.t1_opportunist("127.0.0.1", target_node.ports["shadow"],
                                    f"127.0.1.{seq}", actuator_addr=act_addr)
            target_node.sync()
            return {"status": "ok", "satuan": target_node.satuan,
                    "msg": f"Simulasi T1 (Recon Scan) pada {target_node.satuan} selesai. Terdeteksi oleh Mesin Adaptif."}
        elif action == "t2":
            await sc.t2_targeted("127.0.0.1", target_node.ports["kelir"],
                                 f"127.0.2.{seq}", actuator_addr=act_addr)
            target_node.sync()
            return {"status": "ok", "satuan": target_node.satuan,
                    "msg": f"Simulasi T2 pada {target_node.satuan} dialihkan ke Bayangan! Manipulasi register {act_addr} tertahan (0-Harm ke aset fisik riil)."}
        elif action == "campaign":
            pusat.resolved_campaigns.clear()
            unique_nodes = list({n.satuan: n for n in nodes.values()}.values())
            for idx, n in enumerate(unique_nodes[:3]):
                n_spec = getattr(n.shadow, "spec", None)
                n_act = n_spec.actuator_addr if n_spec else 11
                await sc.t1_opportunist("127.0.0.1", n.ports["shadow"],
                                        f"127.0.3.{(seq + idx) % 230 + 10}", actuator_addr=n_act)
                n.sync()
            return {"status": "ok", "msg": "Simulasi Kampanye Terkoordinasi Multi-Satuan dijalankan. Vektor serangan aktif di Peta Komando C4ISR!"}
        elif action == "phishing":
            target_node.social.on_mail(
                "sarwa.wibisana.21e3b1@cyber.steamcraft.online",
                sender="spear-phish@evil-apt.net (185.220.101.5)",
                subject=f"PERINTAH MENDESAK: Kalibrasi Register {target_node.satuan}"
            )
            target_node.social.scan_text("... referensi dokumen nota-dinas-rahasia ...",
                                         src="185.220.101.5", where="email phishing")
            target_node.sync()
            return {"status": "ok", "satuan": target_node.satuan,
                    "msg": f"Email Phishing & Canary Token pada {target_node.satuan} terdeteksi dan dicatat di Peta Pengintaian."}

        raise HTTPException(400, "Aksi simulasi tidak dikenal")

    return app
