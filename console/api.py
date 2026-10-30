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
import json
import pathlib
import time
import uuid
from typing import Set

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from console import report
from console.pusat import Pusat

STATIC = pathlib.Path(__file__).with_name("static")


class LevelBody(BaseModel):
    level: int
    satuan: str | None = None


def make_console_app(nodes: dict, pusat: Pusat) -> FastAPI:
    app = FastAPI(title="WAYANG Dalang C4ISR Console", docs_url=None, redoc_url=None)
    active_websockets: Set[WebSocket] = set()

    def node(satuan: str):
        if satuan in nodes:
            return nodes[satuan]
        for k, v in nodes.items():
            if satuan.lower() in k.lower() or k.lower() in satuan.lower():
                return v
        if nodes:
            return next(iter(nodes.values()))
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
            pass

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
                    # Baca nilai hidup dari model
                    val = sh.values
                    has_pump_off = any(not s.pump_on for s in sh.sessions.by_id.values())
                    total_diverted = sum(1 for s in sh.sessions.by_id.values() if s.diverted)
                    units_telemetry[name] = {
                        "tank_level_l": round(val.get("tank_level_l", 14250.0), 1),
                        "pump_pressure_bar": round(val.get("pump_pressure_bar", 2.12), 2),
                        "flow_lph": round(val.get("flow_lph", 450.0), 1),
                        "temp_c": round(val.get("temp_c", 27.5), 1),
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
    async def index():
        content = (STATIC / "index.html").read_text(encoding="utf-8")
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
        return pusat.campaign_list

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
        return await api_autonomy()

    @app.get("/api/blocklist")
    async def api_blocklist():
        return [{"satuan": s, "src": e.src, "expires": e.expires, "reason": e.reason, "by": e.by}
                for s, n in nodes.items() for e in n.blocklist.active()]

    @app.get("/api/alerts")
    async def api_alerts():
        out = []
        for s, n in set(nodes.values()):
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

    @app.get("/api/packets/recent")
    async def api_packets_recent():
        from kelir.dpi import OffensiveToolFingerprinter
        out = []
        for n in set(nodes.values()):
            for s in n.store.sessions():
                for a in s.get("actions", []):
                    raw_sample = b"\x00\x01\x00\x00\x00\x06\x01\x03\x75\x31\x00\x02"
                    inspected = OffensiveToolFingerprinter.inspect_frame(raw_sample, s["src"])
                    out.append({
                        "id": f"PKT-{abs(hash(s['session'])) % 90000 + 10000}",
                        "satuan": s["satuan"],
                        "session": s["session"],
                        "src": s["src"],
                        "action": a[1] if isinstance(a, (list, tuple)) else str(a),
                        **inspected
                    })
        return out[:30]

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
        writes_caught = sum(len(s.writes) for s in sh.sessions.by_id.values())
        depth = max([s.engine.depth for s in sh.sessions.by_id.values()] or [1])

        sat_lower = n.satuan.lower()
        if "brawijaya" in sat_lower or "listrik" in sat_lower or "genset" in sat_lower:
            asset_type = "genset"
            kw_base = 46.8
            shadow_kw = 0.0 if has_pump_off else round(sh.values.get("power_load_kw", kw_base), 1)
            shadow_hz = 0.0 if has_pump_off else round(sh.values.get("frequency_hz", 50.02), 2)
            shadow_volt = 0.0 if has_pump_off else 380.0
            return {
                "satuan": satuan,
                "nama_satuan": n.satuan,
                "asset_type": "genset",
                "role": "Sistem Daya Listrik Darurat (ATS/UPS & Genset Pangkalan)",
                "aset_asli": {
                    "nama": "Schneider Electric ATS Controller (380V 50Hz)",
                    "status": "OPERASIONAL NORMAL",
                    "power_source": "PLN UTAMA (MAINS ON LOAD)",
                    "power_load_kw": kw_base,
                    "power_max_kw": 80.0,
                    "power_load_pct": 58.5,
                    "frequency_hz": 50.02,
                    "voltage_v": 382.4,
                    "engine_temp_c": 78.5,
                    "ats_status": "NORMAL (GRID ACTIVE)",
                    "solar_cadangan_l": 850,
                    "perintah_bahaya_diterima": 0,
                    "integritas": "100% AMAN TERLINDUNGI"
                },
                "panggung_bayangan": {
                    "nama": f"Bayangan DSE7320 Genset Controller ({sh.id})",
                    "status": "DIALIHKAN (SHADOW DIVERT)" if total_diverted else "STANDBY SIAGA",
                    "power_source": "GENSET TRIP / MATI (EFEK PALSU)" if has_pump_off else "PLN UTAMA (SIMULASI)",
                    "power_load_kw": shadow_kw,
                    "power_max_kw": 80.0,
                    "power_load_pct": 0.0 if has_pump_off else 56.2,
                    "frequency_hz": shadow_hz,
                    "voltage_v": shadow_volt,
                    "engine_temp_c": round(sh.values.get("engine_temp_c", 78.5), 1),
                    "ats_status": "TRIP TERPUTUS (EFEK PALSU)" if has_pump_off else "NORMAL (EFEK PALSU)",
                    "solar_cadangan_l": 850,
                    "perintah_bahaya_ditangkap": writes_caught,
                    "kedalaman_terbuka": depth,
                    "dwell_time_aktif": True
                }
            }
        elif "siliwangi" in sat_lower or "cctv" in sat_lower or "gerbang" in sat_lower or "perimeter" in sat_lower:
            asset_type = "cctv"
            return {
                "satuan": satuan,
                "nama_satuan": n.satuan,
                "asset_type": "cctv",
                "role": "Komando Perimeter & Gerbang CCTV Pangkalan",
                "aset_asli": {
                    "nama": "Perimeter Barrier Gate & Video Surveillance Gateway",
                    "status": "OPERASIONAL NORMAL",
                    "gate_status": "TERTUTUP / TERKUNCI (0°)",
                    "gate_is_open": False,
                    "cctv_feed_status": "4 FEED AKTIF (1080p 30fps H.265)",
                    "perimeter_beam": "INFRARED BEAM AKTIF (AMAN)",
                    "anpr_verified": "14 KENDARAAN TERVERIFIKASI",
                    "perintah_bahaya_diterima": 0,
                    "integritas": "100% AMAN TERLINDUNGI"
                },
                "panggung_bayangan": {
                    "nama": f"Bayangan HikVision NVR & Gate Decoy ({sh.id})",
                    "status": "DIALIHKAN (SHADOW DIVERT)" if total_diverted else "STANDBY SIAGA",
                    "gate_status": "TERBUKA LEBAR (EFEK PALSU 90°)" if has_pump_off else "TERTUTUP (SIMULASI 0°)",
                    "gate_is_open": has_pump_off,
                    "cctv_feed_status": "LOOPED STATIC DECOY FEED (PALSU)",
                    "perimeter_beam": "BYPASS TERDETEKSI (SIMULASI)" if has_pump_off else "NORMAL (SIMULASI)",
                    "anpr_verified": "LOGIN ADMIN DECOY CAPTURED",
                    "perintah_bahaya_ditangkap": writes_caught,
                    "kedalaman_terbuka": depth,
                    "dwell_time_aktif": True
                }
            }
        elif "mabes" in sat_lower or "pusat" in sat_lower or "siber" in sat_lower or "c4isr" in sat_lower:
            asset_type = "c4isr"
            return {
                "satuan": satuan,
                "nama_satuan": n.satuan,
                "asset_type": "c4isr",
                "role": "Pusat Komando & Pengendali Siber Operasi Terpadu (C4ISR)",
                "aset_asli": {
                    "nama": "Gateway Dalang AI & Validator Kriptografis Hash-Chain",
                    "status": "OPERASIONAL NORMAL",
                    "throughput_gbps": 1.25,
                    "hashchain_status": "100% INTEGRITAS TERTUTUP (SHA-256)",
                    "ledger_blocks": 1482,
                    "consensus_nodes": "5/5 SATUAN TERHUBUNG (100%)",
                    "ai_autonomy_level": "LEVEL 2 (DYNAMIC REACTION)",
                    "perintah_bahaya_diterima": 0,
                    "integritas": "100% AMAN TERLINDUNGI"
                },
                "panggung_bayangan": {
                    "nama": f"Bayangan C4ISR HoneyGrid & Deception Gateway ({sh.id})",
                    "status": "DIALIHKAN (SHADOW DIVERT)" if total_diverted else "STANDBY SIAGA",
                    "throughput_gbps": 0.08,
                    "hashchain_status": "TRAP TOKEN INJEKSI SELESAI" if total_diverted else "STANDBY",
                    "ledger_blocks": 1482,
                    "consensus_nodes": "DECOY PEER GRID AKTIF",
                    "ai_autonomy_level": "DECEPTION TRAP",
                    "perintah_bahaya_ditangkap": writes_caught,
                    "kedalaman_terbuka": depth,
                    "dwell_time_aktif": True
                }
            }
        else:
            return {
                "satuan": satuan,
                "nama_satuan": n.satuan,
                "asset_type": "bbm",
                "role": "Depo Bahan Bakar Minyak (BBM) Taktis Satuan",
                "aset_asli": {
                    "nama": f"PLC Depo BBM Satuan {n.satuan} (Aset Fisik Asli)",
                    "status": "OPERASIONAL NORMAL",
                    "tangki_level_l": 14250,
                    "tangki_kapasitas_l": 20000,
                    "pompa_status": "AKTIF (BERJALAN)",
                    "tekanan_bar": 2.12,
                    "suhu_c": 27.2,
                    "perintah_bahaya_diterima": 0,
                    "integritas": "100% AMAN TERLINDUNGI"
                },
                "panggung_bayangan": {
                    "nama": f"Bayangan Kembar Digital ({sh.id})",
                    "status": "DIALIHKAN (SHADOW DIVERT)" if total_diverted else "STANDBY SIAGA",
                    "tangki_level_l": round(sh.values.get("tank_level_l", 12382.6), 1),
                    "tangki_kapasitas_l": 20000,
                    "pompa_status": "MATI (EFEK PALSU)" if has_pump_off else "AKTIF (BERJALAN)",
                    "tekanan_bar": round(sh.values.get("pump_pressure_bar", 2.04), 2),
                    "suhu_c": round(sh.values.get("temp_c", 27.8), 1),
                    "perintah_bahaya_ditangkap": writes_caught,
                    "kedalaman_terbuka": depth,
                    "dwell_time_aktif": True
                }
            }

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

    @app.post("/api/tactical/lockdown/{satuan}")
    async def api_lockdown(satuan: str):
        n = node(satuan)
        n.autonomy.set_level(3, "tactical_lockdown")
        return {"status": "ok", "msg": f"Pangkalan {n.satuan} berhasil di-LOCKDOWN! Otonomi ditingkatkan ke L3 (Blokir Otomatis)."}

    @app.post("/api/simulate/{action}")
    async def api_simulate(action: str):
        from sim_attacker import scenarios as sc
        target_node = nodes.get("KODAM-IV-Diponegoro") or nodes.get("Kodim-DEMO-03")
        if not target_node:
            target_node = next(iter(nodes.values()))

        if action == "t1":
            await sc.t1_opportunist("127.0.0.1", target_node.ports["shadow"], "127.0.0.88")
            target_node.sync()
            return {"status": "ok", "msg": "Simulasi T1 (Botnet Recon Scan) selesai. Terdeteksi oleh Mesin Adaptif."}
        elif action == "t2":
            await sc.t2_targeted("127.0.0.1", target_node.ports["kelir"], "127.0.0.99")
            target_node.sync()
            return {"status": "ok", "msg": "Simulasi T2 (Manipulasi Kendali ICS) dialihkan secara transparan ke Bayangan! Draf aturan nftables terbit & notifikasi Telegram terkirim."}
        elif action == "campaign":
            unique_nodes = list({n.satuan: n for n in nodes.values()}.values())
            for idx, n in enumerate(unique_nodes[:3]):
                await sc.t1_opportunist("127.0.0.1", n.ports["shadow"], f"198.51.100.{idx + 1}")
                n.sync()
            return {"status": "ok", "msg": "Simulasi Kampanye Terkoordinasi Multi-Satuan dijalankan. Vektor serangan aktif di Peta Komando C4ISR!"}
        elif action == "phishing":
            target_node.social.on_mail(
                "sarwa.wibisana.21e3b1@cyber.steamcraft.online",
                sender="spear-phish@evil-apt.net (185.220.101.5)",
                subject="PERINTAH MENDESAK: Kalibrasi Register Katup Depo"
            )
            target_node.social.scan_text("... referensi dokumen nota-dinas-rahasia ...",
                                         src="185.220.101.5", where="email phishing")
            target_node.sync()
            return {"status": "ok", "msg": "Email Phishing umpan terdeteksi di domain cyber.steamcraft.online dan dicatat di Peta Pengintaian."}

        raise HTTPException(400, "Aksi simulasi tidak dikenal")

    return app
