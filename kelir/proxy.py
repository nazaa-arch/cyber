"""Kelir: proxy Modbus/TCP, penilai sesi, dan pengalih ke bayangan (Bab 9.1, 9.4).

Jaminan keselamatan:
* Sesi yang sudah dialihkan (pinned) TIDAK PERNAH diteruskan ke aset asli.
* Pengalihan terjadi pada batas transaksi (sebelum permintaan diteruskan).
* Gagal aman: bila bayangan bermasalah, sesi mencurigakan diputus bersih.
* Lalu lintas daftar putih tetap melewati jalur asli.
"""
from __future__ import annotations

import asyncio
import time

from engine.autonomy import Autonomy, Blocklist, L3_BLOCK_TTL_S, L3_REPEAT_THRESHOLD
from engine.gamelan import Gamelan
from kelir.mirror import StateMirror
from kelir.scoring import SessionScorer, Decision
from kelir.session import SessionRegistry
from shadows import modbus_proto as mp
from shadows.modbus_shadow import ShadowDevice


class Kelir:
    def __init__(self, satuan: str, real_addr: tuple[str, int], shadow: ShadowDevice,
                 sessions: SessionRegistry, scorer: SessionScorer, bus: Gamelan,
                 autonomy: Autonomy | None = None, blocklist: Blocklist | None = None,
                 mirror: StateMirror | None = None, clock=time.monotonic):
        self.satuan = satuan
        self.real_addr = real_addr
        self.shadow = shadow
        self.sessions = sessions
        self.scorer = scorer
        self.bus = bus
        self.autonomy = autonomy or Autonomy()
        self.blocklist = blocklist or Blocklist()
        self.mirror = mirror
        self.clock = clock
        self.divert_counts: dict[str, int] = {}
        self.stats = {"forwarded": 0, "diverted_frames": 0, "fail_closed": 0, "blocked": 0,
                      "forwarded_operator": 0, "forwarded_unlisted_reads": 0}

    @property
    def maintenance_mode(self) -> bool:
        return self.scorer.maintenance_mode

    @maintenance_mode.setter
    def maintenance_mode(self, v: bool):
        self.scorer.maintenance_mode = bool(v)

    # ---------- util ----------
    def _event(self, s, action: str, **extra) -> None:
        s.events += 1
        self.bus.publish({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "t_mono": self.clock(), "satuan": self.satuan, "shadow": self.shadow.id,
            "proto": "modbus_tcp", "src": s.src, "session": s.id, "action": action,
            "target": None, "stage": s.stage, "depth": s.engine.depth,
            "via": "kelir", **extra})

    def _pin(self, s, decision) -> None:
        s.pinned = True
        s.diverted = True
        s.pin_time = self.clock()
        s.base = self.mirror.snapshot() if self.mirror else None
        self.divert_counts[s.src] = self.divert_counts.get(s.src, 0) + 1
        self._event(s, "shadow_divert", reason=decision.reason,
                    score=round(decision.score, 3),
                    signals=vars(decision.signals).copy(),
                    mirror_used=s.base is not None)
        if self.autonomy.can_autoblock and self.divert_counts[s.src] >= L3_REPEAT_THRESHOLD:
            self.blocklist.add(s.src, L3_BLOCK_TTL_S,
                               "menyentuh bayangan berulang", "auto-L3")
            self._event(s, "auto_block", ttl_s=L3_BLOCK_TTL_S)

    # ---------- koneksi klien ----------
    async def handle_client(self, reader, writer) -> None:
        src = writer.get_extra_info("peername")[0]
        up = None
        try:
            if self.blocklist.is_blocked(src):
                self.stats["blocked"] += 1
                return
            while True:
                fr = await mp.read_frame(reader)
                if fr is None:
                    break
                tid, unit, pdu = fr
                holder = {"c": up}
                resp = await self._route(src, tid, unit, pdu, holder)
                up = holder["c"]
                if resp is None:           # gagal aman: putus bersih
                    break
                if isinstance(resp, _Delayed):
                    await asyncio.sleep(resp.delay)
                writer.write(mp.build_mbap(tid, unit, bytes(resp)))
                await writer.drain()
        finally:
            writer.close()
            if up:
                up[1].close()

    async def _route(self, src: str, tid: int, unit: int, pdu: bytes, holder: dict):
        now = self.clock()
        if src in self.scorer.whitelist:                       # operator sah
            # Batasan Keamanan Zero Trust:
            # IP whitelist memverifikasi asal jaringan, namun frame tetap diparsing
            # dan diuji terhadap kebijakan operasional per-sumber (unit, fungsi, register tulis).
            try:
                req = mp.parse_pdu(pdu)
            except mp.ProtoError:
                return None  # Tolak frame cacat (fail-closed)

            s = self.sessions.get(src, now)
            if s.pinned:
                return self._to_shadow(s, src, unit, pdu)

            allowed, violation = self.scorer.check_source_policy(src, unit, req, req_rate_hz=s.rate_hz(now))
            if not allowed:
                # Skenario Operator Terkompromi: Perintah melanggar batas otorisasi
                s.observe(now, req.action, unit=unit, table=req.table, addr=req.addr,
                          qty=req.qty, fc=req.fc, is_write=req.is_write)
                pol = self.scorer.policies.get(src)
                on_viol = pol.on_violation if pol else "divert"
                self._event(s, "policy_violation_divert",
                            reason=f"Operator terdaftar melanggar batas kebijakan: {violation}",
                            score=1.0, src=src, unit=unit, fc=req.fc)
                if on_viol == "divert":
                    dec = Decision(1.0, True, f"Pelanggaran kebijakan per-sumber: {violation}")
                    self._pin(s, dec)
                    return self._to_shadow(s, src, unit, pdu)
                return None  # drop

            return await self._forward(holder, tid, unit, pdu, whitelisted=True)

        s = self.sessions.get(src, now)
        if s.pinned:
            return self._to_shadow(s, src, unit, pdu)

        try:
            req = mp.parse_pdu(pdu)
            funcs = [req.fc]
            s.observe(now, req.action, unit=unit, table=req.table, addr=req.addr,
                      qty=req.qty, fc=req.fc, is_write=req.is_write)
            action = req.action
        except mp.ProtoError:
            funcs = [pdu[0] if pdu else 0]
            req = None
            action = "invalid_function"
            s.observe(now, action, unit=unit, fc=funcs[0])

        non_read = req is None or req.fc not in mp.READ_FUNCS
        decision = self.scorer.score(
            src, modbus_funcs=funcs, scan_targets=s.seq, scan_window_s=s.scan_window(),
            default_cred_attempts=s.default_cred, req_rate_hz=s.rate_hz(now))
        divert = decision.divert or (non_read and not self.maintenance_mode)   # fungsi bukan-baca dari sumber tak sah
        if divert and self.autonomy.can_divert:
            self._pin(s, decision)
            return self._to_shadow(s, src, unit, pdu)
        if divert and not s.would_divert:
            s.would_divert = True
            self._event(s, "would_divert", reason=decision.reason,
                        score=round(decision.score, 3))
        if not s.informed:
            s.informed = True
            self._event(s, "unlisted_source_read", reason=decision.reason,
                        score=round(decision.score, 3))
        return await self._forward(holder, tid, unit, pdu, whitelisted=False)

    def _to_shadow(self, s, src, unit, pdu):
        try:
            out = self.shadow.handle(src, unit, pdu, via="kelir")
        except Exception:
            out = None
        if out is None:
            self.stats["fail_closed"] += 1
            self._event(s, "fail_closed")
            return None
        self.stats["diverted_frames"] += 1
        resp, delay = out
        return _Delayed(resp, delay)

    async def _forward(self, holder, tid, unit, pdu, whitelisted: bool):
        t0 = time.perf_counter()
        try:
            if holder["c"] is None:
                holder["c"] = await asyncio.wait_for(
                    asyncio.open_connection(*self.real_addr), 2.0)
            r, w = holder["c"]
            w.write(mp.build_mbap(tid, unit, pdu))
            await w.drain()
            fr = await asyncio.wait_for(mp.read_frame(r), 3.0)
        except (OSError, asyncio.TimeoutError):
            fr = None
        if fr is None:
            return None
        self.stats["forwarded"] += 1
        if whitelisted:
            self.stats["forwarded_operator"] = self.stats.get("forwarded_operator", 0) + 1
        else:
            self.stats["forwarded_unlisted_reads"] = self.stats.get("forwarded_unlisted_reads", 0) + 1
        self.shadow.profile.match((time.perf_counter() - t0) * 1000)
        return fr[2]

    async def serve(self, host: str, port: int):
        return await asyncio.start_server(self._client_wrap, host, port)

    async def _client_wrap(self, reader, writer):
        await self.handle_client(reader, writer)


class _Delayed(bytes):
    """PDU dengan tunda; ditulis setelah tidur (profil latensi bayangan)."""

    def __new__(cls, data: bytes, delay: float):
        o = super().__new__(cls, data)
        o.delay = delay
        return o
