"""Kelir: proxy Modbus/TCP, penilai sesi, dan pengalih ke bayangan (Bab 9.1, 9.4).

Jaminan keselamatan:
* Sesi yang sudah dialihkan (pinned) TIDAK PERNAH diteruskan ke aset asli.
* Pengalihan terjadi pada batas transaksi (sebelum permintaan diteruskan).
* Gagal aman: bila bayangan bermasalah, sesi mencurigakan diputus bersih.
* Lalu lintas daftar putih tetap melewati jalur asli.
"""
from __future__ import annotations

import asyncio
import ipaddress
import time

from engine.autonomy import Autonomy, Blocklist, L3_BLOCK_TTL_S, L3_REPEAT_THRESHOLD
from engine.gamelan import Gamelan
from kelir.mirror import StateMirror
from kelir.scoring import SessionScorer, Decision
from kelir.session import SessionRegistry
from shadows import modbus_proto as mp
from shadows.modbus_shadow import ShadowDevice

PROXY_HEADER_TIMEOUT_S = 2.0


async def read_proxy_v1(reader) -> str | None:
    """Baca header PROXY protocol v1 dari Gerbang Bypass; kembalikan IP klien asli."""
    try:
        line = await asyncio.wait_for(reader.readuntil(b"\r\n"), PROXY_HEADER_TIMEOUT_S)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
            asyncio.TimeoutError, ConnectionError):
        return None
    if len(line) > 107:
        return None
    parts = line.decode("ascii", "replace").strip().split(" ")
    if len(parts) != 6 or parts[0] != "PROXY" or parts[1] not in ("TCP4", "TCP6"):
        return None
    try:
        return str(ipaddress.ip_address(parts[2]))
    except ValueError:
        return None


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


class Kelir:
    def __init__(self, satuan: str, real_addr: tuple[str, int], shadow: ShadowDevice,
                 sessions: SessionRegistry, scorer: SessionScorer, bus: Gamelan,
                 autonomy: Autonomy | None = None, blocklist: Blocklist | None = None,
                 mirror: StateMirror | None = None, clock=time.monotonic,
                 zero_trust: bool = True, ids=None, ids_operator_mode: str = "alert"):
        self.satuan = satuan
        # Integrasi Suricata (opsional): IdsWatchlist dari integrations.suricata_eve.
        # ids_operator_mode: "alert" (bawaan, operator tetap ke aset asli) | "divert".
        if ids_operator_mode not in ("alert", "divert"):
            raise ValueError("ids_operator_mode harus 'alert' atau 'divert'")
        self.ids = ids
        self.ids_operator_mode = ids_operator_mode
        self.real_addr = real_addr
        self.shadow = shadow
        self.sessions = sessions
        self.scorer = scorer
        self.bus = bus
        self.autonomy = autonomy or Autonomy()
        self.blocklist = blocklist or Blocklist()
        self.mirror = mirror
        self.clock = clock
        self.zero_trust = zero_trust
        # Aktif bila Kelir duduk di belakang Gerbang Bypass: IP klien asli dibawa lewat
        # header PROXY v1, dan hanya dipercaya dari loopback (Gerbang di mesin yang sama).
        self.proxy_protocol = False
        self.divert_counts: dict[str, int] = {}
        self.active_conns = 0
        self.active_operator_conns = 0
        self.active_per_ip: dict[str, int] = {}
        self.max_global_conns = 300
        self.max_per_ip_conns = 20
        self.reserved_operator_slots = 30  # Komponen C: Alokasi eksklusif operator sah (QoS Anti-Starvation)
        self._sleep_overhead_s = 0.004     # Kompensasi adaptif jitter scheduler OS
        self.stats = {"forwarded": 0, "diverted_frames": 0, "fail_closed": 0, "blocked": 0,
                      "forwarded_operator": 0, "forwarded_unlisted_reads": 0,
                      "conns_rejected_pool": 0, "conns_rejected_rate": 0}

    @property
    def load_percentage(self) -> float:
        unlisted_cap = max(1, self.max_global_conns - self.reserved_operator_slots)
        active_unlisted = max(0, self.active_conns - self.active_operator_conns)
        return (active_unlisted / unlisted_cap) * 100.0

    @property
    def degradation_tier(self) -> int:
        """
        Komponen A: Multi-Tier Degradation Ladder (Tangga Degradasi Cerdas):
        Tingkat 1 (Beban Normal < 75%): High-Interaction fisik kontinu & ladder cycle
        Tingkat 2 (Beban Tinggi 75-90%): Stateless Mirror Decoy (hemat 90% CPU)
        Tingkat 3 (Kritis 90-98%): OT Tarpit (tahan soket buffer penyerang)
        Tingkat 4 (Kapasitas Penuh >= 98%): Blokir langsung di kernel / nftables
        """
        load = self.load_percentage
        if load < 75.0:
            return 1
        elif load < 90.0:
            return 2
        elif load < 98.0:
            return 3
        return 4

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

    def _ids_hit(self, src: str):
        if self.ids is None:
            return None
        try:
            return self.ids.flagged(src)
        except Exception:      # integrasi luar tidak boleh mematikan jalur Modbus
            return None

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
        if self.proxy_protocol:
            real = await read_proxy_v1(reader) if _is_loopback(src) else None
            if real is None:          # header hilang/cacat atau bukan dari Gerbang: tolak
                writer.close()
                return
            src = real
        up = None
        is_operator = src in self.scorer.whitelist

        # Komponen C: Isolasi Jalur Prioritas Operator (QoS Dedicated Pool)
        cur_ip_conns = self.active_per_ip.get(src, 0)
        if not is_operator:
            if cur_ip_conns >= self.max_per_ip_conns:
                self.stats["conns_rejected_rate"] = self.stats.get("conns_rejected_rate", 0) + 1
                writer.close()
                return
            unlisted_cap = self.max_global_conns - self.reserved_operator_slots
            active_unlisted = self.active_conns - self.active_operator_conns
            if active_unlisted >= unlisted_cap:
                self.stats["conns_rejected_pool"] = self.stats.get("conns_rejected_pool", 0) + 1
                writer.close()
                return
        else:
            self.active_operator_conns += 1

        self.active_conns += 1
        self.active_per_ip[src] = cur_ip_conns + 1
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
                    adj_delay = max(0.0005, resp.delay - self._sleep_overhead_s)
                    t_sl = time.perf_counter()
                    await asyncio.sleep(adj_delay)
                    over = max(0.0, min(0.015, (time.perf_counter() - t_sl) - adj_delay))
                    self._sleep_overhead_s = 0.8 * self._sleep_overhead_s + 0.2 * over
                writer.write(mp.build_mbap(tid, unit, bytes(resp)))
                await writer.drain()
        finally:
            if is_operator:
                self.active_operator_conns = max(0, self.active_operator_conns - 1)
            self.active_conns = max(0, self.active_conns - 1)
            if src in self.active_per_ip:
                self.active_per_ip[src] = max(0, self.active_per_ip[src] - 1)
                if self.active_per_ip[src] == 0:
                    del self.active_per_ip[src]
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

            hit = self._ids_hit(src)
            if hit is not None and not self.maintenance_mode:
                # IP bukan identitas: operator terdaftar yang ditandai Suricata
                # kemungkinan workstation-nya dikuasai penyerang.
                if not getattr(s, "ids_noted", False):
                    s.ids_noted = True
                    s.observe(now, req.action, unit=unit, table=req.table, addr=req.addr,
                              qty=req.qty, fc=req.fc, is_write=req.is_write)
                    self._event(s, "ids_flag_operator", reason=hit.reason(), src=src,
                                ids_sid=hit.sid, ids_signature=hit.signature,
                                ids_severity=hit.severity, ids_mode=self.ids_operator_mode,
                                unit=unit, fc=req.fc)
                if self.ids_operator_mode == "divert" and self.autonomy.can_divert:
                    self._pin(s, Decision(1.0, True, f"karantina operator: {hit.reason()}"))
                    return self._to_shadow(s, src, unit, pdu)

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
        hit = self._ids_hit(src)
        if hit is not None and not self.maintenance_mode:
            # Korelasi IDS: sumber tak terdaftar yang sudah ditandai Suricata
            # dialihkan sejak frame pertama, apa pun skor heuristiknya.
            decision = Decision(max(decision.score, 1.0), True,
                                f"dialihkan karena: {hit.reason()} + {decision.reason}",
                                decision.signals)
        # Kebijakan Zero Trust Bawaan:
        # Sumber tak terdaftar selalu dilayani bayangan berbasis State Mirror (0 bacaan ke PLC riil),
        # kecuali jika teknisi sah mengaktifkan Mode Perawatan (maintenance mode).
        # Aset asli hanya melayani sumber terdaftar berkebijakan.
        divert = (
            decision.divert
            or (non_read and not self.maintenance_mode)
            or (self.zero_trust and not self.maintenance_mode)
        )
        if divert and self.autonomy.can_divert:
            if self.zero_trust and not decision.divert and not non_read:
                decision = Decision(decision.score, True, "zero_trust bawaan: sumber tak terdaftar dilayani bayangan cermin")
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
        tier = self.degradation_tier
        if tier >= 4:
            # Tingkat 4 (Kapasitas Penuh 100%): Dorong blokir langsung ke kernel Linux / nftables
            self.blocklist.add(src, ttl_s=3600, reason="Kapasitas Penuh 100% - Kernel L4 Drop", who="kernel-drop")
            self._event(s, "kernel_l4_drop", tier=4, load_pct=round(self.load_percentage, 1))
            self.stats["fail_closed"] += 1
            return None

        # Tingkat 2 & 3: Turunkan ke mode Stateless Mirror Decoy (hemat 90% CPU)
        if tier >= 2:
            self.shadow.degradation_tier = 1
        else:
            self.shadow.degradation_tier = 0

        try:
            req_parsed = mp.parse_pdu(pdu)
            if req_parsed.is_write:
                val_repr = getattr(req_parsed, "val", None)
                if val_repr is None and hasattr(req_parsed, "values"):
                    val_repr = req_parsed.values[0] if len(req_parsed.values) == 1 else list(req_parsed.values)
                self._event(s, "diverted_write_alert",
                            unit=unit, fc=req_parsed.fc, addr=req_parsed.addr, val=val_repr,
                            table=req_parsed.table,
                            reason="Perintah tulis dialihkan ke bayangan (dibuang dari aset fisik)")
        except Exception:
            pass

        t0_shadow = time.perf_counter()
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

        # Kompensasi waktu eksekusi internal (fisika, event bus, SQLite hashchain)
        # agar total latensi respons yang diamati penyerang persis sama dengan aset riil
        elapsed = time.perf_counter() - t0_shadow
        delay = max(0.0005, delay - elapsed)

        # Tingkat 3 (Kritis 90-98%): OT Tarpit - Tahan soket buffer penyerang
        if tier == 3:
            delay = max(delay, 0.85)

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
