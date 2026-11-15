"""Suricata -> WAYANG: alert di eve.json menjadi tanda ancaman untuk Kelir.

Alur: Suricata (port mirror/SPAN segmen OT) mendeteksi -> EveWatcher membaca
alert baru -> IdsWatchlist menandai IP sumber selama TTL -> Kelir:

* sumber TAK TERDAFTAR yang ditandai langsung dialihkan ke bayangan sejak frame
  pertama (termasuk saat zero_trust dimatikan), dengan alasan yang menyebut
  signature Suricata;
* sumber OPERATOR TERDAFTAR yang ditandai (indikasi workstation dikuasai) secara
  bawaan hanya memicu peringatan ke Dalang (mode "alert"), karena mengalihkan
  operator sah memutus kendali proses nyata. Mode "divert" tersedia untuk lab
  atau bila komandan memutuskan karantina.

WAYANG tidak pernah menulis ke Suricata; arah sebaliknya lewat draf rule di
engine.rulegen.suricata_rules yang butuh persetujuan Dalang.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Callable

log = logging.getLogger("wayang.suricata")

DEFAULT_TTL_S = 900.0
DEFAULT_MAX_SEVERITY = 2          # Suricata: 1 = paling berat, 3 = rendah
MAX_LINE_BYTES = 1_000_000        # baris EVE abnormal (mis. payload besar) diabaikan


@dataclass
class IdsHit:
    ip: str
    sid: int
    signature: str
    severity: int
    category: str = ""
    action: str = "allowed"       # allowed | blocked (mode IPS)
    first: float = 0.0
    last: float = 0.0
    expires: float = 0.0
    count: int = 1
    sids: set = field(default_factory=set)

    def reason(self) -> str:
        blk = ", diblokir IPS" if self.action == "blocked" else ""
        return (f"ditandai Suricata IDS: {self.signature} "
                f"(sid {self.sid}, severity {self.severity}{blk})")


class IdsWatchlist:
    """Daftar IP yang ditandai IDS, kedaluwarsa otomatis setelah TTL."""

    def __init__(self, ttl_s: float = DEFAULT_TTL_S, clock=time.monotonic,
                 ignore: set[str] | None = None):
        self.ttl_s = ttl_s
        self.clock = clock
        self.ignore = set(ignore or ())
        self._hits: dict[str, IdsHit] = {}

    def add(self, ip: str, sid: int, signature: str, severity: int,
            category: str = "", action: str = "allowed") -> tuple[IdsHit, bool]:
        """Tandai IP. Kembalikan (hit, baru_atau_memburuk)."""
        now = self.clock()
        h = self.flagged(ip)
        if h is None:
            h = IdsHit(ip, sid, signature, severity, category, action,
                       first=now, last=now, expires=now + self.ttl_s, sids={sid})
            self._hits[ip] = h
            return h, True
        h.count += 1
        h.last = now
        h.expires = now + self.ttl_s
        worse = severity < h.severity or sid not in h.sids
        h.sids.add(sid)
        if severity < h.severity:
            h.sid, h.signature, h.severity, h.category = sid, signature, severity, category
        if action == "blocked":
            h.action = "blocked"
        return h, worse

    def flagged(self, ip: str) -> IdsHit | None:
        h = self._hits.get(ip)
        if h is None:
            return None
        if self.clock() >= h.expires:
            del self._hits[ip]
            return None
        return h

    def active(self) -> list[IdsHit]:
        return [h for ip in list(self._hits) if (h := self.flagged(ip))]


def parse_alert(line: str, max_severity: int = DEFAULT_MAX_SEVERITY) -> dict | None:
    """Ambil alert relevan dari satu baris EVE; None bila bukan alert atau tak layak."""
    line = line.strip()
    if not line or len(line) > MAX_LINE_BYTES:
        return None
    try:
        ev = json.loads(line)
    except ValueError:
        return None
    if not isinstance(ev, dict) or ev.get("event_type") != "alert":
        return None
    al = ev.get("alert")
    if not isinstance(al, dict):
        return None
    try:
        severity = int(al.get("severity", 3))
        sid = int(al.get("signature_id", 0))
    except (TypeError, ValueError):
        return None
    if severity > max_severity:
        return None
    # Suricata 7+ mengisi alert.source bila rule memakai kata kunci `target`;
    # tanpa itu src_ip adalah pengirim paket yang memicu rule.
    src = (al.get("source") or {}).get("ip") if isinstance(al.get("source"), dict) else None
    src = src or ev.get("src_ip")
    try:
        ip = str(ipaddress.ip_address(str(src)))
    except ValueError:
        return None
    return {
        "ip": ip, "sid": sid, "severity": severity,
        "signature": str(al.get("signature", ""))[:200],
        "category": str(al.get("category", ""))[:100],
        "action": "blocked" if al.get("action") == "blocked" else "allowed",
        "dest_ip": ev.get("dest_ip"), "dest_port": ev.get("dest_port"),
        "proto": ev.get("app_proto") or ev.get("proto"),
        "ts": ev.get("timestamp"),
    }


class EveWatcher:
    """Membaca eve.json secara bertahap (tail), tahan rotasi dan pemotongan berkas."""

    def __init__(self, path: str, watchlist: IdsWatchlist,
                 on_flag: Callable[[IdsHit, dict], None] | None = None,
                 max_severity: int = DEFAULT_MAX_SEVERITY, from_start: bool = False,
                 interval_s: float = 1.0):
        self.path = path
        self.watchlist = watchlist
        self.on_flag = on_flag
        self.max_severity = max_severity
        self.interval_s = interval_s
        self._pos: int | None = 0 if from_start else None
        self._ino = None
        self._buf = b""
        self._task: asyncio.Task | None = None
        self.stats = {"lines": 0, "alerts": 0, "flags": 0}

    def poll(self) -> int:
        """Baca baris baru sekali. Kembalikan jumlah alert yang diproses."""
        try:
            st = os.stat(self.path)
        except OSError:
            return 0
        ino = (st.st_ino, st.st_dev)
        if self._pos is None:                       # mulai dari ujung: jangan putar ulang riwayat
            self._pos, self._ino = st.st_size, ino
            return 0
        if ino != self._ino or st.st_size < self._pos:   # rotasi atau dipotong
            self._pos, self._buf = 0, b""
            self._ino = ino
        if st.st_size == self._pos:
            return 0
        try:
            with open(self.path, "rb") as f:
                f.seek(self._pos)
                chunk = f.read(8 * 1024 * 1024)
        except OSError:
            return 0
        self._pos += len(chunk)
        data = self._buf + chunk
        *lines, self._buf = data.split(b"\n")
        if len(self._buf) > MAX_LINE_BYTES:
            self._buf = b""
        n = 0
        for raw in lines:
            self.stats["lines"] += 1
            a = parse_alert(raw.decode("utf-8", "replace"), self.max_severity)
            if a is None or a["ip"] in self.watchlist.ignore:
                continue
            n += 1
            self.stats["alerts"] += 1
            hit, changed = self.watchlist.add(a["ip"], a["sid"], a["signature"],
                                              a["severity"], a["category"], a["action"])
            if changed:
                self.stats["flags"] += 1
                if self.on_flag:
                    try:
                        self.on_flag(hit, a)
                    except Exception:
                        log.exception("penangan tanda IDS gagal")
        return n

    async def _run(self) -> None:
        while True:
            try:
                self.poll()
            except Exception:
                log.exception("pembacaan eve.json gagal")
            await asyncio.sleep(self.interval_s)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.ensure_future(self._run())

    def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self._task = None

    def status(self) -> dict:
        return {"path": self.path, **self.stats,
                "flagged": [{"ip": h.ip, "sid": h.sid, "signature": h.signature,
                             "severity": h.severity, "count": h.count}
                            for h in self.watchlist.active()]}
