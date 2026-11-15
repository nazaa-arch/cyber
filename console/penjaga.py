"""PENJAGA — penjaga gerbang Dalang Console.

Lapisan pertahanan aplikasi web yang berjalan sebelum autentikasi:

1. Blokir alat serang & penyalin situs (sqlmap, nikto, nuclei, HTTrack, wget -m, ...)
   berdasarkan User-Agent.
2. Tolak payload serangan umum di URL (SQLi, XSS, path traversal, Log4Shell, ...).
3. Jebakan jalur probe (/.env, /.git, /wp-admin, ...): tiap sentuhan = satu "strike".
4. Pembatas laju per-IP (anti-flood / anti-scraping massal).
5. IP yang melanggar diblokir sementara (default 15 menit) dan dicatat.

Semua aturan bersifat defensif: hanya menolak permintaan, tidak pernah membalas
menyerang (zero hack-back).

Konfigurasi lewat environment:
    WAYANG_GUARD=0                  matikan penjaga (default: aktif)
    WAYANG_GUARD_RATE=600           maks permintaan per IP per jendela
    WAYANG_GUARD_WINDOW=60          lebar jendela laju (detik)
    WAYANG_GUARD_BAN=900            lama blokir IP (detik)
    WAYANG_GUARD_ALLOW=1.2.3.4,...  IP yang tak pernah diblokir
    WAYANG_GUARD_EXEMPT_LOOPBACK=1  IP loopback tak diblokir (proxy lokal, cloudflared)
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import time
from collections import deque
from urllib.parse import unquote_plus

log = logging.getLogger("wayang.penjaga")

# Alat pemindai/eksploitasi dan penyalin situs (pencocokan substring, huruf kecil).
BAD_AGENTS = (
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei", "acunetix", "netsparker",
    "wpscan", "dirbuster", "gobuster", "dirb", "ffuf", "feroxbuster", "wfuzz", "hydra",
    "arachni", "openvas", "nessus", "w3af", "skipfish", "whatweb", "jaeles", "commix",
    "xsstrike", "burpcollaborator", "interactsh",
    # penyalin/penjiplak situs
    "httrack", "wget", "webcopier", "webcopy", "sitesucker", "teleport", "offline explorer",
    "websitecopier", "webzip", "webreaper", "webstripper", "grabber", "scrapy", "heritrix",
    "archive.org_bot", "ia_archiver",
)

# Jalur yang tak pernah ada di konsol ini; hanya pemindai yang mencarinya.
PROBE_PATHS = re.compile(
    r"(^/\.(env|git|svn|hg|aws|ssh|htaccess|htpasswd|ds_store|vscode|idea)"
    r"|^/(wp-admin|wp-login|wp-content|wp-includes|xmlrpc\.php|wordpress)"
    r"|^/(phpmyadmin|pma|myadmin|adminer|phpinfo|info\.php|config\.php|admin\.php|setup\.php)"
    r"|^/(cgi-bin|server-status|server-info|actuator|console/|manager/html|solr|jenkins)"
    r"|^/(vendor/phpunit|boaform|hnap1|owa/|autodiscover|telescope|_profiler|debug/)"
    r"|\.(php|asp|aspx|jsp|cgi|bak|sql|old|swp|backup|tar\.gz|zip)$)",
    re.IGNORECASE,
)

# Pola payload serangan di path / query.
ATTACK_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|/proc/self|c:\\windows|win\.ini"
    r"|<script|javascript:|onerror\s*=|onload\s*=|<svg|<iframe"
    r"|union[\s(]+select|select\s.+\sfrom\s|sleep\s*\(|benchmark\s*\(|waitfor\s+delay"
    r"|'\s*or\s+'?\d|\bor\s+1\s*=\s*1|information_schema|load_file\s*\("
    r"|\$\{jndi:|\$\{env:|\{\{.*\}\}|<\?php|base64_decode\s*\(|cmd\.exe|/bin/(ba)?sh)",
    re.IGNORECASE,
)

STRIKES_TO_BAN = 3
MAX_LOG = 200


def _env_flag(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


class Penjaga:
    def __init__(self, *, enabled: bool | None = None, rate: int | None = None,
                 window_s: float | None = None, ban_s: float | None = None,
                 allow: set[str] | None = None, exempt_loopback: bool | None = None):
        self.enabled = _env_flag("WAYANG_GUARD", True) if enabled is None else enabled
        self.rate = rate if rate is not None else int(os.environ.get("WAYANG_GUARD_RATE", "600"))
        self.window_s = window_s if window_s is not None else float(os.environ.get("WAYANG_GUARD_WINDOW", "60"))
        self.ban_s = ban_s if ban_s is not None else float(os.environ.get("WAYANG_GUARD_BAN", "900"))
        self.allow = allow if allow is not None else {
            a.strip() for a in os.environ.get("WAYANG_GUARD_ALLOW", "").split(",") if a.strip()}
        self.exempt_loopback = (_env_flag("WAYANG_GUARD_EXEMPT_LOOPBACK", True)
                                if exempt_loopback is None else exempt_loopback)
        self.hits: dict[str, deque] = {}
        self.strikes: dict[str, int] = {}
        self.banned: dict[str, dict] = {}       # ip -> {"until": ts, "reason": str}
        self.events: deque = deque(maxlen=MAX_LOG)
        self.blocked_total = 0

    # -- utilitas -----------------------------------------------------------
    def _exempt(self, ip: str) -> bool:
        if ip in self.allow:
            return True
        if self.exempt_loopback:
            try:
                return ipaddress.ip_address(ip).is_loopback
            except ValueError:
                return False
        return False

    def _record(self, ip: str, kind: str, detail: str, path: str):
        self.blocked_total += 1
        self.events.append({"ts": time.time(), "ip": ip, "kind": kind,
                            "detail": detail[:120], "path": path[:200]})
        log.warning("PENJAGA %s ip=%s path=%s (%s)", kind, ip, path[:200], detail[:120])

    def ban(self, ip: str, reason: str):
        if self._exempt(ip):
            return
        self.banned[ip] = {"until": time.time() + self.ban_s, "reason": reason}
        self.strikes.pop(ip, None)
        log.warning("PENJAGA BLOKIR ip=%s selama %ds: %s", ip, int(self.ban_s), reason)

    def unban(self, ip: str) -> bool:
        self.strikes.pop(ip, None)
        self.hits.pop(ip, None)
        return self.banned.pop(ip, None) is not None

    def is_banned(self, ip: str) -> bool:
        b = self.banned.get(ip)
        if not b:
            return False
        if b["until"] < time.time():
            self.banned.pop(ip, None)
            return False
        return True

    def _strike(self, ip: str, reason: str):
        if self._exempt(ip):
            return
        n = self.strikes.get(ip, 0) + 1
        self.strikes[ip] = n
        if n >= STRIKES_TO_BAN:
            self.ban(ip, reason)

    # -- pemeriksaan utama ---------------------------------------------------
    def check(self, ip: str, method: str, path: str, query: str, user_agent: str):
        """Kembalikan None bila lolos, atau (status_code, pesan) bila ditolak."""
        if not self.enabled:
            return None

        if self.is_banned(ip):
            self.blocked_total += 1
            return 403, "Akses diblokir sementara oleh Penjaga WAYANG"

        ua = (user_agent or "").lower()
        for bad in BAD_AGENTS:
            if bad in ua:
                self._record(ip, "ALAT_SERANG", f"user-agent: {bad}", path)
                self.ban(ip, f"alat serang/penyalin: {bad}")
                return 403, "Akses ditolak"

        raw = path + ("?" + query if query else "")
        decoded = unquote_plus(unquote_plus(raw))
        m = ATTACK_PATTERNS.search(raw) or ATTACK_PATTERNS.search(decoded)
        if m:
            self._record(ip, "PAYLOAD_SERANGAN", m.group(0), path)
            self.ban(ip, f"payload serangan: {m.group(0)[:40]}")
            return 403, "Permintaan ditolak"

        if PROBE_PATHS.search(path):
            self._record(ip, "PROBE", "jalur pemindai", path)
            self._strike(ip, "pemindaian jalur berulang")
            return 404, "Not Found"

        if method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            self._record(ip, "METODE_ANEH", method, path)
            self._strike(ip, f"metode HTTP tidak lazim: {method}")
            return 405, "Metode tidak diizinkan"

        if not self._exempt(ip):
            now = time.time()
            q = self.hits.setdefault(ip, deque())
            while q and now - q[0] > self.window_s:
                q.popleft()
            q.append(now)
            if len(q) > self.rate:
                self._record(ip, "BANJIR", f"{len(q)} permintaan/{int(self.window_s)}s", path)
                self.ban(ip, "banjir permintaan (flood/scraping)")
                return 429, "Terlalu banyak permintaan"
            if len(self.hits) > 50_000:   # cegah memori membengkak oleh IP acak
                for k in list(self.hits)[:10_000]:
                    self.hits.pop(k, None)
        return None

    def status(self) -> dict:
        now = time.time()
        for ip in [ip for ip, b in self.banned.items() if b["until"] < now]:
            self.banned.pop(ip, None)
        return {
            "enabled": self.enabled,
            "rate_limit": f"{self.rate}/{int(self.window_s)}s",
            "ban_seconds": int(self.ban_s),
            "blocked_total": self.blocked_total,
            "banned": [{"ip": ip, "reason": b["reason"], "remaining_s": int(b["until"] - now)}
                       for ip, b in self.banned.items()],
            "recent": list(self.events)[-50:][::-1],
        }
