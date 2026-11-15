"""Tes Penjaga: alat serang, payload, probe, banjir, dan integrasi ke Dalang Console."""
import asyncio

import httpx

from console.api import make_console_app
from console.penjaga import Penjaga
from console.pusat import Pusat


def _p(**kw):
    kw.setdefault("enabled", True)
    kw.setdefault("allow", set())
    kw.setdefault("exempt_loopback", False)
    return Penjaga(**kw)


def test_blocks_attack_tools_and_site_copiers():
    g = _p()
    assert g.check("1.1.1.1", "GET", "/", "", "sqlmap/1.7#stable")[0] == 403
    assert g.is_banned("1.1.1.1")
    assert g.check("1.1.1.1", "GET", "/", "", "Mozilla/5.0")[0] == 403  # tetap terblokir
    assert g.check("2.2.2.2", "GET", "/", "", "Mozilla/4.5 (compatible; HTTrack 3.0x)")[0] == 403
    assert g.check("3.3.3.3", "GET", "/", "", "Wget/1.21")[0] == 403
    assert g.check("4.4.4.4", "GET", "/", "", "Mozilla/5.0 Chrome/130") is None


def test_blocks_attack_payloads():
    g = _p()
    for i, (path, q) in enumerate([
        ("/api/map", "x=1' or 1=1--"),
        ("/api/map", "q=%3Cscript%3Ealert(1)%3C/script%3E"),
        ("/static/..%2f..%2fetc/passwd", ""),
        ("/api/map", "u=${jndi:ldap://x/a}"),
        ("/api/map", "id=1 UNION SELECT password FROM users"),
    ]):
        ip = f"9.9.9.{i}"
        assert g.check(ip, "GET", path, q, "Mozilla/5.0")[0] == 403, (path, q)
        assert g.is_banned(ip)


def test_probe_paths_strike_then_ban():
    g = _p()
    ip = "5.5.5.5"
    for path in ("/.env", "/wp-login.php", "/.git/config"):
        assert g.check(ip, "GET", path, "", "Mozilla/5.0")[0] in (403, 404)
    assert g.is_banned(ip)
    assert g.unban(ip) and not g.is_banned(ip)


def test_rate_limit_bans_flood():
    g = _p(rate=20, window_s=60)
    codes = [g.check("6.6.6.6", "GET", "/api/map", "", "Mozilla/5.0") for _ in range(22)]
    assert codes[:20] == [None] * 20 and codes[20][0] == 429
    assert g.is_banned("6.6.6.6")


def test_loopback_and_allowlist_never_banned():
    g = Penjaga(enabled=True, rate=2, allow={"7.7.7.7"}, exempt_loopback=True)
    for _ in range(10):
        assert g.check("127.0.0.1", "GET", "/api/map", "", "Mozilla/5.0") is None
        assert g.check("7.7.7.7", "GET", "/api/map", "", "Mozilla/5.0") is None
    # payload jahat tetap ditolak per-permintaan walau IP-nya dikecualikan dari blokir
    assert g.check("127.0.0.1", "GET", "/api/map", "x=<script>", "Mozilla/5.0")[0] == 403
    assert not g.is_banned("127.0.0.1")


def test_disabled_guard_passes_everything():
    g = Penjaga(enabled=False)
    assert g.check("1.1.1.1", "GET", "/.env", "", "sqlmap") is None


def test_console_integration_headers_and_guard_endpoint():
    async def go():
        app = make_console_app({}, Pusat(), admin_token="tok")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://c") as c:
            r = await c.get("/")
            assert r.status_code == 200
            assert "noarchive" in r.headers["x-robots-tag"]
            assert r.headers["cross-origin-resource-policy"] == "same-origin"
            assert (await c.get("/robots.txt")).text.startswith("User-agent: *")
            assert (await c.get("/", headers={"User-Agent": "Nikto/2.5"})).status_code == 403
            assert (await c.get("/.env")).status_code == 404
            assert (await c.get("/api/map?x=<script>")).status_code == 403
            assert (await c.get("/api/guard")).status_code == 401           # butuh login
            st = (await c.get("/api/guard", headers={"X-Wayang-Token": "tok"})).json()
            assert st["enabled"] and st["blocked_total"] >= 3
            big = await c.post("/api/auth/login", content=b"x" * 10,
                               headers={"Content-Length": "5000000"})
            assert big.status_code == 413
    asyncio.run(go())
