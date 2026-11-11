# WAYANG — Blind Security Assessment · Phase 1: Attack Surface Discovery

**Target:** `https://cyber.steamcraft.online/`
**Assessment type:** Independent authenticated black-box (token supplied by owner)
**Phase:** 1 — Attack Surface Discovery (read-only)
**Date:** 2026-11-09
**Analyst note:** This phase performed **no destructive actions, no automated scanning/fuzzing, no exploit payloads, no data modification, and no operational-control triggering.** All observations derive from normal HTTP/HTTPS requests and inspection of publicly served responses only. The administrator token was not printed, stored, or transmitted beyond normal use by the owner's own front-end.

---

## 1. Scope & Method

- **Access model:** The application exposes a public HTML/JS single-page console at `/`. Every functional API route behind it returns `401 Unauthorized` (FastAPI-style JSON detail) until authentication.
- **Method:** Passive observation of HTTP response headers, status codes, cookie/session behavior, WebSocket handshake, CORS preflight, and the inline JavaScript embedded in the legitimately served landing page (the client-side SPA is public and downloadable — analysis of it is observation of the target's own delivered content, not inspection of backend source code).
- **Restrictions honored:** No enumeration/brute-forcing of paths beyond a small set of standard framework endpoints (`robots.txt`, `sitemap.xml`, `security.txt`, `openapi.json`, `docs`, `redoc`). No fuzzing. No injection payloads.

---

## 2. Executive Summary

WAYANG is a Python (uvicorn/FastAPI or Starlette) application fronted by Cloudflare and hosted on Render.io. It presents a military C4ISR "deception grid" console with a single-shared "Komando" token as the sole authentication mechanism. The landing page is a fully public SPA that ships the **complete inline UI logic including every API route, the auth/session flow, and the WebSocket endpoint** to unauthenticated visitors.

Baseline security posture is **strong** for a hardened console: HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `cache-control: no-store`, a nonce on the inline script tag, and non-permissive CORS were all observed. The main areas worth follow-up (requiring additional authorization) are: (1) the auth/session token model and its transport/handling, (2) the fully-enumerated operational-control endpoints, and (3) confirmation of whether a Content-Security-Policy is actually enforced end-to-end.

> **No vulnerabilities are claimed in this phase.** Items are recorded as observations with a *potential* security implication; findings not yet evidenced are explicitly marked as requiring further authorized testing.

---

## 3. Publicly Accessible Surface

| URL | Status | Evidence | Implication |
|---|---|---|---|
| `/` | 200 | 111,108-byte `text/html` SPA, `<title>WAYANG · Deception Grid Adaptif IT/OT TNI AD</title>` | Landing console is public; full UI + inline JS is downloadable by anyone |
| `/static/leaflet.js` | 200 | 147,552 bytes `text/javascript` | Third-party map lib (Leaflet) served publicly |
| `/static/echarts.min.js` | 200 | (asset referenced; response observed non-empty) | Charting lib served publicly |
| `/static/Logo.jpeg` | 200 | `image/jpeg` 1,334,222 bytes | Static asset public |
| `/robots.txt` | **401** | `{"detail":"Autentikasi diperlukan"}` | Crawler-disclosure file itself is behind auth — no intentional public indexing hints |
| `/sitemap.xml` | 401 | FastAPI JSON 401 | No public sitemap |
| `/.well-known/security.txt` | 401 | FastAPI JSON 401 | No public security.txt |
| `/openapi.json`, `/api/openapi.json` | 401 | FastAPI JSON 401 | API schema not publicly exposed (good) |
| `/docs`, `/redoc`, `/api/docs`, `/api/redoc` | 401 | FastAPI JSON 401 | Interactive docs disabled/guarded (good) |
| `/api/` (and all `/api/*` probed) | 401 | `{"detail":"Autentikasi diperlukan"}` | Entire API surface is authenticated at the edge |

**Observation OA-1 — SPA-only public root, everything else 401.** The front-end is served only at `/`; no catch-all SPA fallback was observed.

- **Evidence:** `robots.txt`, `sitemap.xml`, `security.txt`, `openapi.json`, `docs`, and every `/api/*` path each returned `401` with a JSON body, while `/` returned `200`.
- **Implication:** Favourable — reduces accidental exposure of unauthenticated endpoints. Worth confirming there is no hidden catch-all route (see OA-5).
- **Further testing required:** None; observed.

---

## 4. Dashboard Sections & Features (as revealed by public SPA)

The public landing page exposes the following interface and feature set (identifiers recovered from the delivered inline JavaScript):

**Right-rail tabs:** `stream` (event stream), `attck` (MITRE ATT&CK matrix), `dec` (decisions), `ses` (forensic sessions).

**Command/functions surfaced via `data-act` handlers:**

| Feature | Client handler | Backend call observed in JS |
|---|---|---|
| Login / token entry | `doLogin` | `POST /api/auth/login` |
| Logout | `doLogout` | `POST /api/auth/logout` |
| DEFCON level change | `changeDefcon` | (UI-local; see autonomy) |
| Autonomy level | `setAutonomyUI` | `POST /api/autonomy` |
| Killswitch / failsafe reset | `post('/api/killswitch')` | `POST /api/killswitch` |
| Attack simulation types | `sim(type)` | `POST /api/simulate/{type}` |
| Unit lockdown | `lockdownCurrent` | `POST /api/tactical/lockdown/{satuan}` |
| Resolve campaign | `resolveCampaign` | `POST /api/tactical/campaign/resolve` |
| Reset incidents (display) | `resetIncidents` | `POST /api/tactical/incidents/reset` |
| Neutralise all threats | `resolveAllThreats` | `POST /api/tactical/campaign/resolve` (empty body) |
| Decision action | `postDecision` | `POST /api/decisions/…` |
| Open forensic session | `openSes` | `GET /api/replay/{satuan}/{id}` |
| Twin-screen (SCADA) | `refreshTwin` | `GET /api/twinscreen/{satuan}` |
| Main state refresh | `refresh` | `GET /api/map`, `/campaigns`, `/decisions`, `/sessions`, `/heatmap`, `/autonomy`, `/bot`, `/recon`, `/personas`, `/map/vectors`, `/events/recent` |
| Recent packets | `renderSelectedPacket` | `GET /api/packets/recent` |
| STIX export | link | `GET /api/tactical/rules/stix.json` |
| Report export | link | `GET /api/report/{satuan}/{id}.docx` / `.html`, `GET /api/report/latest.docx` |

**Observation OA-2 — Client-side feature map fully disclosed publicly.**
- **Evidence:** The entire `data-act` dispatch table and all `fetch`/`post` target paths are present in the unauthenticated `200` response.
- **Implication:** Low-to-moderate. The app is designed as a single shared console; knowing route names is not by itself a vulnerability, but it removes any "security through obscurity" around the control surface and shortens any subsequent authorised probing.
- **Further testing required:** None for Phase 1; the endpoints themselves (Phase 2+ IDOR/authz/injection) require additional authorization.

---

## 5. Authenticated/Observed API Route Inventory

Routes observed through the SPA's own `refresh()` dispatch and inline handlers (method inferred from the client code):

### Read (GET)
`/api/map`, `/api/campaigns`, `/api/decisions`, `/api/sessions`, `/api/heatmap`, `/api/autonomy`, `/api/bot`, `/api/recon`, `/api/personas`, `/api/map/vectors`, `/api/events/recent`, `/api/packets/recent`, `/api/replay/{satuan}/{id}`, `/api/twinscreen/{satuan}`, `/api/tactical/rules/stix.json`, `/api/report/latest.docx`, `/api/report/{satuan}/{id}.docx`, `/api/report/{satuan}/{id}.html`, `/api/auth/status`

### Write (POST — operational)
`/api/auth/login`, `/api/auth/logout`, `/api/autonomy`, `/api/killswitch`, `/api/simulate/{type}`, `/api/tactical/lockdown/{satuan}`, `/api/tactical/campaign/resolve`, `/api/tactical/incidents/reset`, `/api/decisions/…`

### Realtime
`WebSocket /ws/live` (constructed by the client as `wss://<host>/ws/live`).

**Observation OA-3 — All endpoints return identical 401 without a session.**
- **Evidence:** Every probed `GET` returned `401 application/json` with `{"detail":"Autentikasi diperlukan"}` (35-byte body).
- **Implication:** Favorable — the auth gate appears consistently applied. No unauthenticated resource was found.
- **Further testing required:** Confirm edge/method/version bypass behaviour in a later authorized phase.

---

## 6. Authentication & Session Behaviour

- **Model:** Single shared "Komando Token" (`Token Komando`) — no per-user accounts observed in the login UI.
- **Login:** `POST /api/auth/login` with JSON body `{"token":"<value>"}`. On success the client calls `location.reload()`; on failure the server returns `401` with `{"detail":"Token salah"}`.
- **Session state:** `GET /api/auth/status` returns `{"required":true,"authed":false}` unauth. The client polls this to decide whether to show the login overlay; the app supports an optional "open mode" (`Terautentikasi atau tanpa token (mode terbuka)`) if `required` is false.
- **WebSocket auth:** `GET` upgrade to `/ws/live` returned `401` without a session, consistent with cookie-based session auth (no token in URL/query).

**Observation OA-4 — Token login over JSON POST; no `Set-Cookie` on the failed path.**
- **Evidence:** `POST /api/auth/login` with an invalid token returned `401` and **no `Set-Cookie`** header; the response was JSON-only.
- **Implication:** The valid session cookie is presumably `HttpOnly`-set only on success. The login endpoint itself carries no CSRF token in the request, but it is a JSON `Content-Type` POST and CORS is non-permissive (`OPTIONS` → `405`, no `Access-Control-Allow-*`), which substantially reduces cross-origin exploitability. **No rate-limiting claim is made** (only a single request was observed).
- **Further testing required:** YES — authenticated session-cookie attributes (`Secure`/`HttpOnly`/`SameSite`), token brute-force/lockout behaviour, and session fixation are later-phase items requiring explicit authorization.

**Observation OA-5 — Framework/stack fingerprinting.**
- **Evidence:** `x-render-origin-server: uvicorn` (ASGI server) + `rndr-id` (Render.io platform header) + `cf-ray`/`cf-cache-status` (Cloudflare). No `Server` header.
- **Implication:** Backend is Python uvicorn — most consistent with FastAPI/Starlette. `server` header suppression is good; the residual platform headers still disclose hosting and approximate stack, which aids targeted (authorized) testing.
- **Further testing required:** No.

---

## 7. Security Headers & Cookie Attributes

Observed on the `200 /` response:

| Header | Value | Assessment |
|---|---|---|
| `strict-transport-security` | `max-age=63072000; includeSubDomains` | Good (2-year HSTS, subdomains) |
| `x-content-type-options` | `nosniff` | Good |
| `x-frame-options` | `SAMEORIGIN` | Good (clickjacking mitigation) |
| `referrer-policy` | `strict-origin-when-cross-origin` | Good |
| `permissions-policy` | `camera=(), microphone=(), geolocation=()` | Good (sensitive APIs denied) |
| `cross-origin-opener-policy` | `same-origin` | Good |
| `x-xss-protection` | `1; mode=block` | Present (legacy; neutral) |
| `cache-control` / `pragma` / `expires` | `no-cache, no-store, must-revalidate` / `no-cache` / `0` | Good (sensitive content not cached) |
| `content-security-policy` | **absent** | See OA-6 |
| `server` | absent | Good (limited fingerprint) |

- **Cookie attributes:** No `Set-Cookie` issued on the unauth/n login paths observed. Authenticated cookie attributes could not be observed read-only without using the token; deferred to a later authorized phase.

**Observation OA-6 — Inline-script nonce present, but no Content-Security-Policy delivered.**
- **Evidence:** The page ships `<script nonce="Zuk5vTIo9TFAsBDESRtztQ">…</script>`, yet no `Content-Security-Policy` header and no CSP `<meta>` are present in the same response.
- **Implication:** A CSP nonce only provides protection when a CSP policy actually grants script execution via that nonce. As served, the nonce is inert and CSP is effectively **not enforcing**. The code comment (`/* CSP nonce; tanpa handler inline onclick */`) shows intent to migrate to a strict CSP; the policy appears not yet delivered on the observed route.
- **Further testing required:** Confirming CSP delivery across routes (and whether the missing CSP is environment-specific) requires normal authenticated browsing — additional authorization recommended.

**Observation OA-7 — Cloudflare edge + dynamic render.**
- **Evidence:** `cf-cache-status: DYNAMIC`, `cf-ray`, `alt-svc: h3`.
- **Implication:** WAF/CDN in front; normal for the stack. No implication on its own.

---

## 8. Exposed Information & Client-Side Trust Observations

**OA-8 — Client-side "anti-inspection" is cosmetic.**
- **Evidence:** The SPA installs a `MutationObserver` watchdog, blocks `F12`/`Ctrl+Shift+I/J/C`/`Ctrl+U`, blocks right-click, and logs a console warning threat note. This is delivered entirely in client-side JavaScript.
- **Implication:** These are browser-side conveniences, not security controls — they do not prevent an attacker from reading the delivered HTML/JS or sending HTTP requests directly. Not a vulnerability; noted so the owner does not rely on them as a control.

**OA-9 — Hardcoded operational identifiers in public JS/HTML.**
- **Evidence:** Military unit name `KODAM-IV-Diponegoro` and geographic coordinates `-6.1754,106.8272` and `-7.8014,110.3647` (Jawa) are hardcoded in the served page; ESRI ArcGIS tile base (`server.arcgisonline.com`) is referenced.
- **Implication:** Low. These appear to be display/geographic data for a deception grid, not credentials. Included for completeness; no direct security impact identified.

**OA-10 — Third-party external origins.**
- **Evidence:** Remote asset origins: `fonts.googleapis.com`, `fonts.gstatic.com`, `server.arcgisonline.com` (map tiles).
- **Implication:** Low supply-chain/exfiltration surface to monitor. No evidence of misbehaviour.

---

## 9. Areas Requiring Further Authorized Testing (Phase 2+)

These are **not** tested in Phase 1 — they require explicit additional authorization, and several are explicitly destructive/operational:

1. **Authenticated session-cookie attributes** (`Secure`, `HttpOnly`, `SameSite`) — requires one authenticated request using the owner's token.
2. **Auth token model** — lockout/rate-limit behaviour, time-to-live, storage (`localStorage` vs cookie), and whether the shared token is rotated/revocable. *(Requires controlled, low-volume attempts.)*
3. **Authorisation boundaries on object IDs** — `/api/replay/{satuan}/{id}`, `/api/twinscreen/{satuan}`, `/api/report/{satuan}/{id}.*` — for IDOR/BOLA across `satuan`/`id` values. *(Requires authenticated read-only calls with test identifiers.)*
4. **Operational-control endpoints** — `/api/killswitch`, `/api/tactical/lockdown/*`, `/api/tactical/incidents/reset`, `/api/tactical/campaign/resolve`, `/api/autonomy`, `/api/simulate/*` — for authorization/CSRF/rate-limiting review. **Explicitly destructive/state-changing; must not be triggered absent written authorization and an agreed revert procedure.**
5. **WebSocket `/ws/live`** — message authentication, origin validation, and whether telemetry leaks unauthenticated. *(Requires authenticated WS session.)*
6. **CSP enforcement confirmation** — verify whether a CSP (with the observed nonce) is delivered on authenticated routes, and whether `report/*` HTML/`.docx`/STIX export routes inherit it.
7. **Stack confirmation** — pinned uvicorn/FastAPI version and dependency surface are out of scope for black-box; do **not** infer from source. (Any version disclosure would be observed passively only.)

---

## 10. Conclusion

Phase 1 produced a complete attack-surface inventory. The application presents a small, clearly bounded, and consistently authenticated surface, with a strong baseline of security headers and non-permissive CORS, fronted by Cloudflare. The most material open questions for the next phase centre on the single-token session model, authorization boundaries on user-visible object IDs, and the operational-control endpoints — none of which were touched here.

**No vulnerabilities are asserted in this report**; all entries are evidence-backed observations with potential implications, and every item needing further work is explicitly gated on additional authorization.

---

*Report produced under an independent authenticated black-box assessment authorized by the application owner. Read-only observations only; no destructive, operational, or exploitative action performed.*