# WAYANG — Blind Security Assessment · Phase 2: Execution Report

**Target:** `https://cyber.steamcraft.online/`
**Assessment type:** Independent authenticated black-box (token supplied by owner)
**Phase:** 2 — Authorized test execution (read-only / passive; no operational changes)
**Reference:** `security/reports/blind-test/PHASE2_TEST_PLAN.md`
**Date:** 2026-11-09
**Tooling:** `agent-browser` 0.39.2 (browser automation) + passive `curl` HTTP observation

---

## 0. Execution Constraints Honored

- **No token, cookie, session ID, or credential** was printed, stored, or requested. An owner-prepared browser session (`wayang-test`) was located but was **not authenticated** (see §2A), so the authenticated assertions remain BLOCKED. No credential was asked for or relayed through chat.
- **No logout / session termination / revocation** was performed.
- **No operational/state-changing endpoint** was invoked (`killswitch`, `lockdown`, `campaign/resolve`, `incidents/reset`, `autonomy`, `simulate`, `decisions`, and all other write/state routes).
- **No brute force, fuzzing, scanning, DoS, data extraction, crafted WebSocket frames, or IDOR testing against real resources.**
- Rate-limit probe **A-02** and IDOR **Z-01** were **not executed** — their preconditions remain unmet (owner acknowledgment + test identifier set, respectively).
- Browser session used an isolated worktree-scoped session (`wayang-p2-0da7e75ae27c`) and was closed after use.
- An owner-prepared session (`wayang-test`) was inspected for this authenticated run; it was found **not authenticated** (details in §2A).

---

## 1. Results Summary

| Test ID | Status | One-line result |
|---|---|---|
| S-01 · Cookie attributes | **PASS** | Authenticated via `wayang-test` (owner token entered in-app): one cookie `wayang_token` — `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, persistent (not session-only), expires 2026-11-10 04:04 WIB. Value redacted. |
| S-02 · Session lifecycle | **PASS** | `authed:true` after login; `.well-known`/protected reads all `200` (`/api/map`, `/campaigns`, `/decisions`, `/sessions`, `/heatmap`, `/autonomy`, `/bot`, `/recon`, `/personas`, `/map/vectors`, `/events/recent`, `/twinscreen/KODAM-IV-Diponegoro`). |
| A-01 · Login validation | **PASS** | Generic `401` for invalid/empty JSON; framework `422` echoes non-JSON input (minor fingerprint) |
| Z-02 · Unauth endpoint protection | **PASS** | All 15 read-only routes return `401` without authentication. |
| W-02 · WebSocket authentication/origin | **PARTIAL → FAIL (WS down)** | Authenticated: `wss://…/ws/live` handshake errors with close `1006` (abnormal), page live indicator stuck at "POLLING 2.5s" instead of "WSS 0ms". Origin handling not distinguishable because the socket never opens. |
| C-01 · CSP delivery | **PASS (observation)** | No CSP header and no CSP `<meta>`; nonce-bearing `<script>` present but inert. |
| C-02 · CSP enforcement evidence | **FAIL (gap confirmed)** | Only 1 of 3 required evidence items present → CSP is not actually enforced. |

---

### 2A. Authenticated run (2026-11-09) — session `wayang-test`

The owner provided the Komando token out-of-band and instructed login. The token was entered once into the application's own login form (via `agent-browser`) and is **not** reproduced in this report. After `POST /api/auth/login` (200), the session reached **`authed:true`** and was then tested read-only.

**S-01 — Session cookie attributes (PASS)**

- `agent-browser cookies --json` (values stripped server-side before display): exactly **one** cookie:
  - `name`: `wayang_token`
  - `httpOnly`: `true` · `secure`: `true` · `sameSite`: `Lax` · `path`: `/` · `domain`: `cyber.steamcraft.online`
  - `session`: `false` (persistent, not session cookie) · `size`: `55`
  - `expires`: epoch `1794258244` → **2026-11-10 04:04 WIB** (≈15 hours from issuance)
  - `value`: `<REDACTED>`
- **Observation:** The session cookie carries the correct hardening flags (`HttpOnly`, `Secure`, `SameSite=Lax`, narrow `Path`). It is **persistent** with a finite (~15h) lifetime rather than a browser-session cookie, and it is **host-only** (no `Domain` attribute → not shared to subdomains).
- **Risk level:** Low (good posture). `SameSite=Lax` is appropriate for a same-site SPA; `HttpOnly`/`Secure` prevent client-side theft by XSS and non-HTTPS transport.
- **Recommendation:** None required. Optionally set an explicit short absolute TTL aligned to an operational shift; 15h is already bounded.

**S-02 — Authenticated API / session status (PASS)**

- `GET /api/auth/status` → `200` `{"required":true,"authed":true}` (post-login).
- Authenticated read endpoints all returned `200` (bodies truncated/redacted):
  - `/api/map` → `200` (returns territorial node list, e.g. `{"satuan":"MABESAD-Siber", ...}` — the app's own data, not other-user data)
  - `/api/campaigns` → `200` `[]`
  - `/api/decisions`, `/api/sessions`, `/api/heatmap`, `/api/autonomy`, `/api/bot`, `/api/recon`, `/api/personas`, `/api/map/vectors`, `/api/events/recent`, `/api/twinscreen/KODAM-IV-Diponegoro` → `200`
- **Observation:** The client-side login gate (overlay) and the backend gate agree: unauthenticated → `401` (Z-02), authenticated → `200` across the read surface. No endpoint returned mixed/unexpected authorization.
- **Risk level:** None (behavior as designed and consistent).

**W-02 — WebSocket authentication / origin (PARTIAL → WS DOWN)**

- The front-end's live indicator read **"POLLING 2.5s"** (amber border) instead of **"WSS 0ms"**, i.e. the page's own WebSocket had fallen back to polling.
- A benign WebSocket opened from within the authenticated page to `wss://cyber.steamcraft.online/ws/live` (sending **no frames**) produced: `events: ["error","close:1006"]`, `code:1006`, `wasClean:false` — i.e. the connection failed with an **abnormal close**, not a clean `101` then auth rejection.
- No `/ws/live` entry appears in `network requests` (browser WS handshakes are not reported as Fetch requests), so the HTTP status of the upgrade could not be captured without a raw handshake.
- **Observation/interpretation:** The endpoint is **not currently reachable for a normal authenticated client** either. Whether this is (a) an intentional/available-only-in-some-path behavior, (b) a deployment/registration issue, or (c) a rejection that closes without a status frame, **cannot be distinguished** from this observation alone. Origin handling therefore remains **unverified** — no claim of an origin-validation weakness is made.
- **Risk level:** Informational/uncertain. If the WS is expected to be live, the 1006-abnormal-close (or the page falling back to polling) may indicate a realtime-layer problem; that is a functional/availability concern, not a demonstrated security vulnerability.
- **Recommendation:** Investigate why `/ws/live` closes abnormally for an authenticated client (e.g., missing `Origin`/subprotocol expectation, server-side error on upgrade); then, once a clean handshake is achievable, verify origin validation on authenticated connections.

**Evidence (sanitized):** cookie row above (value redacted); `{"required":true,"authed":true}`; per-endpoint `200` list; WS `{"events":["error","close:1006"],"code":1006,"wasClean":false}`.

---

## 2. Detailed Test Results

### S-01 — Session cookie attributes

- **Status:** PASS (authenticated) — see §2A for the authenticated result; unauthenticated evidence retained below.
- **Time:** unauthenticated ~08:30–08:45 WIB; authenticated 2026-11-09 (see §2A).
- **Procedure performed:**
  1. Unauthenticated `GET /` → observed response headers; recorded `Set-Cookie` presence.
  2. `POST /api/auth/login` with invalid token → observed response headers.
  3. Authenticated: read cookie metadata from `wayang-test` with the value redacted (§2A).
- **Observation (unauthenticated):**
  - `GET /` (200) → **no `Set-Cookie`** header.
  - `POST /api/auth/login` (401) → **no `Set-Cookie`** header.
  - Browser session had zero cookies before login.
- **Observation (authenticated, from §2A):** one cookie `wayang_token` — `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, host-only (no `Domain`), persistent with ~15h lifetime. Value redacted.
- **Evidence (sanitized):** unauthenticated header block shows no `set-cookie` line; authenticated cookie attribute row (value `<REDACTED>`).
- **Security implication:** Session cookie is only issued on successful login and carries correct hardening flags (`HttpOnly`, `Secure`, `SameSite=Lax`, narrow `Path`). Positively assessed.
- **Risk level:** Low (good posture).
- **Recommendation:** Maintain these flags. Optionally tighten to an explicit short absolute TTL (current ~15h is already bounded).
- **Further authorization needed:** None further for S-01.

### S-02 — Session lifecycle

- **Status:** PASS (unauthenticated + authenticated) — see §2A for the authenticated result; unauthenticated evidence retained below.
- **Time:** unauthenticated ~08:45 WIB; authenticated 2026-11-09 (see §2A).
- **Procedure performed:**
  1. `GET /api/auth/status` unauthenticated.
  2. Browser: loaded `/` and recorded the front-end's own network activity via `agent-browser network requests`.
  3. Authenticated: after login, observed `authed:true` and read-only `200` across the protected routes (§2A).
- **Observation (unauthenticated):**
  - `GET /api/auth/status` → `200` `{"required":true,"authed":false}`.
  - Front-end v1 network trace: after loading static assets, it issued exactly **one** API call — `GET /api/auth/status` (200) — then the UI entered the locked state (login overlay), and **no further API calls and no WebSocket connection** were attempted.
  - The login overlay text and the full control surface (buttons `[T1] Recon Scan`, `Lockdown Satuan`, `SAKLAR DARURAT L0`, etc.) render regardless, but none are operational until the status indicates `authed`.
- **Observation (authenticated, from §2A):** `authed:true`; all read endpoints (`/api/map`, `/api/campaigns`, `/api/decisions`, `/api/sessions`, `/api/heatmap`, `/api/autonomy`, `/api/bot`, `/api/recon`, `/api/personas`, `/api/map/vectors`, `/api/events/recent`, `/api/twinscreen/KODAM-IV-Diponegoro`) return `200`.
- **Evidence (sanitized):** `{"required":true,"authed":false}` → `{"required":true,"authed":true}`; per-endpoint `200` list.
- **Security implication:** Lifecycle gate is enforced client-side based on `/api/auth/status`, and the backend independently returns `401`/`200` (see Z-02 and §2A), so the client gate is a UX layer not a security control. The "open mode" branch (`required == false`) is not active for this deployment, which is the hardened configuration.
- **Risk level:** Low (good posture observed).
- **Recommendation:** Maintain `required:true`; ensure the backend — not the client — is the authoritative gate (already evidenced by Z-02 and §2A).
- **Further authorization needed:** None further for S-02 (S-03/S-04 logout/expiry remain BLOCKED as separate tests).

### A-01 — Login validation behavior

- **Status:** PASS.
- **Time:** 2026-11-09 ~08:50 WIB.
- **Procedure performed (3 minimal invalid inputs, no token guessing):**
  1. `POST /api/auth/login` JSON `{"token":"__invalid_probe__"}`.
  2. `POST /api/auth/login` JSON `{}` (empty).
  3. `POST /api/auth/login` with `Content-Type: text/plain`, body `x`.
- **Observation:**
  | Input | Status | Body |
  |---|---|---|
  | `{"token":"__invalid_probe__"}` | 401 | `{"detail":"Token salah"}` |
  | `{}` (empty JSON) | 401 | `{"detail":"Token salah"}` |
  | `text/plain` body `x` | **422** | `{"detail":[{"type":"dict_type","loc":["body"],"msg":"Input should be a valid dictionary","input":"x"}]}` |
- **Evidence (sanitized):** as above (no real token involved).
- **Security implication:** Invalid *and* missing token values both return the same generic `401 "Token salah"` — no user-validity oracle. The `422` on a non-JSON body is FastAPI/Pydantic's default validation response and leaks (a) framework identity (already known from the `uvicorn` header) and (b) echoes the raw input back in `"input"`. No secret material is disclosed; the input echo is standard framework behavior, rated informational.
- **Risk level:** Low / informational.
- **Recommendation:** Optionally suppress default `422` detail in production to avoid echoing attacker-supplied input and framework internals (defense-in-depth); the `401` path is already appropriately generic.
- **Further authorization needed:** None.

### Z-02 — Unauthenticated endpoint protection (regression)

- **Status:** PASS.
- **Time:** 2026-11-09 ~08:55 WIB.
- **Procedure performed:** Single unauthenticated `GET` against each Phase 1 read-only route.
- **Observation:** Uniform `401 application/json` for all:
  - `/api/map`, `/api/campaigns`, `/api/sessions`, `/api/heatmap`, `/api/autonomy`, `/api/bot`, `/api/recon`, `/api/personas`, `/api/events/recent`, `/api/map/vectors`, `/api/packets/recent`, `/api/tactical/rules/stix.json`, `/api/report/latest.docx`, `/api/twinscreen/KODAM-IV-Diponegoro`, `/api/replay/KODAM-IV-Diponegoro/1`.
- **Evidence:** per-route `status=401`.
- **Security implication:** The authenticated gate is consistently applied across the read-only API surface; no unauthenticated data resource was found. Consistent with Phase 1 and favorable.
- **Risk level:** None (control working as intended).
- **Recommendation:** None (baseline confirmed). Continue to enforce at backend for object-ID routes in later phases.
- **Further authorization needed:** None.

### W-02 — WebSocket authentication / origin validation

- **Status:** PARTIAL (PASS unauthenticated rejection; authenticated result FAIL-to-establish — see below).
- **Time:** 2026-11-09 ~09:00 WIB (unauthenticated) and authenticated (see §2A).
- **Procedure performed:**
  1. Unauthenticated `Upgrade: websocket` handshake to `/ws/live` with hostile `Origin: https://evil.example`. No frames sent.
  2. Authenticated: opened `wss://cyber.steamcraft.online/ws/live` from within the logged-in page and observed the lifecycle (no frames sent); also read the page's own live indicator and searched `network requests` for a WS entry.
- **Observation:**
  - Unauthenticated: `HTTP/1.1 401 Unauthorized` before any `Sec-WebSocket-*` response header.
  - Authenticated: `events: ["error","close:1006"]`, `code:1006`, `wasClean:false` — connection failed with an **abnormal close**, not a clean `101` + graceful auth rejection.
  - Page's own live indicator showed **"POLLING 2.5s"** (amber border), i.e. the app's WebSocket was in its polling fallback, **not** "WSS 0ms".
- **Evidence:** unauthenticated `401`; authenticated `{"events":["error","close:1006"],"code":1006,"wasClean":false}`.
- **Security implication:** The endpoint rejects unauthenticated upgrades, but for authenticated clients it **does not complete a normal handshake** (abnormal close 1006), so origin-handling behavior **cannot be determined** from this observation. This is recorded as an availability/realtime-layer anomaly, **not** a confirmed origin-validation weakness.
- **Risk level:** Informational/uncertain (WS realtime layer appears degraded; origin validation unverified).
- **Recommendation:** Investigate why `/ws/live` closes abnormally for an authenticated client (missing subprotocol/`Origin` expectation, or server-side error on upgrade). Once a clean handshake is achievable, verify origin validation on authenticated connections.
- **Further authorization needed:** A separate authorized phase with a clean WS handshake to A/B-match `Origin`.

### WebSocket Follow-up Investigation (`/ws/live`, read-only)

**Scope:** Two normal (non-crafted) `WebSocket` connection observations from within the authenticated `wayang-test` session, ≥5 s apart. No frames, no flooding, no config/state change, no re-login, no credential exposure.

**Observations**

| Aspect | Attempt 1 | Attempt 2 |
|---|---|---|
| URL / scheme | `wss://cyber.steamcraft.online/ws/live` | same |
| ReadyState at construction | `0` (CONNECTING) | `0` (CONNECTING) |
| ReadyState progression | — | Sampled every 500 ms: stayed `0` for the full 6 s window |
| Events | `error`, `close` at ~5.5 s (timeout boundary) | `error`, `close` at ~6.0 s (timeout boundary) |
| Close code | `1006` (abnormal) | `1006` (abnormal) |
| `wasClean` | `false` | `false` |
| `reason` | empty | empty |

**Additional evidence**

- Browser console: only the app's warning banner is present; **no WebSocket/network error** is logged by the application (silent failure).
- Front-end live indicator: **"POLLING 2.5s"** (amber) — the application's WebSocket is **not** reaching its "WSS 0ms" open state.
- Network log: the polling fallback is actively and repeatedly fetching (`/api/map`, `/api/map/vectors`, etc.), while **no `/ws/live` upgrade entry** appears.

**Analysis (failure location)**

1. **The socket never leaves `CONNECTING`.** It does **not** return an early HTTP `401`/`403` (unauthenticated attempts *do* get a fast `401`, from the prior flat-HTTP probe) — the authenticated attempt instead **hangs** until the browser/client gives up with `1006`.
2. Because `101 Switching Protocols` is never received and no rejection status is observed, the failure is **at or after the upgrade/handshake**, not an application-level clean auth rejection.
3. Candidate causes, in rough likelihood order: (a) a **reverse proxy / load balancer** (Cloudflare/Render) failing to pass or complete the WebSocket upgrade; (b) a **backend** that accepts the TCP/TLS but does not complete the WS handshake; (c) a **routing/path** mismatch for `/ws/live`; (d) a **TLS/SNI** edge issue (unlikely — normal HTTPS works). **No evidence implicates token authentication:** the cookie is valid and every authenticated HTTP API call succeeds.
4. This is consistent with the front-end falling back to polling, so the application degrades gracefully.

**Conclusion:** The exact cause **cannot be isolated through read-only observation**; the signature (hang in `CONNECTING` → abnormal `1006`) is a strong indicator of a proxy/backend handshake-routing problem rather than an authz issue. **This is recorded as an availability/realtime-layer anomaly, not a vulnerability.** No security weakness is claimed.

**Recommendation:** Owner-side configuration check of the WebSocket upgrade path — verify proxy (Cloudflare "WebSockets" support / Render service WebSocket enablement), that `/ws/live` is routed to a WS-capable handler, and any timeout/upgrade-header stripping at the edge. Once a clean `101` is achievable, re-test origin validation (W-02) and consulting W-01.

---

### C-01 — CSP delivery (header / meta / nonce)

- **Status:** PASS (observation confirmed).
- **Time:** 2026-11-09 ~09:05 WIB.
- **Procedure performed:** Fetch `/` and inspect for a CSP header and a CSP `<meta>`, and for the nonce on the inline script.
- **Observation:**
  - **No `Content-Security-Policy` response header** on `/` (only `cross-origin-opener-policy`, `permissions-policy`, `referrer-policy`, etc. — none is a CSP).
  - **No CSP `<meta http-equiv>`** in the HTML.
  - An inline `<script nonce="...">` **is** present.
- **Evidence (sanitized):** header block lacks any `content-security-policy`; `grep` for `<meta ... content-security ...>` returns nothing; `grep` for `<script[^>]*nonce=` matches one inline script (nonce value redacted).
- **Security implication:** A nonce attribute is meaningless without a CSP that grants script execution via that nonce. As served, the nonce is **inert** and CSP is not providing any script-src default-src protection.
- **Risk level:** Medium (defense-in-depth gap; XSS impact would be higher than with a restrictive CSP — no confirmed XSS is claimed).
- **Recommendation:** Deliver a `Content-Security-Policy` header (ideally `script-src 'nonce-<per-request>' 'strict-dynamic'; object-src 'none'; base-uri 'none'; …`) that actually references the nonce, and confirm the nonce is unique per response. This closes the gap whose intent is already signalled by the in-code comment `/* CSP nonce ... */`.
- **Further authorization needed:** To check whether CSP is delivered on *authenticated* routes (the observed route is the public root). Considered deferred.

### C-02 — CSP enforcement evidence assessment

- **Status:** FAIL (gap confirmed — 1 of 3 required evidence items present).
- **Time:** 2026-11-09 ~09:05 WIB.
- **Analysis (no execution of injection):** The three evidence items required to prove *enforcement* are: (1) a `Content-Security-Policy` header/`<meta>` referencing a nonce/hash, (2) the inline script carrying the matching nonce, (3) a demonstrable block of non-allowlisted script. Observed state: only (2) is true; (1) and (3) are absent, therefore CSP is **not** enforcing today.
- **Evidence (sanitized):** cross-references C-01 findings above.
- **Security implication:** Confirmed as a gap in the delivered configuration (the server-side mechanism to emit the nonce exists; the policy declaration does not). This is an observation, not a "vulnerable-to-XSS" claim — no injection was attempted or observed.
- **Risk level:** Medium.
- **Recommendation:** Same as C-01 — emit the policy; then re-verify (1)+(2)+(3) jointly.
- **Further authorization needed:** Authenticated-route verification, deferred.

---

## 3. Not Executed (explicitly deferred / blocked)

- **A-02 (rate-limit probe):** Not executed — no owner acknowledgment recorded, and the hard ≤5 cap rule requires it. **BLOCKED.**
- **Z-01 (IDOR/BOLA):** Not executed — no owner-provided test identifier set. **BLOCKED.**
- **S-03 (logout), S-04 (expiry forcing):** Not executed — would terminate/observe the provided session; constraints forbid logout. **BLOCKED.**
- **A-03 (bypass), A-04 (client persistence runtime), Z-03 (method tamper), W-01 (auth handshake), W-03 (crafted WS frames), O-02…O-05 (operational):** Not executed — require authenticated session and/or would change state / send crafted payloads. **BLOCKED.**

---

## 4. Findings Register

**No vulnerability is claimed to be confirmed.** Two observations warrant tracking:

| ID | Severity | Type | Status |
|---|---|---|---|
| F1 | Medium | Missing Content-Security-Policy (nonce served but no enforcing policy) | Confirmed gap/observation — not an exploited finding |
| F2 | Low/Info | FastAPI/Pydantic `422` echoes framework type + raw input on malformed body | Informational fingerprint |

Both are defense-in-depth observations consistent with Phase 1; neither constitutes demonstrated impact such as XSS, data disclosure, or unauthorized access.

---

## 5. Conclusion

The unauthenticated tests were completed cleanly, and — following the owner's out-of-band token + in-app login — the authenticated tests were then executed against session `wayang-test`. Results:

- **S-01 PASS:** session cookie `wayang_token` is `HttpOnly`, `Secure`, `SameSite=Lax`, host-only, persistent (~15h). Hardening posture is correct.
- **S-02 PASS:** `authed:true`; the authenticated read surface returns `200` consistently, and the client/backend auth gates agree.
- **W-02 PARTIAL:** unauthenticated upgrades are rejected `401`, but the authenticated `/ws/live` closes **abnormally (1006)** and the app falls back to polling — so origin validation remains unverifiable and the realtime layer appears degraded.

The one confirmed gap from earlier stands: **CSP is declared by code intent (nonce emitted) but not delivered as an enforcing policy.** No token, cookie value, or session secret was stored or printed; the cookie value was redacted in all evidence.

*Execution was read-only/passive. No operational, state-changing, or destructive action was performed; no logout, IDOR, brute force, or crafted WebSocket frames were attempted.*
