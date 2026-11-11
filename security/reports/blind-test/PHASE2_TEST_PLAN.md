# WAYANG — Blind Security Assessment · Phase 2: Test Plan

**Target:** `https://cyber.steamcraft.online/`
**Assessment type:** Independent authenticated black-box (token supplied by owner)
**Phase:** 2 — Test Plan (NO EXECUTION — this document plans tests only)
**Reference:** `security/reports/blind-test/PHASE1_ATTACK_SURFACE.md`
**Date:** 2026-11-09

---

## 0. Binding Constraints (applies to every test case)

1. **Production environment.** No destructive testing, no denial-of-service, no fuzzing, no exploit payloads, no lockout exhaustion, no brute force.
2. **No operational state changes.** State-changing endpoints are inventoried but never invoked.
3. **No data extraction / enumeration** beyond the explicitly authorized read-only test resources.
4. **Token handling:** the administrator token is never stored on disk, printed to screen, written into report artifacts, scripts, or logs. When a test requires an authenticated request, the token is supplied to the test tool through a one-shot environment variable or by pasting into the application's own login form, then discarded. Any evidence captured must redact the token value.
5. **Do not log out, revoke, or deactivate the provided session.** Logout is therefore planned only as a passive/observational item and marked **BLOCKED**.
6. **Session-attribution:** all authenticated results are recorded as authenticated observations, never "anonymous unauthorized".
7. **Stop conditions are per-test and mandatory.** Any test that observes a lockout, rate-limit (`429`), IP ban, or unexpected state change stops immediately and does not resume without owner authorization.
8. **BLOCKED** marks a test that requires additional explicit authorization before execution, regardless of whether the token itself is already in hand.

---

## Test ID Convention

- `S-xx` — Session security
- `A-xx` — Authentication
- `Z-xx` — Authorization
- `W-xx` — WebSocket
- `C-xx` — CSP / headers
- `O-xx` — Operational API (inventory & access-control review only)

---

# OBJECTIVE 1 — Session Security

### S-01 · Inspect session-cookie attributes

- **Test ID:** S-01
- **Objective:** Determine the `Secure`, `HttpOnly`, `SameSite`, `Path`, and `Domain` attributes of the session cookie set on successful authentication, and whether the cookie is set at login or by middleware on every response.
- **Preconditions:** No active session of concern; target reachable. Access to one authenticated request using the owner-provided token.
- **Required authorization:** Token already authorized. **Execution requires authenticated request** — otherwise proceed with unauthenticated observation only.
- **Safe test procedure:**
  1. Issue a single valid `POST /api/auth/login` with the owner's token via the normal front-end flow or a one-shot request, capturing **response headers only** (`Set-Cookie`).
  2. Record the attribute flags; do **not** record the cookie value.
  3. Make one `GET /api/map` (authenticated) and inspect whether the session cookie is re-sent and echoed in `Set-Cookie`.
  4. Do **not** persist the cookie value to disk.
- **Expected result:** A session cookie with `HttpOnly` (expected), `Secure` (expected, given HSTS), `SameSite=Lax` or `Strict` (expected), and a narrow `Path`.
- **Evidence to collect:** Redacted `Set-Cookie` header line with value masked (e.g., `session=<REDACTED>; HttpOnly; Secure; SameSite=Lax; Path=/`).
- **Risk of side effects:** Negligible — read-only except for login itself.
- **Stop condition:** If login fails or any unexpected redirect/state change occurs, stop and revert to unauthenticated observation.

### S-02 · Review session lifecycle via `/api/auth/status`

- **Test ID:** S-02
- **Objective:** Confirm how session state is represented before, during, and (passively) after authentication, without logging out.
- **Preconditions:** Target reachable.
- **Required authorization:** None for the unauthenticated read (`{"required":true,"authed":false}` already observed). Authenticated observation requires the token.
- **Safe test procedure:**
  1. `GET /api/auth/status` unauthenticated → record.
  2. (Optional, token-permitted) `GET /api/auth/status` authenticated → record.
  3. Observe whether `required`/`authed` reflect session presence and whether any session identifier leaks into the response body.
- **Expected result:** Unauthenticated returns `required:true, authed:false`; authenticated returns `authed:true` with no secret material in the body.
- **Evidence to collect:** Raw JSON bodies (they contain no secrets by design).
- **Risk of side effects:** None.
- **Stop condition:** If the response ever includes token/session material, stop and record as a finding candidate only.

### S-03 · Review logout behavior

- **Test ID:** S-03
- **Objective:** Determine whether logout invalidates the server-side session and clears the cookie, **without actually terminating the provided session**.
- **Preconditions:** An active authenticated session (owner's).
- **Required authorization:** **BLOCKED** — logging out deactivates the authenticated session, which the assessment must not do (see Constraint 5). Requires explicit owner permission to open a disposable second session or to permit session termination.
- **Safe test procedure (if unblocked, on a disposable session only):** `POST /api/auth/logout`, then confirm a follow-up `GET /api/map` returns `401` and the cookie is cleared.
- **Expected result:** Subsequent authenticated endpoint returns `401`; cookie cleared/expired.
- **Evidence to collect:** Status codes and `Set-Cookie` (value redacted) before/after.
- **Risk of side effects:** Terminates session (hence BLOCKED).
- **Stop condition:** Not applicable while BLOCKED.

### S-04 · Session expiration behavior

- **Test ID:** S-04
- **Objective:** Establish whether sessions expire (idle/absolute) and, if so, the approximate window, by passive observation only.
- **Preconditions:** Authenticated session; long observation window.
- **Required authorization:** **BLOCKED for active testing.** Passive observation (token permitted) can note idle/logged transitions if they occur naturally during the engagement.
- **Safe test procedure:** Do not force expiration. Record `authed` transitions only if the status endpoint spontaneously changes. No polling loops against production.
- **Expected result:** A documented expiry hint (e.g., `max-age` on the cookie, or a server-side absolute timeout) — or no expiry observed.
- **Evidence to collect:** Observed status transitions with timestamps (token redacted).
- **Risk of side effects:** None (passive).
- **Stop condition:** No active forcing; observation only.

---

# OBJECTIVE 2 — Authentication

### A-01 · Login validation behavior (invalid input only)

- **Test ID:** A-01
- **Objective:** Characterize the response to malformed/invalid credentials without attempting to guess the real token.
- **Preconditions:** Target reachable; no valid token required.
- **Required authorization:** Token not required — all requests are intentionally invalid.
- **Safe test procedure (minimal):**
  1. `POST /api/auth/login` with an obviously invalid value (already observed: `{"detail":"Token salah"}`).
  2. One request with an empty body `{}` → record status/body.
  3. One request with non-JSON content → record status/body.
  4. No dictionary words, no token enumeration, no oracle probing.
- **Expected result:** Consistent `401` with a generic JSON `detail`; no stack traces; no distinction that leaks whether a value is close to valid.
- **Evidence to collect:** HTTP status + body for each of the three minimal inputs.
- **Risk of side effects:** None (three malformed requests total).
- **Stop condition:** If any input yields a non-`401`/non-generic response (e.g., a stack trace or timing oracle), stop and record as a finding candidate.

### A-02 · Rate-limit / lockout behavior (safe minimal probe)

- **Test ID:** A-02
- **Objective:** Determine whether the login endpoint applies rate limiting or lockout, using the smallest defensible request count.
- **Preconditions:** Target reachable; documented/apparent rate-limit behavior unknown.
- **Required authorization:** Token not required. **Requires owner acknowledgment** that a small number of failed logins is acceptable; otherwise **BLOCKED**.
- **Safe test procedure (bounded):**
  1. Perform **at most 5** failed `POST /api/auth/login` attempts, spaced ≥2 s apart, against the non-valid-token path only.
  2. Observe whether a `429 Too Many Requests`, an HTTP `403`, or a lockout message appears.
  3. **Never** continue past 5 requests; **never** attempt to reach or confirm a lockout threshold.
- **Expected result:** Either a rate-limit signal appears within 5 attempts, or behavior is unchanged (indicating a higher/no limit, which is then reported as an observation, not tested further).
- **Evidence to collect:** Per-request status code and any `Retry-After`/`429` header (body redacted if it echoes input).
- **Risk of side effects:** Low, but potential for trigger auditing/alerts — hence the ≤5 bound and explicit acknowledgment requirement.
- **Stop condition:** HARD STOP at 5 requests, or immediately upon any `429`/lockout/ban signal. Do not probe to exhaustion.

### A-03 · Auth-bypass / transport manipulation

- **Test ID:** A-03
- **Objective:** Determine whether session/auth can be transported via alternate vectors (headers, query string) and whether CORS/method tuning changes access.
- **Preconditions:** Target reachable.
- **Required authorization:** **BLOCKED** for any bypass attempt. Passive method/header observation is permitted.
- **Safe test procedure (passive only):** Confirm the `OPTIONS` preflight result (`405`, `allow: POST`) and absence of `Access-Control-Allow-Origin`; note that `401` is returned consistently regardless of method framing.
- **Expected result:** No CORS trust; auth remains cookie/JSON-bound.
- **Evidence to collect:** Header lines only.
- **Risk of side effects:** None.
- **Stop condition:** No active bypass attempts.

### A-04 · Token transport / storage observation

- **Test ID:** A-04
- **Objective:** Observe whether the front-end persists the token client-side (localStorage/sessionStorage) after login, without executing a harmful payload.
- **Preconditions:** Access to the served SPA (already public).
- **Required authorization:** Static code observation of public content only — permitted. Runtime observation requires an authenticated browser session.
- **Safe test procedure:** Inspect the publicly served `doLogin`/`doLogout` logic (already reviewed in Phase 1) for any client-side token persistence. Do **not** extract or replay a real token.
- **Expected result:** Token is sent only in the JSON body and never written to `localStorage`/`sessionStorage` (Phase 1 evidence suggests a server-side cookie is used instead).
- **Evidence to collect:** Reference to the relevant client-side function; no secret data.
- **Risk of side effects:** None.
- **Stop condition:** If client-side token persistence is found, record and stop (no further tampering).

---

# OBJECTIVE 3 — Authorization

### Z-01 · Access boundary on object identifiers (IDOR/BOLA)

- **Test ID:** Z-01
- **Objective:** Determine whether resource identifiers (`satuan`, `id`) are validated against the caller's authorization, using only explicitly authorized test resources.
- **Preconditions:** An authenticated session and an **explicitly authorized list of test `satuan`/`id` values** from the owner (e.g., the known-good own values and one explicitly-designated "other" test value).
- **Required authorization:** **BLOCKED** until the owner explicitly authorizes specific test resource identifiers. The single shared token means there may be no true cross-tenant boundary; testing is deferred rather than assumed.
- **Safe test procedure (if unblocked):** `GET` the read-only routes from Phase 1 (`/api/replay/{satuan}/{id}`, `/api/twinscreen/{satuan}`, `/api/report/{satuan}/{id}.html`) using (a) the authorized own resource (baseline) and (b) the explicitly authorized differing resource; diff responses.
- **Expected result:** Differing `satuan`/`id` outside the authorized set are rejected (`401/403`) or return only authorized data.
- **Evidence to collect:** Status codes and response shapes; no private content is retained in the report.
- **Risk of side effects:** None (read-only).
- **Stop condition:** If a differing resource returns other-tenant data, stop and record as a finding candidate; do not enumerate further.

### Z-02 · Unauthenticated access confirmation

- **Test ID:** Z-02
- **Objective:** Re-confirm that all Phase 1 inventory routes reject unauthenticated access (baseline regression).
- **Preconditions:** Target reachable.
- **Required authorization:** None.
- **Safe test procedure:** Single unauthenticated `GET` against the read-only route set; record `401`.
- **Expected result:** Uniform `401` as documented in Phase 1.
- **Evidence to collect:** Status codes only.
- **Risk of side effects:** None.
- **Stop condition:** n/a (single request per route).

### Z-03 · Method / version framing of authorized resources

- **Test ID:** Z-03
- **Objective:** Confirm that changing HTTP method does not alter authorization framing for read-only resources.
- **Preconditions:** Target reachable.
- **Required authorization:** **BLOCKED** for any authenticated method-tampering; unauthenticated method observation only.
- **Safe test procedure:** Observe `OPTIONS` and (if neutral) `HEAD` on one read-only endpoint; expect rejection without auth.
- **Expected result:** Non-permissive; no exposure.
- **Evidence to collect:** Status codes.
- **Risk of side effects:** None.
- **Stop condition:** No write-method testing.

---

# OBJECTIVE 4 — WebSocket

### W-01 · WebSocket authentication validation

- **Test ID:** W-01
- **Objective:** Confirm `/ws/live` requires an authenticated session (already `401` unauthenticated) and opens with a valid session.
- **Preconditions:** Authenticated session (owner's token).
- **Required authorization:** Token already authorized; a single authenticated handshake is permitted.
- **Safe test procedure:** Perform one `wss://…/ws/live` upgrade with the authenticated session; observe the handshake result; close immediately on receipt of the first benign `telemetry_tick`/connection message. Do not transmit crafted frames.
- **Expected result:** `101 Switching Protocols` with valid session; `401` without.
- **Evidence to collect:** Handshake status and first benign message type (payload redacted).
- **Risk of side effects:** Negligible (read-only stream).
- **Stop condition:** Immediately close on any unexpected/unsolicited data.

### W-02 · WebSocket origin validation

- **Test ID:** W-02
- **Objective:** Determine whether the server validates the `Origin`/`Sec-WebSocket-Protocol` on the upgrade.
- **Preconditions:** Target reachable.
- **Required authorization:** None needed for a passive failed-handshake check using an arbitrary `Origin`.
- **Safe test procedure:** Issue a single unauthenticated upgrade with a clearly non-matching `Origin` (`https://evil.example`); observe whether it is rejected (`401`/`403`) or proceeds to another auth check.
- **Expected result:** Rejected before app logic.
- **Evidence to collect:** Handshake status code.
- **Risk of side effects:** None.
- **Stop condition:** One request; no payload transmission.

### W-03 · WebSocket message authorization / crafted frames

- **Test ID:** W-03
- **Objective:** Plan (not execute) evaluation of message-level authorization (e.g., injection of `event`/`telemetry_tick`/decision frames once connected).
- **Preconditions:** Authenticated WS session.
- **Required authorization:** **BLOCKED** — sending unauthorized or crafted messages is explicitly out of scope for this assessment.
- **Safe test procedure:** Not executed. Documented for a possible later authorized phase with an agreed benign test frame set.
- **Expected result:** n/a (planned only).
- **Evidence to collect:** n/a.
- **Risk of side effects:** State-changing if ever executed (hence BLOCKED).
- **Stop condition:** n/a.

---

# OBJECTIVE 5 — CSP

### C-01 · Confirm CSP delivery on authenticated vs unauthenticated routes

- **Test ID:** C-01
- **Objective:** Confirm the Phase 1 observation (nonce served, no CSP header) holds across routes and, if any route does serve a CSP, capture what it grants.
- **Preconditions:** Target reachable; authenticated access for non-public routes.
- **Required authorization:** Unauthenticated routes require none; authenticated routes require the token. **Actual confirmation of authenticated-route CSP is BLOCKED** pending a token-permitted authenticated page fetch; the unauthenticated route check is permitted now.
- **Safe test procedure:** Re-request `/` and record the presence/absence of `Content-Security-Policy`; note the observed inline nonce. Do not alter any response.
- **Expected result:** No `Content-Security-Policy` header and no CSP `<meta>`, matching Phase 1 (OA-6).
- **Evidence to collect:** Header block and the nonce-bearing `<script>` tag (nonce value may be redacted in the report; its mere presence is the evidence).
- **Risk of side effects:** None.
- **Stop condition:** n/a.

### C-02 · Determine evidence required to confirm policy enforcement

- **Test ID:** C-02
- **Objective:** Define (not execute) what minimal evidence would prove CSP is actually enforcing script allow-listing end-to-end.
- **Preconditions:** n/a (analysis).
- **Required authorization:** n/a.
- **Safe test procedure:** Identify the three required pieces of evidence: (1) a `Content-Security-Policy` header/`<meta>` that references `'nonce-…'` or hashes; (2) the served inline `<script>` carrying a matching nonce; (3) a demonstrable case where a non-nonce inline script or disallowed origin is blocked. Confirm none are yet satisfied.
- **Expected result:** Currently only (2) is present; (1) and (3) are absent — so CSP is not enforcing today. This is a documentation/observation, not a triggered test.
- **Evidence to collect:** The prior header and HTML references.
- **Risk of side effects:** None.
- **Stop condition:** No active inline-injection test (that would be a fuzz/exploit step and is out of scope).

---

# OBJECTIVE 6 — Operational API (Inventory & Access-Control Review Only)

> These endpoints change state and **must never be invoked** during this assessment. The purpose of this section is solely to inventory them and articulate the access-control properties that should be verified in a future, explicitly authorized phase.

### O-01 · Operational endpoint inventory

- **Test ID:** O-01
- **Objective:** Enumerate all state-changing endpoints identified in Phase 1.
- **Preconditions:** n/a.
- **Required authorization:** n/a (inventory only).
- **Safe test procedure:** Static cross-reference of the Phase 1 route list.
- **Expected result:** Confirmed inventory:

  | Endpoint | Method | Nature |
  |---|---|---|
  | `/api/autonomy` | POST | Changes autonomy level |
  | `/api/simulate/{type}` | POST | Injects a simulation event |
  | `/api/decisions/…` | POST | Records a decision |
  | `/api/killswitch` | POST | Failsafe reset (L0) |
  | `/api/tactical/lockdown/{satuan}` | POST | Isolates OT interactions for a base |
  | `/api/tactical/campaign/resolve` | POST | Archives/neutralises a threat campaign |
  | `/api/tactical/incidents/reset` | POST | Resets incident display status |

- **Evidence to collect:** The route list with source reference.
- **Risk of side effects:** None (inventory only).
- **Stop condition:** No invocation.

### O-02 through O-05 · Access-control requirements (no execution)

Each records, for a specific control surface, the access-control requirements to verify later, and is **BLOCKED** for any direct testing.

- **O-02 · `/api/killswitch`** — **BLOCKED.** Requires: authenticated-only access; confirmation gate; audit logging; idempotency; rate-limit. Never invoked.
- **O-03 · `/api/tactical/lockdown/{satuan}`** — **BLOCKED.** Requires: per-`satuan` authorization, confirmation, reversible effect, audit. Never invoked.
- **O-04 · `/api/tactical/incidents/reset` + `/api/tactical/campaign/resolve`** — **BLOCKED.** Requires: confirmation (the client already prompts), audit/integrity (forensic evidence must be preserved — the client states it is not deleted), reboot-safe idempotency. Never invoked.
- **O-05 · `/api/autonomy` + `/api/simulate/{type}` + `/api/decisions/…`** — **BLOCKED for direct writes.** Requires: authenticated writes only; input validation; no cross-`satuan` side effects. Passive review only.

For each: **Expected result** (documented, not measured), **Evidence** = the client-side confirmation/audit wording already observed, **Risk** = state-changing, **Stop condition** = no execution.

---

## 7. Summary of Blocked vs. Permitted

| Test | Status | Reason |
|---|---|---|
| S-01, S-02, A-01, Z-02, W-02, C-01, C-02 | Permitted (token use limited to necessary authenticated reads) | Read-only / passive |
| A-02 | Permitted with owner acknowledgment, hard ≤5 cap | Minimal rate-limit observation |
| S-03 (logout), S-04 (expiry forcing), A-03 (bypass), Z-01 (IDOR), Z-03 (method tamper), W-01 (clone-auth only), W-03 (crafted WS), O-02…O-05 | **BLOCKED** | Require additional authorization and/or would change state |

**Verification of a state-changing endpoint's behavior is deferred entirely to a later, explicitly authorized phase with an agreed revert procedure.**

---

*Plan only — no tests executed in this phase. Token never stored or printed. Destructive, DoS, fuzzing, data-extraction, and operational state-change actions are all prohibited and are not planned.*