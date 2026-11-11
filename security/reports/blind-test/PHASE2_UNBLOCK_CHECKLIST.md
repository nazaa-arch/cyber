# WAYANG — Blind Security Assessment · Phase 2: Unblock Checklist

**Target:** `https://cyber.steamcraft.online/`
**Purpose:** Preparation checklist for the authenticated/advanced Phase 2 tests that remain blocked. This document **plans** how tests can be unblocked — it does **not** execute any test, access the target, request credentials, or modify existing reports/source code.
**References:** `PHASE2_TEST_PLAN.md` · `PHASE2_EXECUTION_REPORT.md`
**Date:** 2026-11-09

---

## 0. Local Token/Session Provisioning (without printing or storing credentials)

The authenticated tests require a **temporary** admin session. This section defines how it may be provided locally while keeping the token out of reports, terminal output, and logs.

### 0.1 Recommended approach — reuse an already-logged-in profile

`agent-browser` can attach to a Chrome profile where the owner has already logged into WAYANG:

```
agent-browser cookies set --curl <file>        # import cookies from a curl-format file the owner saved
```
or
```
agent-browser --profile <path-to-chrome-profile> open https://cyber.steamcraft.online/
```

The owner logs in manually, out-of-band (not through chat). The token itself never enters the conversation. `agent-browser` reuses the resulting session cookie.

### 0.2 Alternative — disposable token via environment variable (one-shot)

Only if the owner prefers to hand off a *disposable* token:

```
# Owner runs locally (NOT pasted into chat):
$ echo -n "TOKEN" | agent-browser auth save wayang --url https://cyber.steamcraft.online/ --password-stdin
```

The value is consumed into the local auth vault and is **never** echoed into the conversation, terminal scrollback, or a report.

### 0.3 Hard rules for all provisioning paths

1. The token/cookie value is never written into a report, terminal output, script file, or log.
2. Evidence captured during testing must redact the cookie value (e.g., `session=<REDACTED>; HttpOnly; Secure`).
3. The session is treated as **temporary** and is closed (`agent-browser close`) at the end of the authenticated run.
4. No logout, revoke, or deactivation of a session is performed (see S-03/S-04).
5. The token is not requested via chat; provisioning is performed entirely out-of-band by the owner.

> **0.4 Status note (2026-11-09):** session `wayang-test` was authenticated via the owner's out-of-band token entered in-app. **S-01, S-02, and W-02 have now been executed** (see `PHASE2_EXECUTION_REPORT.md` §2A). Statuses below are updated accordingly.

---

## 1. Status Classification

| Status | Meaning |
|---|---|
| **READY** | Can execute now without further owner input. |
| **NEEDS OWNER APPROVAL** | Requires a specific authorization/acknowledgment or provisioning decision from the owner before execution. |
| **BLOCKED** | Must not execute until a named operational procedure is established; typically state-changing or destructive. |

---

## 2. Session Prerequisites (S-01, S-02, W-02)

### S-01 — Inspect session-cookie attributes

- **Prerequisite:** A temporary authenticated session (Section 0), or an already-logged-in profile.
- **Authorization gate:** Authenticated request with owner-supplied (not chat-relayed) session/token.
- **Safety:** Read-only observation of `Set-Cookie` header only; cookie value redacted in evidence.
- **Status:** **DONE (PASS)** — `wayang_token`: `HttpOnly`, `Secure`, `SameSite=Lax`, host-only, persistent (~15h). See `PHASE2_EXECUTION_REPORT.md` §2A.

### S-02 — Session lifecycle (authenticated)

- **Prerequisite:** Temporary authenticated session; passive observation of `/api/auth/status` before/after (no logout).
- **Authorization gate:** Authenticated session.
- **Safety:** Read-only; no session termination.
- **Status:** **DONE (PASS)** — `authed:true`; read surface returns `200`. See `PHASE2_EXECUTION_REPORT.md` §2A.

### W-02 — WebSocket Origin validation (authenticated)

- **Prerequisite:** Temporary authenticated session; perform one handshake with matching `Origin` and one with mismatching `Origin` (no crafted data frames).
- **Authorization gate:** Authenticated session; permission to issue exactly two benign upgrade attempts.
- **Safety:** Close the socket immediately upon handshake; no message frames.
- **Status:** **DONE (PARTIAL)** — authenticated handshake fails with abnormal close `1006` (no clean `101`), page falls back to polling; origin validation **unverifiable** until the WS is reachable. See `PHASE2_EXECUTION_REPORT.md` §2A.

---

## 3. Rate-Limit Probe (A-02)

- **Objective recap:** Determine whether `/api/auth/login` rate-limits or locks out, using the smallest defensible request count.
- **Prerequisite:** Owner explicit acknowledgment that observed failed-login attempts are acceptable for the security assessment.
- **Boundary (hard, non-negotiable):**
  - At most **5** failed `POST /api/auth/login` requests.
  - Spacing **≥ 2 s** between requests.
  - Only obviously-invalid token values (never the real token, never dictionary/guess attempts).
  - **Immediate stop** on any `429 Too Many Requests`, lockout message, `403`, IP ban signal, or any unexpected response — do not probe to exhaustion.
- **Evidence to collect (redacted):** per-request status code, `Retry-After`/`429` headers if present; no token values.
- **Risk of side effects:** Triggering monitoring/alerting (acceptable within the stated bound); potential to reach a lockout threshold is avoided by design.
- **Status:** **NEEDS OWNER APPROVAL** — requires the acknowledgment above.

---

## 4. IDOR/BOLA Resource Identifiers (Z-01)

- **Objective recap:** Determine whether resource IDs (`satuan`, `id`) are validated against the caller's authorization, using only explicitly authorized test resources.
- **Prerequisite (from owner):** A named test resource set:
  1. One or more **authorized own resources** (baseline — e.g., the owner's legitimate `satuan`/`id` values).
  2. One explicitly-designated **"other" test value** (a differing `satuan`/`id`) the owner authorizes us to request read-only, to observe whether it is rejected — **not** a real other-tenant value.
- **Authorization gate:** Owner supplies the test identifiers and confirms the differing resource is a deliberate test object.
- **Boundary:**
  - Read-only `GET` only.
  - Routes in scope: `/api/replay/{satuan}/{id}`, `/api/twinscreen/{satuan}`, `/api/report/{satuan}/{id}.html` (and only these — no writes).
  - Do **not** access or enumerate real other-user/other-tenant data.
- **Stop condition:** If a differing resource returns data (potential BOLA), stop immediately, record as a finding candidate, and do **not** enumerate further.
- **Status:** **BLOCKED** — until the owner provides the test identifier set.

---

## 5. Session-Termination & WebSocket-Frame Tests (S-03/S-04, W-01/W-03)

### S-03 — Logout behavior

- **Obstacle:** Logout terminates/deactivates the provided session; constraint 5 prohibits revoking the given session.
- **Approval needed:** Owner permission to either (a) open a **disposable second session** that may be logged out, or (b) explicitly authorize terminating a disposable test session.
- **Safety:** Perform only on the disposable session; confirm subsequent `GET /api/map` returns `401` and the cookie is cleared.
- **Status:** **NEEDS OWNER APPROVAL** (disposable session).

### S-04 — Session expiration

- **Obstacle:** Active forcing of expiration may require control over timeouts and repeated polling.
- **Approval needed:** Owner-confirmed acceptable to observe idle expiry on a disposable session (no forced polling against production).
- **Safety:** Passive observation only; no polling loops.
- **Status:** **NEEDS OWNER APPROVAL** (disposable session; passive).

### W-01 — WebSocket authentication validation (clone-auth)

- **Prerequisite:** Authenticated session; a single `wss://…/ws/live` upgrade.
- **Authorization gate:** Authenticated handshake permitted; observe first benign message type, then close.
- **Status:** **NEEDS OWNER APPROVAL** (authenticated session).

### W-03 — WebSocket message authorization / crafted frames

- **Obstacle:** Sending crafted/unauthorized WebSocket frames is explicitly out of scope for this assessment.
- **Approval needed:** A written, limited authorization with an agreed benign test-frame set and a revert/rollback procedure; even then, framed as a later phase.
- **Status:** **BLOCKED** (no crafted frames in this assessment).

---

## 6. Operational (State-Changing) Endpoints — Never Invoke Without Special Procedure

The following endpoints change system state and **must not be invoked** under any normal testing condition. Listed here for situational awareness only.

| Endpoint | Method | Nature | Current status |
|---|---|---|---|
| `/api/autonomy` | POST | Changes autonomy level | **BLOCKED** |
| `/api/simulate/{type}` | POST | Injects a simulation event | **BLOCKED** |
| `/api/decisions/…` | POST | Records a decision | **BLOCKED** |
| `/api/killswitch` | POST | Failsafe reset (L0) | **BLOCKED** |
| `/api/tactical/lockdown/{satuan}` | POST | Isolates OT interactions for a base | **BLOCKED** |
| `/api/tactical/campaign/resolve` | POST | Archives/neutralises a threat campaign | **BLOCKED** |
| `/api/tactical/incidents/reset` | POST | Resets incident display status | **BLOCKED** |

**Special-procedure requirements before any such endpoint could ever be considered (a separately authorized, non-default phase):**

1. Written owner authorization naming the exact endpoint and effect.
2. An agreed revert/rollback procedure.
3. A dedicated, disposable test environment or a confirm-before-execute gate.
4. Audit-log review capability to detect and clean up any test residue.
5. A designated emergency stop.

Until all five are satisfied, these endpoints remain **BLOCKED** and are never touched.

---

## 7. Consolidated Status Board

| Test | Status | Unblocks when |
|---|---|---|
| S-01 (auth cookie attrs) | **DONE (PASS)** | Executed — `wayang_token` `HttpOnly`/`Secure`/`SameSite=Lax`, host-only, ~15h |
| S-02 (auth lifecycle) | **DONE (PASS)** | Executed — `authed:true`, read surface all `200` |
| A-01 (login validation) | **READY** | Already executed (PASS) |
| A-02 (rate-limit probe) | **NEEDS OWNER APPROVAL** | Owner acknowledges ≤5 failed attempts acceptable |
| Z-01 (IDOR/BOLA) | **BLOCKED** | Owner provides test identifier set |
| Z-02 (unauth protection) | **READY** | Already executed (PASS) |
| W-01 (WS auth handshake) | **NEEDS OWNER APPROVAL** | Authenticated session |
| W-02 (WS origin) | **DONE (PARTIAL)** | Executed — authenticated WS closes `1006`; origin unverifiable |
| W-03 (WS crafted frames) | **BLOCKED** | Written limited authorization + benign test-frame set |
| C-01 / C-02 (CSP) | **READY** | Already executed (gap confirmed) |
| S-03 (logout) | **NEEDS OWNER APPROVAL** | Disposable second session authorized for logout |
| S-04 (expiry) | **NEEDS OWNER APPROVAL** | Disposable session + passive observation permitted |
| O-01 (endpoint inventory) | **READY** | Already documented (inventory only) |
| O-02…O-05 (operational) | **BLOCKED** | Special procedure (Sec. 6) |

---

*Checklist only — no target access, credential request, test execution, or modification of existing reports performed. No source code modified.*