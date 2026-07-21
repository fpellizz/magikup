# Functional Specification — Password Recovery via Email

**Feature:** Self-service password reset ("Forgot password?")
**Product:** MagikUp v4.2.0
**Status:** Draft for review
**Author:** Spec authoring pass (codebase-mapped)
**Date:** 2026-07-21

---

> **HARD PREREQUISITE.** This feature cannot ship without an outbound email
> capability. MagikUp today has **no SMTP/email code anywhere** (`itsdangerous`
> is the only signing/token lib; `broadcaster.py` is WebSocket pub/sub,
> unrelated). Password recovery **depends on** the companion *Email Sending*
> spec, which introduces:
> - a Fernet-encrypted `[smtp]` config section (host, port, username,
>   `ENC:password`, TLS mode, from-address),
> - an async send helper (stdlib `smtplib` in a threadpool, or `aiosmtplib`),
> - new egress (SMTP submission port, typically 587/465).
>
> Everything below assumes that `send_email(to, subject, html, text)` helper
> and `[smtp]` config already exist and are covered by that spec. Where this
> spec touches email plumbing, it references it — it does not re-specify it.

---

## 1. Purpose & User Stories

### Purpose
Let a user who has forgotten their password recover access without an admin
manually editing `users.json` or running a CLI reset. The flow is
email-based, token-gated, single-use, expiring, and audited — matching the
existing bcrypt/lockout/audit security posture of `app/auth.py`.

### User stories
- **US-1 — Forgotten password (happy path).** As an operator who forgot my
  password, I click "Forgot password?" on the login page, enter my username or
  email, receive an email with a reset link, open it, set a new policy-valid
  password, and can immediately log in.
- **US-2 — Locked-out user self-recovery.** As a user whose account was locked
  by `ACCOUNT_LOCKOUT_THRESHOLD` (10) failed attempts, completing a valid reset
  clears `failed_attempts` and `locked`, restoring access without an admin.
- **US-3 — Admin sets emails.** As an admin, I set/edit each user's email
  address in Admin → Users so reset emails can be delivered.
- **US-4 — No-enumeration privacy.** As any visitor (including an attacker), I
  always see the same generic "if an account exists, an email has been sent"
  message regardless of whether the username/email exists.
- **US-5 — No-email fallback.** As the bootstrap admin (or any user without an
  email set), self-service reset is unavailable by design; the documented
  manual fallback (edit `users.json` / CLI reset) remains the recovery path.
- **US-6 — Auditability.** As a security reviewer, every reset request, email
  send, token use, success, and failure appears in `audit.log`.

---

## 2. Scope

### In scope
- "Forgot password?" link on `templates/login.html`.
- New request page (enter username or email).
- Signed, expiring, single-use reset token built on `itsdangerous`
  `URLSafeTimedSerializer` (already present; **no new dependency**).
- New reset page enforcing the existing `validate_password` policy.
- Updating `password_hash`, clearing `failed_attempts`/`locked` in
  `users.json` on success.
- Adding an `email` field to the `User` dataclass and `users.json` (backward
  compatible, no migration).
- Admin → Users UI to view/set/edit email.
- No-enumeration behavior, rate limiting, token invalidation/single-use
  tracking, audit logging.
- Documented manual fallback for users without email (esp. bootstrap admin).

### Out of scope
- The SMTP/email-sending subsystem itself (companion spec — hard prerequisite).
- Email address *verification* / confirmation flow (double opt-in). Emails are
  set by admins and trusted; see Open Questions.
- Multi-factor authentication, "magic link" login (this is reset only).
- Password history / reuse prevention beyond the existing policy.
- SSO / external IdP integration.
- Notifying users by email of admin-initiated password resets (nice-to-have,
  Open Questions).

---

## 3. UX / UI

All new pages match MagikUp's design system: single violet accent
(`#7c3aed` light / `#8b5cf6` dark), `.app-main` shell where applicable, flat
`.card` surfaces, `.btn-primary` / `.btn-outline`, mono for data, light+dark
via `data-bs-theme`, tokens in `static/style.css`.

### 3.1 Login page — `templates/login.html` (minimal edit)
- Add a **"Forgot password?"** link inside the existing `.remember-forgot`
  row, to the right of the remember-me checkbox.
- Link target: `{{ base_path }}/forgot-password`.
- Styling: violet accent text link, consistent with the standalone login
  tokens (this page inlines its own tokens and loads Bootstrap +
  bootstrap-icons from the jsdelivr CDN — keep new markup self-contained, no
  new external assets).

### 3.2 Request page — new `templates/forgot_password.html`
- **Standalone, unauthenticated**, styled like `login.html` (two-column:
  `.brand-panel` + `.form-panel`) for visual continuity. Reuse the same inlined
  token block and CDN references already in `login.html`.
- Single form field: **"Username or email"** (one input, accepts either).
- Primary button: **"Send reset link"** (`.btn-login`).
- Posts to `{{ base_path }}/forgot-password`.
- After POST, always render the **same generic confirmation** (no
  enumeration): *"If an account with that username or email exists, we've sent
  a password reset link. Check your inbox."* — rendered as a Bootstrap
  `alert-info`/success block, replacing the form.
- A "Back to login" link (`{{ base_path }}/login`).

### 3.3 Reset page — new `templates/reset_password.html`
- **Standalone, unauthenticated**, same styling as above.
- Reached via `GET /reset-password?token=<token>`.
- If token invalid/expired/used → render an **error state**: generic
  *"This reset link is invalid or has expired."* + a button to
  "Request a new link" (→ `/forgot-password`). No password fields shown.
- If token valid → show two fields: **New password**, **Confirm new
  password**, and a small inline note stating the policy: *"At least 8
  characters, including uppercase, lowercase, and a digit."* (mirrors
  `validate_password`).
- Include the token in a **hidden field** and post to
  `{{ base_path }}/reset-password`.
- On success → render success state with a **"Go to login"** button and audit
  the event. Optionally auto-redirect to `/login` after a short delay.
- On policy failure or mismatch → re-render with a Bootstrap `alert-danger`
  and the same field-level guidance (the token, if still valid, is preserved;
  see single-use rules in §5).

### 3.4 Admin → Users (edit `templates/admin.html`, Users tab)
- The Users tab (`#users-panel`) already lists users in a
  `.table.table-hover` with role `.badge-soft` badges and status dots. Add an
  **Email** column (mono, muted when empty → show em-dash "—").
- **Add User modal (`#addUserModal`)** and the **Edit User** modal: add an
  **Email** input (`type="email"`, optional). Follows existing Admin-style
  modal markup (label + Bootstrap form control).
- When a user has no email set, surface a subtle hint (tooltip or muted text:
  *"No email — self-service reset unavailable"*) so admins understand why a
  user cannot self-recover.
- No new tab is added; this feature lives in the existing Users tab plus the
  standalone auth pages.

---

## 4. Configuration & Data Model

### 4.1 `users.json` — add `email` field (backward compatible)
Follow the brief's exact recipe (no schema migration; `.get()` fallbacks keep
old files valid):

1. Extend the `User` dataclass (`app/auth.py:~75`) with `email: str = ""`.
2. Add `"email"` to the dicts built in `create_user()` (`~287`) and
   `_ensure_users_file()` (`~196`).
3. Read it via `udata.get("email", "")` in **both** `get_user()` (`~224`) and
   `get_all_users()` (`~242`).
4. Persistence is automatic (whole dict JSON-dumped by `_save_users`).
5. `update_user()` gains the ability to set/change `email`.

`email` is **not a secret** and is **not Fernet-encrypted** (it is displayed in
the Admin UI and used as a lookup key). It is stored plaintext in
`users.json`, consistent with `username`/`role`.

### 4.2 Reset token — signed, expiring, no persistence of the token itself
- Reuse `itsdangerous.URLSafeTimedSerializer` (already used for sessions in
  `app/auth.py`), but with a **dedicated serializer instance and a distinct
  salt** so reset tokens cannot be confused with session tokens:
  ```
  reset_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="password-reset")
  ```
  `SECRET_KEY` is the same one already derived from `SESSION_SECRET_KEY` env or
  the `.session_key` file on the config PVC.
- **Token payload** (signed, tamper-evident, but *not* encrypted — treat as
  readable):
  ```json
  {
    "u": "<username>",
    "pwv": "<first 12 chars of current bcrypt password_hash>",
    "iat": <unix issue time>
  }
  ```
  - `u` — the resolved username the token is for.
  - `pwv` ("password version") — a fingerprint of the *current*
    `password_hash`. Because a successful reset changes `password_hash`, any
    previously issued token's `pwv` no longer matches → **automatic
    single-use / invalidation without server-side token storage.** A password
    change (`change_password`) or admin reset likewise invalidates all
    outstanding tokens.
  - `iat` — informational; expiry is enforced by `URLSafeTimedSerializer`'s
    `max_age`.
- **Expiry:** `PASSWORD_RESET_TOKEN_MAX_AGE = 1800` seconds (30 minutes),
  enforced via `reset_serializer.loads(token, max_age=1800)` (raises
  `SignatureExpired`).

### 4.3 Single-use / invalidation without a token store (primary mechanism)
The `pwv` fingerprint makes tokens implicitly single-use: the first successful
reset rotates `password_hash`, so the token's `pwv` no longer matches and it is
rejected on any replay. This needs **no new file and no new state** — it works
on the read-only-rootfs, single-replica pod.

**Optional hardening (recommended, see Open Questions):** to invalidate a token
the instant it is *used* (before the hash even changes) and to block issuing
many concurrent valid tokens, add a small `[password_reset]` bookkeeping value
per user. Two options:
- **(a) users.json field** — `pw_reset_at: <unix>` on the user record, set when
  a reset link is issued; the token embeds `iat` and is only accepted if
  `iat >= pw_reset_at` is *not* violated by a newer issuance… (adds
  complexity). **Simpler:** store `pw_reset_jti` (a random id) on issuance and
  in the token; accept only if they match, then clear it on use. Clearing on
  use gives true single-use even before the hash changes.
- **(b) No extra state** — rely solely on `pwv` (accept the small window where a
  token works until the password actually changes; a reset always changes it,
  so real single-use holds for the *effective* operation).

Recommendation: **`pw_reset_jti` on the user record in `users.json`** — it is
free (whole-dict JSON, no migration), gives explicit single-use, and lets a new
request invalidate the previous outstanding link. Written under the existing
`_users_lock`.

### 4.4 New/changed files summary
| File | Change |
|------|--------|
| `app/auth.py` | `User.email`, `User.pw_reset_jti`; token helpers; reset orchestration; per-IP rate limiter reuse; audit events |
| `app/main.py` | 5 new routes (§5); wire request bodies (Pydantic) |
| `templates/login.html` | add "Forgot password?" link |
| `templates/forgot_password.html` | **new** request page |
| `templates/reset_password.html` | **new** reset page |
| `templates/admin.html` | Email column + Email inputs in add/edit user modals |
| Companion spec | `[smtp]` section in `config.ini` (Fernet-encrypted password), `send_email` helper |

No change to `config.ini` is required *by this spec* beyond what the email spec
adds. Nothing new is Fernet-encrypted here (email addresses and reset tokens
are not secrets at rest; the SMTP password is, and belongs to the email spec).

---

## 5. API Endpoints

All new endpoints are **unauthenticated** (a forgotten-password user has no
session). They rely on rate limiting, generic responses, and token signing for
safety. Admin email editing rides existing authenticated user routes.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/forgot-password` | none | Render request page |
| POST | `/forgot-password` | none | Accept username/email, always return generic response, send email if a match with an email exists |
| GET | `/reset-password?token=` | none | Validate token, render reset form or error state |
| POST | `/reset-password` | none | Validate token + policy, update password, clear lockout, invalidate token |
| PUT | `/api/users/{username}` | `require_admin` | **Existing** route — extended to accept `email` |
| POST | `/api/users` | `require_admin` | **Existing** route — extended to accept `email` |

### 5.1 `POST /forgot-password`
- Request (form-encoded, matching login.html style): `identifier` (username or
  email).
- Behavior:
  1. Per-IP rate limit check (reuse `app/auth.py` in-memory limiter,
     `RATE_LIMIT_MAX_ATTEMPTS`/`RATE_LIMIT_WINDOW_SECONDS`, or a dedicated
     lower bucket for this endpoint — see Open Questions). On exceed → still
     return the generic 200, but do not send.
  2. Resolve user: match `identifier` against `username` (exact) then against
     `email` (case-insensitive). Requires a helper `find_user_by_identifier()`.
  3. If a user is found **and has a non-empty `email` and `enabled=True`**:
     mint a reset token (§4.2), build link
     `{base_url}{base_path}/reset-password?token=<token>`, and call
     `send_email(...)` (companion spec). Set `pw_reset_jti` on the user.
  4. **Always** render the same generic confirmation (200), regardless of
     match/no-match/disabled/no-email. Timing should be roughly constant (do
     the token/email work in the background / after responding, or add a small
     constant delay) to avoid a timing oracle.
- Response: `200` HTML, generic confirmation. No JSON, no status leakage.
- Audit: `password_reset_requested` with the *submitted identifier* (not
  whether it matched), IP; and a separate `password_reset_email_sent` (with the
  resolved username) only when an email is actually dispatched.

### 5.2 `GET /reset-password?token=`
- Validates the token: `reset_serializer.loads(token, max_age=1800)`, then
  checks `pwv` against the user's current `password_hash[:12]` and (if used)
  `pw_reset_jti`.
- Valid → render `reset_password.html` with the token in a hidden field.
- Invalid/expired/used/missing/user-disabled → render generic error state
  (200, no leakage of which condition failed).

### 5.3 `POST /reset-password`
- Request (form-encoded): `token`, `password`, `confirm_password`.
- Behavior:
  1. Re-validate the token exactly as in 5.2 (never trust that GET validated
     it). Invalid → error state.
  2. `password == confirm_password`; else re-render with error (token
     preserved).
  3. `validate_password(password)` (≥8, upper, lower, digit); else re-render
     with policy error (token preserved).
  4. On success, under `_users_lock`: set new `password_hash` via
     `hash_password`, set `failed_attempts = 0`, `locked = False`, clear
     `pw_reset_jti`, persist via `_save_users`. This reuses the same field
     mutations as `reset_user_password`/`change_password` but is
     token-authorized rather than admin/self-authorized.
  5. Do **not** auto-create a session; user is redirected to `/login` to sign
     in with the new password (keeps the reset flow and the session flow
     separate).
- Response: `200` success state (or `303` redirect to `/login`).
- Audit: `password_reset_completed` (resolved username, IP). On repeated/failed
  token use: `password_reset_failed` (reason category: expired | invalid |
  used).

### 5.4 Admin user routes (existing, extended)
- `POST /api/users` (`AddUserModel`) and `PUT /api/users/{username}`
  (`UpdateUserModel`) gain an optional `email: str` field (Pydantic
  `EmailStr` recommended for format validation). Empty string clears it.
- GET responses that list users include `email` (it is not a secret — no `***`
  masking needed, unlike AWS/S3 secrets).

---

## 6. Security & Privacy

This section is the heart of the spec. Threats and mitigations:

| # | Threat | Mitigation |
|---|--------|------------|
| T1 | **User enumeration** via request page (different response/timing for existing vs non-existing accounts) | Single generic response for all cases; constant-ish timing (defer email work, or fixed delay); identical behavior for no-match, disabled, and no-email users. Audit logs the *submitted* identifier, never a "not found" hint back to the client. |
| T2 | **Token forgery / tampering** | `URLSafeTimedSerializer` HMAC signature over `SECRET_KEY`; any tamper → `BadSignature` → generic error. |
| T3 | **Token replay after use** | `pwv` fingerprint (password hash changes on success → old tokens rejected) **plus** `pw_reset_jti` cleared on use for immediate single-use. |
| T4 | **Token expiry** | `max_age=1800` (30 min); `SignatureExpired` → generic error. |
| T5 | **Brute force / spam of request endpoint** (mail-bombing a victim, resource exhaustion) | Reuse per-IP in-memory rate limiter; consider a per-target throttle (don't send >1 email per user per N minutes — `pw_reset_jti`/timestamp supports this). Return generic 200 even when throttled. |
| T6 | **Brute force of reset token** | 30-min window + HMAC over a strong `SECRET_KEY` makes guessing infeasible; add per-IP rate limit on `POST /reset-password`. |
| T7 | **Account lockout interaction** | A completed reset intentionally clears `failed_attempts`/`locked` (US-2). But the *request* flow must work for locked accounts (locked users need recovery). Requesting a reset does not itself change lockout. Only successful completion clears it. |
| T8 | **Disabled accounts** | `enabled=False` users get the generic response but **no email**; even a forged token is rejected because the reset path checks `enabled`. |
| T9 | **Email interception / link leakage** | Tokens are single-use + short-lived; email link uses HTTPS `base_url`. The email must not include the password. Mitigation depth depends on the SMTP transport (TLS) defined in the email spec. |
| T10 | **Secret key rotation** | Reset tokens are invalidated if `.session_key`/`SESSION_SECRET_KEY` changes (shared `SECRET_KEY`). Acceptable — worst case a user re-requests. Documented. |
| T11 | **Open redirect via reset link** | The reset link is built server-side from configured `base_url`/`base_path`; no user-supplied redirect parameter is honored. |
| T12 | **Privilege/role escalation via reset** | Reset only mutates `password_hash`/lockout for the token's own `u`; role/endpoints/enabled are never touched. No admin bootstrap via reset. |

### Privacy notes
- Email addresses are PII but not secrets; stored plaintext in `users.json`
  (on the encrypted-at-rest config PVC, but the field itself is not
  Fernet-wrapped). They appear in the Admin UI to admins only.
- The audit log records identifiers submitted to `/forgot-password`. This is
  intentional for security forensics but means submitted (possibly
  mistyped/third-party) emails land in `audit.log` — call out in privacy
  review.

### No-email users & bootstrap admin (fallback)
- Users without an `email` **cannot** self-recover. This is by design and
  matches T1 (generic response, no email sent).
- The **bootstrap admin** created by `_ensure_users_file()` (initial random
  password logged at first run) has no email unless one is set. Its documented
  recovery path remains: edit `users.json` / run the CLI/manual reset (as today
  via `reset_user_password`). This spec must **not** remove or weaken that
  fallback — it is the break-glass for the highest-privilege account.

---

## 7. Dependencies

- **Python libraries:** *none new for this spec.* `itsdangerous` (already a
  dependency, used for sessions) provides `URLSafeTimedSerializer`. `bcrypt`
  (already present) for hashing.
- **Hard prerequisite (separate spec):** the email-sending subsystem —
  `smtplib`/`aiosmtplib`, `[smtp]` config section (Fernet-encrypted password),
  and outbound SMTP egress. Password recovery is unusable without it.
- **Infra / egress:** outbound SMTP submission (587 STARTTLS or 465 implicit
  TLS) to the configured relay — owned by the email spec but noted here because
  it gates delivery.
- **No inbound network changes**, no new privileged capabilities.

---

## 8. Kubernetes / Deploy Impact

- **securityContext:** *unaffected.* Unlike the OpenVPN comparison
  (`/dev/net/tun` + `NET_ADMIN`), this feature adds **no** kernel-networking or
  privilege requirements. It stays fully compatible with the locked-down pod:
  `runAsNonRoot`, `runAsUser 1000`, `readOnlyRootFilesystem: true`,
  `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`,
  `seccompProfile: RuntimeDefault`. This is the SSM-tunnel-style "userspace,
  no privilege" posture, not the OpenVPN one.
- **Writable state:** all mutations land in `users.json` on the existing
  `magikup-config` PVC and appends to `audit.log`. No new PVC, no `/tmp` usage
  beyond what exists. Compatible with read-only rootfs.
- **Secrets:** no new Secret from this spec. The out-of-band `magikup-secret`
  (`ENCRYPTION_KEY`) and `.session_key` are unchanged. The SMTP password
  (email spec) is Fernet-encrypted in `config.ini` on the config PVC — no k8s
  Secret needed for it either, consistent with existing `[fileshare:*]` etc.
- **Sidecars:** none.
- **Replicas / strategy:** unchanged (`replicas: 1`, `Recreate`). Single
  replica means the in-memory rate limiter and `pw_reset_jti` in `users.json`
  are globally consistent — no distributed-state concern. (If MagikUp ever
  scales out, the in-memory limiter becomes per-pod; noted for the future.)
- **NetworkPolicy:** add an egress allow for the SMTP relay in the
  overlay-specific NetworkPolicy (belongs to the email spec; noted).

---

## 9. Failure Modes & Edge Cases

| Scenario | Behavior |
|----------|----------|
| SMTP down / send fails | User still sees the generic confirmation (no leak). Failure is audited (`password_reset_email_error`) and logged; the token was minted but simply never delivered — it expires harmlessly. Consider a bounded retry in the email helper (email spec). |
| User has no email | Generic confirmation, no email sent, no token minted. Fallback = manual reset. |
| Disabled user requests reset | Generic confirmation, no email, token (if forged) rejected at reset. |
| Locked user requests reset | Email sent (locked ≠ no-email); successful reset clears `locked` + `failed_attempts`. |
| Token expired (>30 min) | Generic error page + "request a new link". |
| Token reused after success | Rejected (`pwv` mismatch and/or `pw_reset_jti` cleared) → generic error. |
| Two reset links requested | Latest issuance overwrites `pw_reset_jti`; earlier link becomes invalid (if the `pw_reset_jti` hardening is adopted). With `pwv`-only, both stay valid until one is used. |
| Password fails policy | Re-render reset page with policy error; token preserved (still one logical attempt) until a successful change or expiry. |
| Confirm mismatch | Re-render with error; token preserved. |
| `SECRET_KEY` rotated between issue and use | Token invalid → generic error → user re-requests. |
| Email typo / attacker submits victim's email | Only the real owner of the mailbox receives the link; submitter learns nothing (generic response). Rate limit curbs mail-bombing. |
| Concurrent reset + admin reset | Both take `_users_lock`; last write wins on `password_hash`. Admin reset also changes the hash → invalidates outstanding self-service tokens (`pwv`). |
| Very old `users.json` without `email`/`pw_reset_jti` | `.get(..., "")` fallbacks; treated as no-email → no self-service (safe default). |
| Username that is also someone's email | `find_user_by_identifier` resolves username first, then email; document precedence. Ambiguity is unlikely given username validation. |

---

## 10. Effort Estimate

**Overall: M** (assuming the email-sending prerequisite is delivered
separately; this feature *alone* is small-to-medium).

| Area | Size | Notes |
|------|------|-------|
| `users.json` `email` + `pw_reset_jti` (dataclass + 3 dict builders + reads) | S | Backward-compatible, no migration; brief gives exact line refs. |
| Token helpers (mint/verify, `pwv`, jti) reusing `URLSafeTimedSerializer` | S | No new dep; mirror `create_session_token`/`verify_session_token`. |
| Auth orchestration (`find_user_by_identifier`, request/complete flows, rate limit, audit events, lockout clearing) | M | Reuses existing limiter, audit, bcrypt, `_users_lock`. |
| 5 routes in `app/main.py` (2 pages GET, 2 POST, extend user API) + Pydantic bodies | M | Follows existing route/response patterns. |
| `forgot_password.html` + `reset_password.html` (new, styled like login) | M | Two standalone pages; reuse login's token/CDN block. |
| `login.html` link + `admin.html` Email column/inputs | S | Small template edits. |
| Tests (token expiry/replay, enumeration, policy, lockout clear) | M | Security-critical paths. |
| **Dependency: email-sending subsystem** | (separate spec, M–L) | **Blocks delivery.** |

Net incremental effort for this feature *given* email support: **M**.

---

## 11. Open Questions / Decisions for the User

1. **Single-use hardening:** Adopt the `pw_reset_jti` field (explicit single-use
   + supersede previous link) or rely on the `pwv`-only mechanism (simpler, but
   a token stays valid until the password actually changes)? *Recommended:*
   `pw_reset_jti`.
2. **Token lifetime:** Confirm 30 minutes, or prefer 15 / 60?
3. **Email verification:** Should admin-entered emails require a
   confirmation/verification step before they can receive reset links, or are
   they trusted as entered? (Out of scope as drafted — trusted.)
4. **Rate-limit bucket:** Reuse the existing login limiter
   (`5 / 300s` per IP) for `/forgot-password` and `/reset-password`, or a
   dedicated (lower) bucket? Also decide a per-*target* throttle (max 1 reset
   email per user per N minutes).
5. **Notify on admin reset:** When an admin resets a password via
   `reset_user_password`, should the user be emailed too? (Nice-to-have; would
   also lean on the email spec.)
6. **Post-reset behavior:** Redirect to `/login` (recommended) vs auto-login by
   minting a session on success?
7. **`base_url` for links:** Where does the reset link's absolute base come
   from — a new `[settings]` `base_url`, request-derived host, or existing
   `base_path` + `X-Forwarded-*`? Needed for correct links behind the ingress.
8. **Email format validation:** Use Pydantic `EmailStr` (pulls in
   `email-validator`, a small new dep) or a light regex to avoid any new
   dependency?
9. **Bootstrap admin policy:** Confirm the manual `users.json`/CLI reset stays
   the documented break-glass and that we will *not* auto-email the initial
   admin (which has no email by default).
