# Functional Spec — Email Sending (SMTP)

**Status:** Draft · **Target version:** MagikUp v4.3.0 · **Author:** spec phase · **Audience:** MagikUp maintainers

> This is a **functional specification only**. No application code is changed by this document. It describes the outbound-email *foundation* that later features (password recovery, schedule-failure alerts, operation notifications) will consume. Those consumers are explicitly **out of scope** here.

---

## 1. Purpose & user stories

MagikUp currently has **no way to send email** — there is no SMTP client, no `[smtp]` config, no `email` field on users, and `itsdangerous` is the only signing/token library present. This spec introduces a small, reusable outbound-email service and its admin-managed configuration, so that later features have a dependable `send_email(...)` primitive and a place to configure the mail server.

The scope of *this* deliverable is deliberately narrow: **configure an SMTP server, encrypt its password like every other MagikUp secret, and prove it works with a "Send test email" button.**

### User stories

- **As an admin**, I want to enter my organization's SMTP server settings (host, port, security mode, credentials, from-address) on the Admin page, so MagikUp can send mail on our behalf.
- **As an admin**, I want the SMTP password stored encrypted at rest (never in plaintext, never echoed back to the browser), consistent with how AWS/S3/fileshare secrets are handled.
- **As an admin**, I want a **"Send test email"** button that sends to an address I type and shows me a clear success or a specific, actionable error (auth failed, connection refused, TLS error, timeout), so I can validate the config without waiting for a real notification.
- **As an admin**, I want to disable email globally with one toggle, so no feature attempts to send when the server is not ready.
- **As a maintainer (future consumer)**, I want a single `email_service.send_email(to, subject, html, text)` function that reads the stored config, so I don't reimplement SMTP per feature.

### Non-goals (this deliverable)

- No password-recovery flow, no alerting, no scheduled-job notifications (future consumers; see §2).
- No inbound mail, no IMAP/POP, no mailbox reading, no templated newsletters.
- No per-user "email me" preferences UI (the `email` field is added to the data model, but user-facing opt-in lives with the future consumer).

---

## 2. Scope

### In scope

1. New encrypted config section **`[smtp]`** in `config/config.ini`, following the `[fileshare:*]` / `[filebrowser:*]` encrypted-secret recipe in `app/config.py`.
2. New module **`app/email_service.py`** — stdlib `smtplib` + `ssl`, exposing `send_email(...)` and a `send_test_email(...)` helper.
3. New Admin UI: an **"Email" card** (recommended) or **tab** on `templates/admin.html`, matching the existing design system, with a config form and a **Send test email** action.
4. Admin API endpoints: get/save SMTP config (secret masked on read) and a test-send endpoint.
5. New **`email`** field on the `User` dataclass in `app/auth.py` / `users.json` (additive, backward-compatible), so future consumers have a recipient address. No user-facing email UI beyond an optional field on the existing Add/Edit User modal (see §3, Open Question).
6. Kubernetes/egress considerations for reaching the SMTP host.

### Out of scope (named future consumers)

- **Password recovery / "forgot password"** — will reuse `itsdangerous.URLSafeTimedSerializer` for signed, expiring tokens and call `email_service.send_email(...)`. Mentioned only to justify the `email` field and the `text`+`html` signature.
- **Schedule-failure alerts / operation notifications** — future consumers of `send_email(...)`; not built here.
- SMTP OAuth2 / XOAUTH2 (e.g. Gmail/M365 modern auth) — see Open Questions.

---

## 3. UX / UI

All UI reuses the existing design system: `.app-main` shell, `.card.config-card` with `.card-header`, `.btn.btn-sm.btn-primary` / `.btn-outline`, Bootstrap modals, `.table.table-hover`, `.badge-soft`, `.dot`/`.dot-success`/`.dot-idle`, `.mono` for data, single violet accent (`#7c3aed` light / `#8b5cf6` dark), light+dark via `data-bs-theme`, tokens from `static/style.css`. **No changes to `login.html`** are part of this deliverable (the forgot-password link is a future consumer's concern).

### 3.1 Placement — recommended: a card in the existing **Settings** tab

Because there is a single `[smtp]` section (not a list of N accounts like AWS/S3), a dedicated tab is heavier than needed. **Recommendation:** add an **"Email (SMTP)"** `.card.config-card` inside the existing `#settings-panel` tab-pane, beneath the current settings card.

> Alternative (Open Question §11): a full new `email` tab (`nav-link` + `tab-pane`) following the `#adminTabs` pattern, persisted in `localStorage` like the others. Choose the tab if we expect notification-preference sub-panels to grow here.

### 3.2 The Email config card

Header: title **"Email (SMTP)"** + a status pill on the right:
- `.dot-success` **"Configured"** when a host is saved and email is enabled.
- `.dot-idle` **"Not configured"** / **"Disabled"** otherwise.

Form fields (Bootstrap form controls, `.mono` for host/port):

| Field | Control | Notes |
|---|---|---|
| Enabled | switch (`form-check form-switch`) | master on/off; gates all sends |
| SMTP host | text | e.g. `smtp.example.com` |
| Port | number | default depends on security (see below) |
| Security | select: `STARTTLS` / `SSL/TLS` / `None` | drives which smtplib path is used |
| Username | text | optional (some relays are IP-allowlisted, no auth) |
| Password | password input | shows `••••` placeholder when a secret exists; blank = "leave unchanged" |
| From address | email | required; RFC-validated |
| From name | text | optional display name, e.g. `MagikUp` |
| Reply-To | email | optional |
| Timeout (s) | number | default 15, bounded 5–60 |

Buttons in the card footer:
- **Save** — `.btn.btn-sm.btn-primary` → `POST /api/config/smtp`.
- **Send test email** — `.btn.btn-sm.btn-outline` → opens the test modal.

**Password field semantics (mirror `api_get_aws_accounts` masking):** on load, if a password is stored, the field renders empty with a placeholder and a small hint "leave blank to keep current password". Submitting an empty password field means "keep the existing encrypted value" (do not overwrite with empty). This exactly matches how existing secret fields behave in the admin.

### 3.3 Send-test-email modal

A standard Admin-style Bootstrap modal (`#sendTestEmailModal`, same markup family as `#addEndpointModal`):

- One field: **Recipient** (email), defaulting to the logged-in admin's own `email` if set, else blank.
- Helper text: "Sends a small test message using the currently **saved** SMTP settings." (Test uses saved config, not unsaved form edits — so the admin saves first; keeps the endpoint simple and avoids sending secrets in the test request.)
- **Send** button → `POST /api/config/smtp/test`.
- Result rendered inline in the modal:
  - Success: green `.alert` "Test email sent to `<addr>`. Check the inbox."
  - Failure: red `.alert` with a **specific** message mapped from the exception class (see §7 / §9), e.g. "Authentication failed (535). Check username/password." — never the raw traceback, never the password.

---

## 4. Configuration & data model

### 4.1 New INI section `[smtp]` (single fixed section)

Follows the encrypted-secret pattern but as a **fixed section** (like `[settings]`/`[query]`), not a user-named prefix — so **no** `_RESERVED_PREFIXES` registration and no name-validation are needed.

```ini
[smtp]
enabled = false
host =
port = 587
security = starttls        ; one of: starttls | ssl | none
username =
password = ENC:...         ; Fernet-encrypted, "ENC:" prefix; empty allowed
from_address =
from_name = MagikUp
reply_to =
timeout_seconds = 15
```

- **`password` is the only encrypted field.** Stored via `encrypt_password(...)` on save, read via `decrypt_password(...)` — exactly the `[fileshare:*]` pattern. (Note the contrast with `[aws:*]`, whose `secret_access_key` is currently plaintext; we deliberately follow the **encrypted** side, matching S3/fileshare/filebrowser.)
- Booleans (`enabled`) written as `str(x).lower()`, read with `getboolean(..., fallback=False)`.
- Ints (`port`, `timeout_seconds`) via `getint(..., fallback=...)`.
- `read_config()` already uses `interpolation=None`, so literal `%` in passwords/URLs is safe — important for SMTP passwords.

### 4.2 New `config.py` helpers (mirroring the `[settings]`/`[fileshare]` triad)

- `@dataclass SMTPConfig` — plaintext `password` in memory, all fields above.
- `get_smtp_config() -> SMTPConfig` — reads `[smtp]`, **decrypts** the password on read, applies fallbacks.
- `save_smtp_config(cfg: SMTPConfig)` — `read_config()` → `add_section('smtp')` if missing → `set` each field → `set('smtp','password', encrypt_password(cfg.password))` → `write_config`. If the incoming password is empty **and** an encrypted value already exists, preserve the existing value (implements the "leave blank to keep" UX).
- Document defaults/comments in `get_default_config()` so fresh installs get a commented `[smtp]` stub.
- `[smtp]` is **not** required by import/export validation (only `['settings','auth']` are required); it round-trips through `get_full_config_content()` / `import_config_content()` unchanged, carrying its `ENC:` secret.

### 4.3 `users.json` — additive `email` field

Per the context brief, `User` has **no email today**. Add it additively (no migration):

- Add `email: str = ""` to the `User` dataclass (`app/auth.py:~75`).
- Add `"email"` to the dicts built in `_ensure_users_file()` (~196) and `create_user()` (~287).
- Read with `udata.get("email", "")` in **both** `get_user()` (~224) and `get_all_users()` (~242).
- Backward compatible: old `users.json` files without the key stay valid via `.get()` fallback. Whole-dict JSON dump handles persistence.
- Optional (Open Question §11): surface an **Email** input on the existing Add/Edit User modal, validated as RFC email or empty. Not required for the SMTP foundation itself.

### 4.4 New file

- `app/email_service.py` — the send module. No new persisted files. Logs go to the existing logs PVC via the app's logger.

---

## 5. `app/email_service.py` — module contract (functional, not implementation)

Stdlib only (`smtplib`, `ssl`, `email.message.EmailMessage`, `email.utils`). No new heavy dependency.

```
send_email(to, subject, html, text=None, *, reply_to=None) -> None
    # Loads get_smtp_config(); raises EmailNotConfigured if disabled/host empty.
    # Builds a multipart/alternative message (text + html); if text is None,
    # derive a minimal plaintext fallback.
    # Connects per `security`:
    #   ssl      -> smtplib.SMTP_SSL(host, port, timeout, context=ssl.create_default_context())
    #   starttls -> smtplib.SMTP(host, port, timeout); ehlo(); starttls(context=...); ehlo()
    #   none     -> smtplib.SMTP(host, port, timeout)   (discouraged; warn in UI)
    # login(username, password) only if username set.
    # send_message(...); always quit()/close in finally.

send_test_email(recipient) -> None
    # Thin wrapper: fixed subject/body identifying the MagikUp instance + timestamp.
```

Behavioral requirements:
- **Timeout** on every socket op from `timeout_seconds` (default 15) — never block the event loop indefinitely. Because `smtplib` is blocking, call sites in async FastAPI handlers must run it in a threadpool (`run_in_threadpool` / `asyncio.to_thread`).
- **TLS context** via `ssl.create_default_context()` (verifies cert + hostname by default). See §6 for the "allow insecure" question.
- **Recipient validation** before connecting: reject anything failing a conservative RFC-5322-ish check; support a single recipient for the test, and a list for `send_email`.
- **Never log the password**, the full auth exchange, or message bodies at INFO. On error, log the exception *class* + SMTP status code + host/port, not credentials.
- Raise a small set of typed exceptions (`EmailNotConfigured`, `EmailAuthError`, `EmailConnectionError`, `EmailTLSError`, `EmailTimeout`, `EmailSendError`) so the API layer can map them to precise user messages.

---

## 6. API endpoints

All under the existing config-API convention; **all admin-gated** with `Depends(auth.require_admin)`. Pydantic `BaseModel` request bodies, matching `AWSAccountModel` style. Secret masked as `"***"` in GET (replicating `api_get_aws_accounts`, `main.py:~1858`).

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/api/config/smtp` | admin | — | `SMTPConfigOut` with `password` field returned as `"***"` if set, else `""`; all other fields plaintext. Plus derived `configured: bool`. |
| POST | `/api/config/smtp` | admin | `SMTPConfigIn` (all fields; `password` optional) | `{ "status": "ok" }`. Empty `password` ⇒ keep existing. Validates `security ∈ {starttls,ssl,none}`, port 1–65535, `from_address` RFC-valid, timeout 5–60. |
| POST | `/api/config/smtp/test` | admin | `{ "recipient": "<email>" }` | On success `{ "status": "sent", "recipient": ... }`. On failure `HTTP 400/502` with `{ "status": "error", "code": "<enum>", "message": "<user-safe>" }`. |

Notes:
- Test uses the **saved** config (not the request body) — so no secret ever travels in the test request, and the test measures exactly what future consumers will use.
- The test endpoint maps exceptions → codes: `auth`, `connection`, `tls`, `timeout`, `not_configured`, `invalid_recipient`, `unknown`. UI renders the mapped `message`.
- Consider a light rate-limit on `/api/config/smtp/test` (e.g. reuse the in-memory per-IP limiter idea from `auth.py`) to avoid using MagikUp as a spam relay via repeated test sends. (Open Question §11.)

---

## 7. Security & privacy

| Threat | Mitigation |
|---|---|
| SMTP password disclosure at rest | Fernet encryption with `ENC:` prefix via `encrypt_password()`; key durable on config PVC (`config/.encryption_key`, chmod 0600), seeded from `ENCRYPTION_KEY` Secret — identical to all other MagikUp secrets. |
| Password echoed to browser / logs | GET returns `"***"` (never the token or plaintext); email_service never logs the password or the AUTH exchange; blank-submit preserves stored secret. |
| Passive network capture of credentials | Default to **STARTTLS** (587) or **SSL/TLS** (465); use `ssl.create_default_context()` (cert + hostname verification on). `security=none` is allowed but the UI must warn ("credentials sent in cleartext"). |
| MITM via forged cert | Default context verifies the chain and hostname; do **not** disable verification silently. If an "allow insecure TLS" escape hatch is added (Open Question), it must be an explicit, clearly-labeled per-config toggle, off by default. |
| MagikUp used as an open relay / spam | Only admins can configure and trigger sends; the foundation exposes no unauthenticated send path. Test endpoint is admin-only and rate-limitable. Future consumers must send only to addresses MagikUp controls (user records), not arbitrary user input. |
| Header injection via from/reply-to/subject | Build messages with `email.message.EmailMessage` (which encodes headers safely); reject CR/LF in `from_address`, `from_name`, `reply_to`, `subject`, and recipients. |
| Recipient exfiltration / typo blasting | Validate recipient format; test sends to exactly one address; log recipient at INFO but not bodies. |
| Secret leaking through import/export | `[smtp]` round-trips with its `ENC:` token; the exported config carries ciphertext, not plaintext — same trust model as existing sections. Warn (existing behavior) that export bundles secrets. |
| SSRF-ish abuse (pointing SMTP host at internal services) | Admin-only config limits blast radius; NetworkPolicy overlay (see §8) should constrain egress to the intended relay where feasible. |

---

## 8. Dependencies

- **Python libs:** none new — stdlib `smtplib`, `ssl`, `email.*`. (`aiosmtplib` was considered; stdlib + threadpool keeps the dependency surface at zero, consistent with the brief's preference. Revisit only if fully-async sending becomes a requirement.)
- **Token/signing:** none here; the future password-recovery consumer reuses the already-present `itsdangerous.URLSafeTimedSerializer` (ideally a separate serializer + salt) — no new dependency then either.
- **Infra:** an SMTP relay reachable from the pod (customer-provided: corporate relay, SES SMTP endpoint, SendGrid/Mailgun SMTP, etc.).
- **Egress:** outbound TCP to the configured SMTP host/port — commonly **587 (STARTTLS)** or **465 (SSL/TLS)**, occasionally **25** or **2525**. DNS resolution for the host.

---

## 9. Kubernetes / deploy impact

Unlike the OpenVPN analog, **email sending needs no privileged networking** — it is a plain userspace outbound TCP connection, so it is fully compatible with the locked-down pod:

- **securityContext untouched:** `runAsNonRoot`, `runAsUser 1000`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault` all remain. Outbound TCP from an unprivileged process requires none of these to change. (Contrast with the SSM tunnel, which spawns a subprocess but still needs no kernel networking privileges — email is even simpler: an in-process socket.)
- **No sidecar, no new capability, no `/dev/net/tun`.**
- **Secret:** no new Secret required — the SMTP password rides inside the existing Fernet-encrypted `config.ini` on the config PVC, protected by the existing `magikup-secret`/`ENCRYPTION_KEY`. (If an org prefers, the SMTP password *could* be surfaced as a separate Secret later, but that is not needed and not proposed.)
- **Writable filesystem:** none needed beyond existing mounts; email is in-memory. `/tmp` (emptyDir) is available if any transient spooling is ever wanted (not required).
- **NetworkPolicy:** base excludes NetworkPolicy (overlay-specific). Overlays that restrict egress **must add an egress allow rule** to the SMTP host/port (and DNS), or sends will time out. Document the required port in the overlay.
- **Deploy topology unchanged:** single replica, `Recreate` — fine; email is stateless and synchronous.

---

## 10. Failure modes & edge cases

| Scenario | Behavior |
|---|---|
| Email disabled or host empty | `send_email` raises `EmailNotConfigured`; test endpoint returns `not_configured`; future consumers must degrade gracefully (e.g. password-recovery shows "email not configured, contact admin"). |
| Wrong host / port unreachable | `EmailConnectionError` → test shows "Could not connect to `<host>:<port>`. Check host/port and egress." |
| Auth rejected (535/534) | `EmailAuthError` → "Authentication failed. Check username/password." |
| STARTTLS not offered by server, or cert invalid | `EmailTLSError` → "TLS negotiation failed. Try SSL/TLS mode or check the server certificate." |
| Slow/hung server | socket timeout (`timeout_seconds`) → `EmailTimeout` → "Timed out after Ns." Never hangs the request/event loop (threadpool + timeout). |
| Invalid recipient | rejected pre-connect → `invalid_recipient`, HTTP 400. |
| Blank password submitted with existing secret | keeps stored encrypted password (no clobber). |
| Blank password submitted with **no** existing secret + username set | save allowed; send will likely fail auth — surfaced only at test/send time. |
| `security=none` with credentials | allowed but UI warns; credentials sent cleartext. |
| Encryption key rotated / lost | `decrypt_password` returns `""` on `InvalidToken` (existing behavior) → treated as "no password set"; admin must re-enter. Consistent with all other secrets. |
| Import of a config from another instance | `ENC:` token only decrypts if the target instance shares the encryption key; otherwise password reads as empty and must be re-entered — same as existing sections. |
| Multiple recipients (future) | `send_email` accepts a list; partial failures reported per RFC via `smtplib` refused-recipients dict → surfaced as `EmailSendError`. |
| Concurrent test clicks | idempotent; optional rate-limit prevents relay abuse. |

---

## 11. Effort estimate

**Overall: S–M (small-to-medium).** No new dependency, no k8s hardening changes, single fixed config section, one small stdlib module.

| Work item | Size | Notes |
|---|---|---|
| `SMTPConfig` dataclass + `get_/save_smtp_config` + `get_default_config()` stub | S | Direct copy of the `[fileshare]`/`[settings]` triad; only `password` encrypted. |
| `app/email_service.py` (send_email + send_test_email + typed exceptions) | S–M | Stdlib smtplib/ssl; the care is in TLS modes, timeouts, and error mapping. |
| API: GET/POST `/api/config/smtp` + POST `/api/config/smtp/test` (Pydantic models, `require_admin`, `"***"` masking, threadpool call) | S | Mirrors existing config endpoints. |
| Admin UI: Email card in Settings tab + test modal (design-system markup, mask/keep-password UX, error rendering) | M | Most of the visible effort; matches existing modals. |
| `users.json` `email` field (dataclass + 3 dict builders + optional Add/Edit User input) | S | Additive, backward-compatible. |
| Docs: NetworkPolicy egress note for overlays; `.env`/secret unchanged | S | Documentation only. |
| Tests: config round-trip (encrypt/decrypt), error-mapping unit tests, mask-on-GET | S–M | |

Rough total: **M**, front-loaded on the module's error handling and the admin card.

---

## 12. Open questions / decisions for the user

1. **Card vs. tab.** Put the SMTP form as a **card inside the existing Settings tab** (recommended, lighter) or a **dedicated "Email"/"Notifications" tab** (better if notification preferences will grow here)?
2. **`email` on users now?** Add the optional Email input to the Add/Edit User modal in this deliverable, or add only the backing field and defer the UI to the password-recovery feature?
3. **`security=none` allowed?** Keep the "None" (cleartext) option with a warning, or forbid it entirely and require STARTTLS/SSL?
4. **Insecure-TLS escape hatch?** Do any target relays use self-signed/internal certs that would need an explicit "do not verify certificate" toggle (off by default, clearly labeled), or do we mandate valid certs?
5. **Test-send rate limiting.** Add an in-memory per-IP/per-admin limit on `/api/config/smtp/test` (reusing the `auth.py` limiter idea) to prevent relay abuse — yes/no?
6. **From-address policy.** Any constraint that `from_address` domain match an allowlist (some relays reject mismatched envelope-from), or leave fully free-form?
7. **OAuth2 / XOAUTH2.** Any need for modern-auth SMTP (Gmail/M365) now, or is username+password (app-password) sufficient for the foreseeable relays? (OAuth2 would be a larger, later change.)
8. **Separate Secret for SMTP password?** Keep it inside the Fernet-encrypted `config.ini` (recommended, matches all other secrets) or surface it as its own k8s Secret env var?
