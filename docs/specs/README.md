# MagikUp — Feature Specs: Prioritization & Roadmap

This directory holds three functional specifications. This README summarizes them,
maps their dependencies, weighs effort against value and risk, and recommends an
implementation order (including an MVP-first path) plus the cross-cutting concerns
shared across all three.

| Spec | File |
|---|---|
| Email Sending (SMTP) | [`email-sending.md`](./email-sending.md) |
| Password Recovery via Email | [`password-recovery.md`](./password-recovery.md) |
| OpenVPN Integration | [`openvpn-integration.md`](./openvpn-integration.md) |

---

## 1. Feature overviews

**Email Sending (SMTP).** Introduces MagikUp's first outbound-email capability —
a small, reusable SMTP foundation, since no email code exists today. It adds an
encrypted `[smtp]` config section (only the password is Fernet-encrypted, `ENC:`
prefix), a stdlib `app/email_service.py` module exposing `send_email(...)` /
`send_test_email(...)` with typed errors and STARTTLS/SSL/none modes, an
admin-gated `/api/config/smtp` API with a masked secret, an "Email (SMTP)" card in
the existing Settings tab with a send-test modal, and an additive `email` field on
the `User` model. Consumers (password recovery, alerts) are explicitly out of
scope. It needs no privileged networking — the locked-down pod securityContext is
untouched and the password rides inside the existing Fernet-encrypted config PVC.

**Password Recovery via Email.** Self-service "Forgot password?" reset so users
(including lockout victims) regain access without an admin hand-editing
`users.json`. It reuses the already-present `itsdangerous.URLSafeTimedSerializer`
for signed, expiring (30-min), single-use tokens (dedicated salt; a `pwv`
password-hash fingerprint for implicit single-use, plus an optional `pw_reset_jti`
for explicit single-use), adds two standalone pages styled like `login.html`, a
"Forgot password?" link, an Email column in Admin → Users, and five routes reusing
bcrypt, `_users_lock`, the per-IP rate limiter, and the audit log. Its security
core is strict no-user-enumeration, token expiry/single-use, rate limiting, and a
preserved manual break-glass. It adds no new Python dependency and no privileged
networking — fully compatible with the hardened pod.

**OpenVPN Integration.** Lets MagikUp reach PostgreSQL endpoints that are only
routable across an OpenVPN tunnel — the direct analog of the existing AWS SSM
jump-host feature. It adds an `[openvpn:<name>]` encrypted-secret config family, a
12th `vpn_profile` field on `[endpoints]` (mutually exclusive with `use_ssm`), a
tunnel-manager + `ensure_vpn_connected` / resolve pair mirroring `ssm_tunnel.py`, a
new admin "VPN" tab, and admin-only `/api/config/openvpn*` routes with masked
secrets. The crux is Kubernetes: an OpenVPN client needs `/dev/net/tun` +
`NET_ADMIN`, which collides head-on with the hardened pod (`runAsNonRoot`,
`readOnlyRootFilesystem`, `drop: [ALL]`). The spec analyzes options honestly —
**A** VPN sidecar (recommended if built), **B** external gateway, **C**
hostNetwork (rejected), **D** declare out of scope (zero regression, no feature) —
and this single decision gates whether any code is written.

---

## 2. Dependency graph

```
                 ┌─────────────────────┐
                 │  Email Sending      │   foundation: send_email(), [smtp]
                 │  (SMTP)             │   config, User.email field
                 └──────────┬──────────┘
                            │ HARD dependency
                            │ (cannot ship without it)
                            ▼
                 ┌─────────────────────┐
                 │  Password Recovery  │   consumes send_email();
                 │  ("Forgot password")│   adds tokens, reset pages
                 └─────────────────────┘

                 ┌─────────────────────┐
                 │  OpenVPN Integration│   ORTHOGONAL — no dependency on
                 │  (infra / VPN)      │   the email features; shares only
                 └─────────────────────┘   the Fernet/config/audit primitives
```

- **Password Recovery HARD-depends on Email Sending.** No SMTP code exists today;
  the reset flow is unusable without `send_email(...)` and the `[smtp]` config.
  Email Sending must land first. (Both features touch `User.email`; Email Sending
  adds the backing field, so building it first also settles that overlap.)
- **OpenVPN is orthogonal infrastructure.** It shares no functional dependency
  with the email features — only the common building blocks (Fernet
  encrypt/decrypt, config triad pattern, `require_admin`, audit log, NetworkPolicy
  egress). It can be scheduled independently, before, after, or never, without
  affecting the email track.

---

## 3. Effort vs. value

| Feature | Effort | Value | Risk | Notes |
|---|---|---|---|---|
| Email Sending (SMTP) | **S–M** | **High (enabling)** | **Low** | Zero new deps, no k8s hardening change; unblocks recovery + future alerts. Risk is front-loaded on TLS/error-mapping + the admin card. |
| Password Recovery | **M** (on top of email) | **High (user-facing)** | **Medium** | No new deps, no privileged networking. Risk is security correctness: enumeration, token single-use, rate limiting, lockout interaction. |
| OpenVPN Integration | **L** (or ~0 for Option D) | **Medium / niche** | **High** | App layer is S–M/M; the sidecar + PodSecurity + `NET_ADMIN` hardening regression dominates cost and risk. Enforced `restricted` PodSecurity blocks Option A outright. |

Effort legend: S small, M medium, L large.

---

## 4. Recommended implementation order

**1 → Email Sending (SMTP) first.**
It is the smallest true unlock: low risk, no dependency change, no hardening
impact, and it is the hard prerequisite for password recovery (and later
schedule-failure alerts). Delivering it establishes `send_email(...)`, the
encrypted `[smtp]` section, and the `User.email` field that the next feature
depends on. Highest leverage per unit of effort.

**2 → Password Recovery second.**
Directly consumes the email foundation from step 1 and is the highest-value
user-facing outcome (self-service reset, lockout self-recovery, no admin
hand-editing `users.json`). Incremental effort is M, with no new dependencies and
no securityContext impact. Sequencing it immediately after email keeps momentum on
the shared `User.email` work.

**3 → OpenVPN Integration last — and gated on an explicit decision.**
It is orthogonal, so it never blocks the email track and loses nothing by waiting.
It is also the largest, riskiest item because of the `NET_ADMIN` / `/dev/net/tun`
hardening trade-off. Do **not** start coding until the user confirms the
deployment shape: **A (sidecar)**, **B (external gateway)**, or **D (decline)**.
If the target namespace enforces the `restricted` Pod Security Standard, Option A
is blocked and the realistic choices are B or D. Under Option D the effort
collapses to documentation only.

### MVP first

Ship **Email Sending (SMTP) as the standalone MVP**: the `[smtp]` config card, the
`send_email` module, and the "Send test email" button proving end-to-end delivery.
It is independently valuable (validated mail plumbing, admin-configurable relay)
and is the foundation everything else builds on. It can be trimmed further for a
first cut — defer the user `email` UI to the password-recovery consumer, and defer
the `security=none` / insecure-TLS escape hatches — while still delivering a
working, testable send path. Password Recovery is the natural fast-follow once the
MVP is in place. OpenVPN stays out of the MVP entirely.

---

## 5. Cross-cutting concerns

These span all three specs and should be handled consistently.

**Secret handling.** All secrets follow the existing Fernet / `ENC:` pattern
(`encrypt_password` / `decrypt_password`), with the durable key on the config PVC
(`config/.encryption_key`, chmod 0600) seeded from the `ENCRYPTION_KEY` Secret.
Encrypted at rest: the SMTP password; OpenVPN `auth_password`, keys, and
(recommended) the whole `.ovpn` body. GET responses mask secrets (`"***"` for
OpenVPN, `"***"`/empty for SMTP), and blank/`"***"` submission means "keep
existing" (non-destructive edit). By design, `email` addresses and reset tokens are
**not** secrets and are not encrypted. Export/import round-trips `ENC:` tokens,
which only decrypt on an instance sharing the same Fernet key.

**Kubernetes securityContext.** Email Sending and Password Recovery are pure
userspace and keep the hardened pod fully intact (`runAsNonRoot`, `runAsUser 1000`,
`readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`,
`capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`). OpenVPN is the sole
exception: it needs `NET_ADMIN` + `/dev/net/tun`, forcing the sidecar-scoped
elevation (Option A) or the whole feature being declined. PodSecurity admission is
the gate — enforced `restricted` rejects `NET_ADMIN` and requires a namespace label
change or exception from platform owners.

**Egress.** All three add outbound egress that overlay NetworkPolicies must allow
(the base excludes NetworkPolicy): SMTP submission on 587 (STARTTLS) / 465
(SSL/TLS), occasionally 25/2525, plus DNS; OpenVPN to its server port (commonly
UDP 1194 or a configured TCP port). Password Recovery inherits the SMTP egress via
its dependency. Overlays that restrict egress must add these rules or connections
time out. OpenVPN additionally risks route/CIDR overlap with cluster/pod/DNS
ranges — must be validated per profile.

**Audit.** All admin-config and security-relevant actions append to the existing
audit log via `audit_log(event, username, ip, details)`. Email: SMTP config
save/test events (never logging the password or AUTH exchange). Password Recovery:
`password_reset_requested` (submitted identifier), `password_reset_email_sent`,
`password_reset_completed`, `password_reset_failed` (reason category), plus a
called-out privacy note that submitted (possibly third-party) identifiers land in
`audit.log`. OpenVPN: profile create/update/delete/connect/disconnect/test. Across
all three, log event metadata and status codes — never secrets, credentials, or
message bodies.
