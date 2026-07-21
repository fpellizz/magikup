# Functional Specification — OpenVPN Integration

**Product:** MagikUp
**Baseline version:** v4.2.0
**Status:** DRAFT — functional specification only (no implementation, no code changes)
**Author:** spec-authoring pass
**Date:** 2026-07-21

---

## 0. Intent disambiguation

"OpenVPN integration" is ambiguous. Three plausible readings:

- **(a) — PRIMARY / RECOMMENDED.** MagikUp reaches **database endpoints that are only reachable across an OpenVPN tunnel**. This is the direct analog of the existing AWS SSM jump-host feature (`use_ssm` + `jumphost_alias` on an endpoint, `app/ssm_tunnel.py`, `ensure_tunnel_sync` / `resolve_endpoint_connection` in `app/main.py`). The feature would add OpenVPN **profiles** as a new connectivity provider, per-endpoint association to a profile, connection lifecycle/health/reconnect, and host/port resolution through the tunnel. **This document specs (a) in depth.**

- **(b) — OUT OF SCOPE.** MagikUp provisions/manages an OpenVPN **server** or issues client profiles/certificates. This is a PKI + server-lifecycle product in its own right, unrelated to MagikUp's "operate a Postgres fleet" mission. Explicitly declined below.

- **(c) — OUT OF SCOPE (deploy concern, not app feature).** Fronting the MagikUp UI itself behind a VPN. This is an infrastructure/ingress decision (put the pod behind a VPN-gated Service/Ingress or a private network). It needs no application code and is a Kubernetes/network topic, not a feature. Declined below.

> **Critical up-front warning.** Unlike SSM (a pure userspace TCP-forwarding subprocess needing **no** kernel networking privilege), an in-process OpenVPN client requires a `tun` device and `NET_ADMIN`. This collides head-on with MagikUp's locked-down pod (`runAsNonRoot`, `runAsUser: 1000`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`). **This is the single highest-effort, highest-risk feature of the current backlog.** The Kubernetes section (§8) analyzes the options honestly; the Effort section (§10) rates it **L (Large)**.

---

## 1. Purpose & user stories

### Purpose
Let MagikUp connect to PostgreSQL endpoints whose network path is only available through an OpenVPN tunnel (e.g. a customer or partner network that publishes an `.ovpn` profile), without exposing those databases publicly and without manual per-session VPN wrangling. This complements — it does not replace — the SSM jump-host path. Some fleets have AWS SSM; others hand out `.ovpn` files.

### User stories
- **US-1 (admin).** As an admin, I can add an OpenVPN **profile** (name + `.ovpn` config + any credentials/certs) on an Admin "VPN" tab, so that endpoints behind that VPN become reachable.
- **US-2 (admin).** As an admin, I can associate a database endpoint with an OpenVPN profile (analogous to choosing a jump host), so its traffic is routed through that tunnel.
- **US-3 (admin).** As an admin, I can see each profile's live connection **status** (connected / connecting / down / last error, assigned local address) and **connect / disconnect / test** it, mirroring the jump-host and remote-storage "Test" affordances.
- **US-4 (operator).** As an operator, when I run a query/backup/restore against a VPN-associated endpoint, the tunnel is transparently ensured up first (like `ensure_tunnel_sync`) and I get a clear error if it cannot be established — I never touch the VPN directly.
- **US-5 (admin).** As an admin, my OpenVPN credentials and private keys are **encrypted at rest** (Fernet, `ENC:` prefix) exactly like S3 / fileshare / filebrowser secrets, and masked (`"***"`) in API GET responses.
- **US-6 (admin).** As an admin, VPN profile create/update/delete/connect/disconnect events appear in the audit log (`audit_log`).
- **US-7 (admin).** As an admin, VPN profiles are included in config export/import so a MagikUp instance is reproducible.

---

## 2. Scope

### In scope (interpretation a)
- A new `[openvpn:<name>]` **encrypted-secret config section** family in `app/config.py`, modeled on the `[fileshare:*]` triad.
- Storage of the `.ovpn` profile body and any auth material (inline username/password, `auth-user-pass`, inline or referenced certs/keys, TLS auth key), with secrets Fernet-encrypted.
- A per-endpoint **connectivity selector** extending the pipe-delimited `[endpoints]` value with an OpenVPN profile reference — the OpenVPN analog of `use_ssm` + `jumphost_alias`.
- A tunnel manager analog (design only) — an "ensure profile connected" + "resolve endpoint connection through VPN" pair mirroring `ensure_tunnel_sync` / `resolve_endpoint_connection`.
- Admin UI: a new **VPN** tab on `templates/admin.html` (profiles CRUD + status), following the existing design system.
- Admin-role API endpoints for profile CRUD, connect/disconnect, status, and test.
- Kubernetes/deploy impact analysis and a recommended deployment shape.
- Failure modes, edge cases, security threats/mitigations, effort, and open questions.

### Out of scope
- Interpretation (b): provisioning/running an OpenVPN **server**, PKI/CA, certificate issuance, or generating client profiles.
- Interpretation (c): placing the MagikUp UI itself behind a VPN (pure infra/ingress).
- WireGuard, IPsec, SSH `-w` tun, or other VPN technologies (OpenVPN only).
- Per-user (non-admin) management of VPN profiles. Profiles are an admin-only, instance-wide resource, like AWS accounts and jump hosts.
- Split-DNS / name resolution *inside* the VPN beyond what is needed to reach the configured DB host:port (see Open Questions).
- Automatic import of `.ovpn` from a URL (paste/upload only in v1).

---

## 3. UX / UI

All new UI follows the existing design system: `.app-main` shell, `.card.config-card` with `.card-header`, `.btn.btn-sm.btn-primary` / `.btn-outline`, Bootstrap modals styled like `#addEndpointModal` / `#addUserModal`, `.table.table-hover`, `.badge-soft`, status dots `.dot / .dot-success / .dot-idle`, `.mono` for data, single violet accent (`#7c3aed` light / `#8b5cf6` dark), light+dark via `data-bs-theme`, tokens in `static/style.css`.

### 3.1 New Admin tab: "VPN"
Add one `nav-link` button to `#adminTabs` and one `.tab-pane fade` panel under `#adminTabContent`, using the identical markup pattern to the existing tabs (`endpoints`, `jumphosts`, `aws`, `remotestorage`, `settings`, `importexport`, `security`, `users`). Recommended insertion position: **immediately after `jumphosts`** (both are "connectivity" concepts), giving tab order `endpoints, jumphosts, vpn, aws, remotestorage, settings, importexport, security, users`. The last-selected-tab `localStorage` persistence already present handles the new tab automatically.

**Panel layout** (`#vpn-panel`):
- A `.card.config-card` titled "OpenVPN Profiles" with a `.btn.btn-sm.btn-primary` "Add Profile" in the `.card-header`.
- A `.table.table-hover` listing profiles, columns:
  - **Name** (`.mono`)
  - **Status** — status dot + label: `.dot-success` "Connected", `.dot-idle` "Idle/Disconnected", a warning-styled dot "Connecting", error-styled "Error". Show assigned tunnel address when connected.
  - **Auth type** — `.badge-soft` (e.g. `cert`, `user-pass`, `user-pass+cert`).
  - **Endpoints using it** — count badge (derived from `[endpoints]` references).
  - **Actions** — `Connect` / `Disconnect` (`.btn-outline`), `Test`, `Edit`, `Delete`.

### 3.2 Add/Edit Profile modal (`#addVpnProfileModal`)
Bootstrap modal, Admin-modal styling. Fields:
- **Profile name** — text, validated `^[a-zA-Z0-9_-]{2,50}$` (same rule as `validate_schedule_name`); disabled on edit.
- **`.ovpn` config** — a `<textarea class="mono">` (paste) plus an optional file `<input type="file" accept=".ovpn,.conf">` that populates the textarea client-side. Required.
- **Auth username** — text, optional (for `auth-user-pass` profiles).
- **Auth password** — `<input type="password">`, optional. **Encrypted at rest.**
- **Client certificate / private key / TLS-auth key** — either inline in the `.ovpn` or separate `mono` textareas. Any private key material is **encrypted at rest**. On edit, secret fields render as `"***"` placeholders and are only overwritten if the admin types a new value (same non-destructive pattern as AWS/S3/fileshare edit).
- **Auto-connect** — checkbox (`.form-check`): whether MagikUp should bring this profile up eagerly at startup vs. lazily on first endpoint use (default: lazy, matching SSM behavior).
- **Notes** — optional free text.

Footer: `Cancel` (`.btn-outline`) + `Save` (`.btn-primary`). A `Test connection` button may sit next to Save (calls the test endpoint, shows inline result), matching the remote-storage "Test" pattern.

### 3.3 Endpoint modal change (existing `#addEndpointModal`)
The endpoint add/edit modal currently exposes SSM controls (`use_ssm` toggle + `jumphost_alias` select). Extend it with a **Connectivity** selector so the two mechanisms are mutually exclusive and explicit:
- A single "Connectivity" dropdown / segmented control: `Direct` | `AWS SSM jump host` | `OpenVPN profile`.
- When `OpenVPN profile` is chosen, reveal a profile `<select>` populated from the VPN profiles list.
- This is the UI expression of the data-model rule in §4.3 (mutual exclusivity of `use_ssm` and `vpn_profile`).

> Note: this modifies an existing template at implementation time. This spec only *describes* the change; no template is edited as part of writing this spec.

### 3.4 Status surfacing elsewhere
The existing endpoint "connection status" surface (see `app/main.py` ~line 3047–3071, which reports SSM tunnel status) should gain an OpenVPN equivalent message, e.g. `"OpenVPN profile '<name>' connected -> <host>:<port> reachable"`. No new page; this reuses the existing status JSON shape.

### 3.5 No login-page change
`templates/login.html` is untouched. (Contrast: a future password-reset feature would touch it; OpenVPN does not.)

---

## 4. Configuration & data model

### 4.1 New INI section family `[openvpn:<name>]`
Modeled precisely on the `[fileshare:*]` encrypted-secret triad in `app/config.py` (dataclass + `get_*` decrypt-on-read + `save_*` encrypt-on-write + `delete_*`).

Proposed dataclass (in-memory, plaintext secrets):

```
@dataclass
class OpenVPNProfile:
    name: str
    ovpn_config: str            # the .ovpn body (may itself contain inline keys)
    auth_username: str = ""
    auth_password: str = ""     # SECRET — Fernet encrypted at rest
    client_key: str = ""        # SECRET — private key PEM, if separate from ovpn
    tls_auth_key: str = ""      # SECRET — ta.key, if separate
    auto_connect: bool = False
    notes: str = ""
```

Section keys written per profile (one section per profile, prefix `openvpn:`):

| INI key | Type | Encrypted? | Notes |
|---|---|---|---|
| `ovpn_config` | multiline str | **Yes (recommended)** | See §4.2 on multiline + `%` handling |
| `auth_username` | str | No | |
| `auth_password` | str | **Yes** — `ENC:` | via `encrypt_password` |
| `client_key` | str | **Yes** — `ENC:` | private key material |
| `tls_auth_key` | str | **Yes** — `ENC:` | |
| `auto_connect` | bool | No | `str(x).lower()`, read `getboolean(fallback=False)` |
| `notes` | str | No | |

Helper functions to add (mirror `get_fileshare_configs` / `save_fileshare_config` / `delete_fileshare_config`):
- `get_openvpn_profiles() -> Dict[str, OpenVPNProfile]` — iterate `config.sections()` filtering `startswith("openvpn:")`, **decrypt** each secret via `decrypt_password(...)` on read.
- `get_openvpn_profile(name) -> Optional[OpenVPNProfile]`.
- `save_openvpn_profile(profile)` — `read_config()` → `add_section` if missing → `config.set(...)` per field → `config.set(section, 'auth_password', encrypt_password(profile.auth_password))` (and same for `client_key`, `tls_auth_key`) → `write_config`.
- `delete_openvpn_profile(name)` — `remove_section` + `write_config`.

**Reserved prefix + name validation.** Because `<name>` is user-supplied and used verbatim in the section key, add `"openvpn:"` to `_RESERVED_PREFIXES` (config.py ~line 801) and validate the name with the existing pattern (`^[a-zA-Z0-9_-]{2,50}$`, reserved-prefix collision check), exactly like `validate_schedule_name`.

**Defaults/documentation.** Add a documented, commented `[openvpn:example]` block to `get_default_config()` (the template string) explaining the format, next to where the `[endpoints]` format is documented (~line 309).

### 4.2 Fernet encryption & the `.ovpn` body
- Reuse the existing durable-key mechanism unchanged: `_get_or_create_encryption_key()` (key on config PVC `config/.encryption_key`, seeded from `ENCRYPTION_KEY` Secret), `_get_fernet()`, `encrypt_password` / `decrypt_password`, `ENCRYPTED_PREFIX = "ENC:"`.
- **Recommendation:** encrypt the *whole* `ovpn_config` body too (not only the separate secret fields), because many `.ovpn` files embed `<key>...</key>` and `<tls-auth>...</tls-auth>` inline. Treating `ovpn_config` as an encrypted field is the safest default. This works with the existing helpers (`encrypt_password` is content-agnostic).
- **`configparser` multiline + `%` caveat.** `read_config()` already uses `interpolation=None`, so literal `%` in certs/config is safe. Multiline INI values are supported via indentation continuation, BUT round-tripping a raw PEM/`.ovpn` through `configparser` is fragile (leading whitespace, blank lines). **Encrypting `ovpn_config` sidesteps this entirely**: the stored value becomes a single-line `ENC:<token>` with no newlines. This is a concrete reason to prefer encrypting the body.
- **Alternative considered:** store each profile's `.ovpn` as a **separate file** on the config PVC (e.g. `config/openvpn/<name>.ovpn`, chmod 0600) with only a filename reference in the INI. Cleaner for large configs and for handing the file to a subprocess/sidecar, but introduces a second on-disk secret store that the export/import path and Fernet-at-rest guarantee must also cover. **Decision deferred to Open Questions (Q3).** Default recommendation: single encrypted INI field for v1 simplicity.

### 4.3 Per-endpoint association (the SSM analog)
The `[endpoints]` section stores each DB as one pipe-delimited value parsed positionally in `get_database_configs()` (config.py ~line 989) and rebuilt in `save_database_config` (~line 1072):

```
host|port|username|ENC:password|use_ssm|jumphost_alias|read_only|backup_use_replica|replica_host|pg_version|sslmode
```

Add a **12th field** `vpn_profile` (empty string when not used), appended at the end for backward compatibility:

```
...|sslmode|vpn_profile
```

Parsing must be defensive (as the existing parser already is for optional trailing fields): `vpn_profile = parts[11].strip() if len(parts) > 11 else ""`. Add `vpn_profile: str = ""` to the `DatabaseConfig` dataclass (config.py ~line 40, alongside `use_ssm` / `jumphost_alias`) and to the corresponding Pydantic models in `app/main.py` (~lines 204, 223).

**Mutual-exclusivity rule (validated on save):** an endpoint may use **at most one** of `use_ssm` or `vpn_profile`. If both are set, reject on save (400) — the UI enforces this via the single "Connectivity" selector (§3.3). If `vpn_profile` is set it must reference an existing `[openvpn:<name>]` (validate like the existing `jumphost_alias` existence check at main.py ~line 995).

### 4.4 users.json
**No change.** VPN profiles are an admin-only instance resource; there is no per-user VPN field. (The `User` dataclass and users.json remain as-is.)

### 4.5 Runtime connection state (not persisted)
A VPN tunnel manager analog holds **ephemeral** state only (in memory, like `SSMTunnelManager` / `tunnel_manager`): per-profile process handle / connection object, status, assigned local address/interface, last error, last-connected timestamp. Nothing here is written to the INI. Any scratch files the client needs (e.g. a materialized `.ovpn`, a management socket) live under `/tmp` (the existing emptyDir) or the config PVC, never the read-only root FS.

---

## 5. API endpoints

All under the existing config-API convention, all `Depends(auth.require_admin)` (admin-only, like every other `/api/config/*` route). Pydantic `BaseModel` request bodies. Secrets **masked as `"***"`** in every GET response (replicate `api_get_aws_accounts` masking, main.py ~line 1858).

| Method | Path | Role | Request body | Response |
|---|---|---|---|---|
| GET | `/api/config/openvpn` | admin | — | List of profiles; secrets masked `"***"`; each with derived `status` and `endpoints_using` count |
| GET | `/api/config/openvpn/{name}` | admin | — | Single profile; `ovpn_config` presence indicated but secret parts masked |
| POST | `/api/config/openvpn` | admin | `OpenVPNProfileModel` (name, ovpn_config, auth_username, auth_password?, client_key?, tls_auth_key?, auto_connect, notes) | `{ "success": true, "name": ... }`; on edit, `"***"` secret fields are preserved (not overwritten) |
| DELETE | `/api/config/openvpn/{name}` | admin | — | `{ "success": true }`; **409/400 if any endpoint still references it** (referential-integrity guard, analogous to protecting a jump host in use) |
| POST | `/api/config/openvpn/{name}/test` | admin | — | Attempt to establish the tunnel (bounded timeout), report reachability of a probe target; tear down if it was not already up. `{ "success": bool, "message": str }` |
| POST | `/api/config/openvpn/{name}/connect` | admin | — | Bring profile up (idempotent). `{ "success": bool, "status": ..., "message": str }` |
| POST | `/api/config/openvpn/{name}/disconnect` | admin | — | Tear profile down. `{ "success": bool }` |
| GET | `/api/config/openvpn/{name}/status` | admin | — | `{ "status": "connected|connecting|idle|error", "local_address": ..., "last_error": ..., "connected_since": ... }` |

**Endpoint status route:** extend the existing endpoint connection-status response (main.py ~line 3047) to include OpenVPN messaging when `endpoint.vpn_profile` is set, symmetric to the current `use_ssm` branch.

**Export/import:** `[openvpn:*]` sections are naturally included by `get_full_config_content()` / `import_config_content()` since those operate on the whole INI. **Caveat:** exported config contains `ENC:` secrets that are only decryptable with the *same* Fernet key — document that exporting VPN profiles between instances requires transferring the encryption key, exactly as with existing encrypted sections. No change to the required-sections validation (`['settings','auth']`).

---

## 6. Resolution & lifecycle (design, mirrored on SSM)

Two functions analogous to the SSM pair, plus a manager analog. **Design only; not implemented here.**

- **`ensure_vpn_connected(endpoint)`** — analog of `ensure_tunnel_sync` (main.py ~425). If `endpoint.vpn_profile` is empty, no-op. Otherwise look up `cfg.get_openvpn_profile(endpoint.vpn_profile)`; if the profile is not already connected, bring it up (subprocess/sidecar signal — see §8), wait (bounded) for the tunnel/route to be ready, else raise 400 with a clear message (mirroring the "Jump host not found / no tunnel" errors).
- **`resolve_endpoint_connection(endpoint)`** — the existing function (main.py ~404) gains a third branch. Today: `use_ssm` → `("localhost", local_port)`; else `(host, port)`. Add: if `endpoint.vpn_profile` → return the **real `(host, port)`** unchanged, because a real VPN gives you routable access to the target host directly (no port rewrite). The difference from SSM is important: **SSM forwards to `localhost:<local_port>`; OpenVPN makes the true `host:port` routable.** So resolution for VPN endpoints returns the true address, but only *after* `ensure_vpn_connected` has succeeded. This asymmetry must be explicit in the implementation.
- **Call sites.** All ~20 DB operations already call `ensure_tunnel_sync(endpoint)` then `resolve_endpoint_connection(endpoint)` (main.py ~1030–1542). The natural design is to make `ensure_tunnel_sync` dispatch to the VPN path when `vpn_profile` is set (or add a sibling `ensure_connectivity(endpoint)` that fans out to SSM or VPN), so the call sites need minimal change.
- **Health & reconnect.** The manager should track liveness (management interface / process exit / periodic probe of the target host:port) and support reconnect with backoff. Because a single VPN profile may serve many endpoints, connections are **shared and reference-nothing-per-endpoint** (like a jump-host tunnel keyed by target); idle teardown policy is an open question (Q5).
- **`_validate_remote_target` analog.** SSM validates the remote host charset (`^[A-Za-z0-9._-]+$`) before injecting into the session `--parameters`. Any value passed to the OpenVPN client process (profile name, materialized file path, management commands) must be similarly validated/escaped to prevent command/argument injection.

---

## 7. Security & privacy

| Threat | Mitigation |
|---|---|
| VPN credentials / private keys leak from config at rest | Fernet-encrypt `auth_password`, `client_key`, `tls_auth_key`, and (recommended) the whole `ovpn_config` body via the existing `encrypt_password`/`ENC:` mechanism; key durable on config PVC, chmod 0600. |
| Secrets echoed back through the API | Mask all secret fields as `"***"` in GET responses (replicate `api_get_aws_accounts`); non-destructive edit (blank/`"***"` = keep existing). |
| Command/argument injection via profile name or config into the VPN client process | Validate profile name (`^[a-zA-Z0-9_-]{2,50}$`, reserved-prefix check); validate/escape any value handed to the client subprocess (analog of `_validate_remote_target`); never shell-interpolate. |
| Privilege escalation via relaxed pod security to get `tun`/`NET_ADMIN` | See §8 — the recommended shape isolates the elevated capability to a **dedicated sidecar** rather than the app container; the hardening regression is called out explicitly, and the app container keeps `drop: [ALL]`. |
| A materialized `.ovpn`/key written to disk for the client persists in plaintext | Write only to `/tmp` (emptyDir, ephemeral) or a private path; chmod 0600; delete after use; never to backups/logs PVCs; never logged. |
| Secrets in logs (client is verbose) | Set OpenVPN verbosity low; scrub/allowlist what the manager logs; never log `auth_password`/keys; audit-log only event metadata. |
| Whole-config export carries encrypted VPN secrets to another instance | Documented: `ENC:` tokens are only decryptable with the matching Fernet key; exporting profiles requires transferring the key deliberately. |
| Deleting a profile silently breaks endpoints | Referential-integrity guard on DELETE (409 if referenced), plus "endpoints using" count in the UI. |
| A tunnel exposes far more of the remote network than a single DB | Note in docs: OpenVPN grants route-level access (broad) vs. SSM port-forward (single host:port, narrow). This is an inherent, larger blast radius. Recommend routing scoping where the profile supports it; flag as Open Question Q4. |
| Audit gap | Log profile create/update/delete/connect/disconnect/test via `audit_log(event, username, ip, details)` (NDJSON), consistent with existing admin actions. |

Privacy: VPN profiles are instance-wide admin data; no PII beyond an optional auth username. No new user-data collection.

---

## 8. Kubernetes / deploy impact — the central problem

**This is the hard part and the reason the feature is rated L.**

### 8.1 Why it conflicts
An OpenVPN client needs:
- Access to `/dev/net/tun` (a device node), and
- `CAP_NET_ADMIN` to create the `tun` interface and install routes, and
- (typically) the ability to write resolv.conf / run up/down scripts.

MagikUp's pod today (`kubernetes/template/deployment.yaml`) is deliberately the opposite:
- Pod: `runAsNonRoot: true`, `runAsUser/Group: 1000`, `fsGroup: 1000`, `seccompProfile: RuntimeDefault`.
- App + init container: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`.
- `automountServiceAccountToken: false`; writable paths only via mounts (`/backups`, `/app/config`, `/app/logs`, `/tmp`).
- `replicas: 1`, `strategy: Recreate`.

Running the VPN client **inside the app container** would require adding `NET_ADMIN`, mounting the tun device, and almost certainly relaxing `readOnlyRootFilesystem` and `runAsNonRoot` — a **material hardening regression across the whole app**. Not recommended.

### 8.2 Options (honest trade-offs)

**Option A — Sidecar container with its own elevated securityContext + shared pod network. (RECOMMENDED if the feature is built.)**
- A second container in the same pod runs the OpenVPN client with `securityContext: { capabilities: { add: [NET_ADMIN] }, allowPrivilegeEscalation: true }`, its own (non-read-only) root or a writable emptyDir, and a mounted `/dev/net/tun` (device plugin or a small privileged shim). Because containers in a pod **share the network namespace**, the tun interface and routes the sidecar creates are visible to the app container — the app can reach VPN-only DB hosts directly, *without* the app container gaining any capability.
- The app container keeps `drop: [ALL]`, `readOnlyRootFilesystem: true`, non-root. The blast radius of the elevated capability is confined to the sidecar.
- **Cost:** the pod is no longer uniformly hardened; the sidecar is a new image to build/scan/maintain; the app must signal the sidecar which profile to bring up (shared volume drop-file, a tiny local management API, or the OpenVPN management socket on a shared emptyDir). Multiple profiles = either multiple sidecars or one sidecar multiplexing (adds complexity). `runAsNonRoot: true` at pod level may need to be dropped or scoped per-container; verify cluster PodSecurity admission (`restricted` profile will reject `NET_ADMIN` — likely needs a namespace at `baseline`/`privileged` or an exception).
- **This is the standard "vpn sidecar" pattern and the least-bad option.**

**Option B — Gateway / router pod outside MagikUp.**
- Run the OpenVPN client in a **separate deployment** (or a node-level gateway) that establishes the tunnel and advertises routes; MagikUp connects to DB hosts via that gateway (e.g. by routing, a NetworkPolicy-permitted egress, or the DB host resolving to a service that egresses through the gateway).
- MagikUp's pod stays **completely unmodified and fully hardened**. Cleanest security posture.
- **Cost:** MagikUp no longer "owns" the VPN — profile CRUD in the UI would only be meaningful if MagikUp can push config to the gateway (extra control channel), otherwise the VPN tab becomes read-only/status-only and the profiles live elsewhere. Weakens the product story (US-1/US-2). Best when ops already run such a gateway.

**Option C — Host networking / host routing.**
- Establish the tunnel on the node and use `hostNetwork`. Rejected: `hostNetwork` + node-level routing is a large security and multi-tenancy regression, incompatible with the hardened posture and with running multiple instances.

**Option D — Declare OpenVPN out of scope for the hardened pod (status quo + guidance).**
- Do **not** run any VPN in-cluster. Document that VPN-only endpoints must be reached via a network path the cluster already has (peering, a gateway you run, or SSM where available). MagikUp gains no VPN feature; the pod stays hardened.
- **Cost:** no feature. But zero security regression and zero maintenance. **This is the honest fallback and should be presented to the user as a real choice.**

### 8.3 Additional deploy impacts (any option that runs a client in-cluster)
- **Egress:** new outbound to the VPN server on its port (commonly UDP `1194`, or a configured TCP port). Any NetworkPolicy overlay must permit it (base excludes NetworkPolicy; overlays add it).
- **Secret:** no new *env* Secret required — the `.ovpn`/keys live Fernet-encrypted in the config PVC like other secrets. The materialized plaintext for the client goes to an ephemeral emptyDir/`/tmp`.
- **Image:** a sidecar adds a new image (`openvpn` client) to build, scan, and version alongside `ghcr.io/fpellizz/magikup:4.2.0`.
- **`Recreate` / single replica:** fine — one VPN client per pod matches the singleton `tunnel_manager` model. Restarts drop tunnels (acceptable; they re-establish lazily, like SSM).
- **PodSecurity admission:** adding `NET_ADMIN` will be rejected under the `restricted` Pod Security Standard. Requires namespace label change or admission exception — call out to platform owners.

---

## 9. Failure modes & edge cases

- **VPN server unreachable / auth fails.** `ensure_vpn_connected` times out → 400 with a clear message at every DB call site; profile status `error` + `last_error` surfaced in the VPN tab. (Mirrors SSM "no tunnel" 400.)
- **Profile deleted while endpoints reference it.** DELETE returns 409 (referential guard); UI shows usage count.
- **Both `use_ssm` and `vpn_profile` set.** Rejected on endpoint save (400); UI prevents via single selector.
- **Sidecar down but app up (Option A).** DB ops fail fast; status shows disconnected; reconnect with backoff; consider a readiness signal.
- **Tunnel flaps mid-operation** (e.g. mid-backup). Long-running `pg_dump`/`pg_restore` may break; document that VPN reliability directly affects long ops. Reconnect does not resume an in-flight dump.
- **Overlapping route/CIDR conflicts.** A profile that pushes routes overlapping cluster/pod CIDRs can break in-cluster connectivity (including to the DB or to the K8s API/DNS). High-risk; must be tested per profile. Open Question Q4.
- **DNS inside the VPN.** If the DB host is only resolvable via a DNS server pushed by the VPN, MagikUp must use the resolved address; note that push-DNS handling is client/OS-specific and may not apply in the sidecar model. Q6.
- **`configparser` round-trip corruption of raw `.ovpn`.** Mitigated by encrypting the body (single-line `ENC:` token). If stored plaintext, blank lines/indentation can corrupt the file — a reason not to store it plaintext.
- **Large `.ovpn`/cert bodies.** INI value size is bounded by the 1Gi config PVC; fine, but very large values bloat config.ini and every export. The separate-file storage alternative (§4.2) mitigates.
- **Key rotation.** Rotating the Fernet key re-encrypts on next save (existing `/api/encrypt-passwords` flow); ensure VPN fields participate.
- **Concurrent connect requests** for the same profile. Manager must be idempotent (single shared connection), like the SSM manager reusing an existing tunnel.
- **Test connection side effects.** `test` may transiently bring the tunnel up; must not disrupt an already-connected profile in use by live endpoints (only tear down what it started).

---

## 10. Effort estimate

**Overall: L (Large).** The application-layer work is moderate; the deployment/security work is what makes it large and risky.

| Area | Size | Notes |
|---|---|---|
| Config layer (`[openvpn:*]` triad, dataclass, reserved prefix, defaults, endpoint 12th field) | **S–M** | Direct copy of the `[fileshare:*]` pattern + one pipe-field addition. Well-trodden. |
| API endpoints (CRUD, connect/disconnect, status, test, masking, referential guard) | **M** | Standard `require_admin` routes + Pydantic models; mirrors existing config APIs. |
| Tunnel manager analog + `ensure_vpn_connected` / resolve branch + call-site dispatch | **M** | Analogous to `ssm_tunnel.py` + `ensure_tunnel_sync`, but process/interface lifecycle & health/reconnect are genuinely fiddly. |
| Admin UI (VPN tab, modal, endpoint connectivity selector, status dots) | **M** | Follows the design system; endpoint modal edit adds coupling. |
| **Kubernetes / security (sidecar image, securityContext scoping, tun device, PodSecurity, NetworkPolicy egress)** | **L** | The dominant cost & risk; hardening regression to design and justify; new image to maintain; cluster admission changes. |
| Security review, docs, testing (tunnel flaps, route conflicts) | **M** | Higher than usual due to networking blast radius. |

If the user chooses **Option D (out of scope for the hardened pod)**, effort collapses to **~0 code / S docs** — hence the disambiguation matters enormously to sizing.

---

## 11. Open questions / decisions for the user

1. **Interpretation confirmation.** Confirm this is interpretation (a) — reach VPN-only DB endpoints — and that (b) server/PKI provisioning and (c) fronting the UI are out of scope. *(Recommended: yes.)*
2. **Build vs. decline given the K8s cost.** Given §8, is the hardening trade-off acceptable? Choose the deployment shape: **A (sidecar, recommended)**, **B (external gateway)**, or **D (declare out of scope, no code)**. This decision gates whether the feature is built at all.
3. **`.ovpn` storage.** Encrypted single INI field (recommended, simplest, avoids `configparser` newline issues) vs. separate per-profile file on the config PVC (cleaner for large configs / handing to a sidecar). 
4. **Route scope & blast radius.** Are the target VPNs expected to push broad routes? Do we need to constrain/whitelist routes to just the DB host(s), and how do we prevent CIDR overlap with cluster/pod/DNS ranges?
5. **Connection lifecycle policy.** Eager `auto_connect` at startup vs. lazy-on-first-use (recommended: lazy, matching SSM). Idle-teardown timeout? Shared single connection per profile confirmed?
6. **DNS inside the tunnel.** Do any target DBs require VPN-pushed DNS to resolve, or are they always addressable by IP / externally-resolvable name? This affects whether the sidecar model is sufficient.
7. **Multiple concurrent profiles.** Must one pod hold several VPNs up at once (multiple sidecars / multiplexed client), or is a single active profile per instance acceptable for v1?
8. **PodSecurity / cluster policy.** Can the target namespace tolerate a container with `NET_ADMIN` (i.e. not enforced `restricted`)? If not, Option A is blocked and only B or D remain.
