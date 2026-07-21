# MagikUp - PostgreSQL Backup & Restore

A web application for PostgreSQL database backup, restore, and transfer operations. Supports both **direct connections** and **AWS SSM tunnel** connections through configurable jump hosts.

## Features

- **Backup** - Full or schema-level backups with advanced pg_dump parameters and real-time progress
- **Restore** - Restore from backup files with advanced pg_restore parameters, schema selection, table exclusion, role mapping, and TimescaleDB-aware mode
- **Transfer** - One-click database copy (backup + restore) between any endpoints
- **Query Editor** - Execute SQL queries directly on any endpoint with Ace editor, object browser, autocommit toggle, result export, query history, and contextual tooltips
- **Info Page** - Application info, version history, technology stack, and documentation links (HTML manual, PDF download)
- **Dual Connection Mode** - Direct TCP or AWS SSM tunnel per endpoint
- **Jump Host Management** - Configure multiple EC2 jump hosts for SSM tunneling
- **File Manager** - Upload, download, and manage backup files (up to 5GB)
- **Real-time Progress** - WebSocket-based live output streaming
- **Operation History** - Audit trail with downloadable logs
- **Configuration Import/Export** - Single unified config file for easy portability
- **Multi-User Auth** - Three roles (Admin, Operator, Viewer) with granular permissions
- **Security Hardening** - Rate limiting, account lockout, password policy, audit log
- **Context Path / Reverse Proxy** - Deploy under a URL prefix (e.g., `/magikup`) via env var, config file, or Admin UI
- **Kubernetes Ready** - Full manifest set with Kustomize, PVCs, health checks, and ingress

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Browser (UI)                          │
│  Dashboard | Backup | Restore | Transfer | Query | Files | Admin│
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP / WebSocket
┌──────────────────────▼──────────────────────────────────┐
│                  FastAPI (main.py)                        │
│  Routes + WebSocket Handlers + Role-Based Auth           │
├──────────────┬───────────────────────┬──────────────────┤
│  config.py   │  backup_restore.py    │  ssm_tunnel.py   │
│  (INI file)  │  (pg_dump/restore)    │  (AWS SSM)       │
├──────────────┼───────────────────────┼──────────────────┤
│  auth.py     │  operation_logger     │  aws_service     │
│  (users/rbac)│  (audit trail)        │  (boto3)         │
├──────────────┼───────────────────────┼──────────────────┤
│  db_service  │  users.json           │  audit.log       │
│  (psycopg2   │  (user store)         │  (security log)  │
│   + queries) │                       │                  │
└──────┬───────┴───────────┬───────────┴────────┬─────────┘
       │                   │                    │
  Direct TCP          Log Files           SSM Tunnel
       │                   │              (port forward)
       ▼                   ▼                    ▼
  ┌─────────┐      ┌───────────┐      ┌──────────────┐
  │PostgreSQL│      │   /logs/  │      │ EC2 Jumphost │
  │ Database │      │   /backups│      │  (SSM Agent) │
  └─────────┘      └───────────┘      └──────┬───────┘
                                              │
                                       ┌──────▼───────┐
                                       │  RDS/Aurora   │
                                       │  PostgreSQL   │
                                       └──────────────┘
```

## Quick Start

### Docker

```bash
# Build and run with docker-compose
docker compose up -d

# Or build and run manually
docker build -t magikup:latest .
docker run -d \
  -p 8000:8000 \
  -v magikup-backups:/backups \
  -v magikup-config:/app/config \
  -v magikup-logs:/app/logs \
  --name magikup \
  magikup:latest

# Open browser
open http://localhost:8000
```

Default credentials: `admin` / `admin123` (change immediately via Admin > Users)

### Advanced Backup Parameters

The backup page includes an **Advanced Parameters** toggle that exposes fine-grained pg_dump options:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--large-objects` | On | Include large objects (BLOBs) in the dump |
| `--no-owner` | On | Skip ownership assignment commands |
| `--no-privileges` | On | Skip GRANT/REVOKE privilege commands |
| `--no-tablespaces` | On | Skip tablespace assignment commands |
| `--no-comments` | On | Skip COMMENT commands |
| `--data-only` | Off | Dump data only, no schema (DDL). Mutually exclusive with `--schema-only` |
| `--schema-only` | Off | Dump schema (DDL) only, no data. Mutually exclusive with `--data-only` |
| `--clean` | Off | Add DROP commands before CREATE |
| `--create` | Off | Include CREATE DATABASE command |
| `--exclude-table` | Off | Exclude tables matching a glob pattern (e.g. `temp_*`) |
| `--exclude-table-data` | Off | Exclude data for tables matching a glob pattern |

All parameters include tooltip popups with detailed descriptions. Table exclusion patterns support `*` and `?` wildcards and are validated against shell injection.

### Advanced Restore Parameters

The restore page includes an identical **Advanced Parameters** toggle exposing fine-grained pg_restore options:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--clean` | On | Drop database objects before recreating. Uses `--if-exists` to avoid errors |
| `--no-owner` | On | Skip ownership assignment commands |
| `--no-privileges` | On | Skip GRANT/REVOKE privilege commands |
| `--no-tablespaces` | On | Skip tablespace assignment commands |
| `--no-comments` | On | Skip COMMENT commands |
| `--data-only` | Off | Restore data only, no schema (DDL). Mutually exclusive with `--schema-only` |
| `--schema-only` | Off | Restore schema (DDL) only, no data. Mutually exclusive with `--data-only` |
| `--exit-on-error` | Off | Stop at first error instead of continuing |
| `--no-publications` | On | Skip publication definitions |
| `--no-subscriptions` | On | Skip subscription definitions |
| `--jobs N` | Off | Number of parallel restore processes (1-8) |
| `TimescaleDB` | Off | Run `timescaledb_pre_restore()` before and `timescaledb_post_restore()` after pg_restore; adds `--disable-triggers`. Requires superuser and the `timescaledb` extension on the target database |

**Exclusions:**

| Feature | Description |
|---------|-------------|
| Exclude schemas | One schema per line, passed as `--exclude-schema` to pg_restore |
| Exclude tables | Wildcard patterns (`*`, `?`) via TOC filtering (`pg_restore --list` + `--use-list`) |

Table exclusion uses TOC-based filtering since pg_restore has no native `--exclude-table` flag: the backup's table of contents is listed, matching entries are commented out, and the filtered TOC is passed via `--use-list`.

### Query Editor

The Query Editor page provides a full-featured SQL execution environment:

- **Ace Editor** with PostgreSQL syntax highlighting, auto-completion, and dark mode support
- **Object Browser** - Tree view of schemas, tables, views, functions, and indexes (lazy-loaded)
- **Connection Bar** - Select endpoint, database, role, timeout (5-300s), and row limit (100-10,000)
- **Autocommit Toggle** - Switch in the toolbar (next to History button) to enable/disable autocommit; reads default from the `[query]` section in `config.ini`
- **Results Table** - Sortable results with sticky headers, NULL highlighting, row count, and execution time
- **CSV Export** - Export query results to CSV
- **Query History** - Last 50 queries stored in browser localStorage
- **Keyboard Shortcuts** - Ctrl+Enter (Cmd+Enter on Mac) to execute
- **Contextual Tooltips** - Explanatory tooltips on all buttons, dropdowns, and form elements

Security: Queries run with a server-side `statement_timeout` and row limit. `SET ROLE` uses `sql.Identifier()` to prevent injection. The `execute_query` function in `db_service.py` accepts an `autocommit` parameter to control transaction behavior per query.

![Query Editor](docs/screenshots/08a_query_editor.png)

### Local Development

```bash
pip install -r requirements.txt
python run.py --reload
```

## Multi-User Authentication

### Roles

| Role | Description |
|------|-------------|
| **Admin** | Full access: manage users, endpoints, config; run all operations on all endpoints |
| **Operator** | Run backups/restores/transfers, SQL queries and tunnels — using the **stored endpoint credentials**. Grant it as you would database-operator access, not as a limited role. |
| **Viewer** | Read-only UI: view dashboard, endpoints and operation history. Cannot download backups or run operations. |

### Permissions Matrix

| Area | Admin | Operator | Viewer |
|------|-------|----------|--------|
| Dashboard (read) | Y | Y | Y |
| Run backup/restore/transfer | Y | Y | N |
| Execute SQL queries | Y | Y | N |
| Manage files (upload/delete) | Y | Y | N |
| View endpoints/operations | Y | Y | Y |
| Download backup files | Y | Y | N |
| Admin page (config/endpoints/users) | Y | N | N |
| Clear operations history | Y | N | N |
| Change own password | Y | Y | Y |
| Endpoint access | All | Assigned allowlist¹ | Assigned allowlist¹ |

¹ Each non-admin user has an **endpoint allowlist** (default `["*"]` = all). Restrict it per user in Admin > Users ("Allowed endpoints"). Scoped users only see and can act on their assigned endpoints; everything else returns 403. Admins always have access to all endpoints.

### Read-only Endpoints

An endpoint can be flagged **Read-only** (Admin > Endpoints). For such endpoints:

- The Query Editor connects with `default_transaction_read_only=on`, so any write statement is rejected by PostgreSQL itself.
- **Restore** and **transfer to** that endpoint are refused.
- Backups (which only read) still work.

Use it to expose production databases for safe querying without risk of accidental writes.

### User Management

Users are stored in `config/users.json` (auto-created on first startup from config.ini). Manage users from the Admin panel > Users tab:

- Create/edit/delete users
- Assign roles
- Enable/disable accounts
- Unlock locked accounts
- Reset passwords

### Admin Settings

The Admin > Settings tab includes configuration sections for:

- **Application Settings** - Backup directory, pg_dump/pg_restore paths, max upload size
- **Network** - Context path for reverse proxy deployment (overridden when `ROOT_PATH` env var is set)
- **AWS Configuration** - Access keys, region
- **Query Editor** - Default autocommit toggle for the Query Editor

### Security Features

- **Rate Limiting**: 5 failed login attempts per IP → blocked for 5 minutes
- **Account Lockout**: 10 failed login attempts for a user → account locked (admin can unlock)
- **Password Policy**: Minimum 8 characters, 1 uppercase, 1 lowercase, 1 digit
- **Audit Log**: All security events logged to `config/audit.log` (viewable in Admin panel)

## Configuration

All configuration is stored in `config/config.ini`. User accounts are in `config/users.json`.

### Configuration Sections

#### `[settings]` - Application Settings

| Key | Default | Description |
|-----|---------|-------------|
| `backup_dir` | `/backups` | Directory for backup files |
| `pg_dump_path` | `/usr/bin/pg_dump` | Path to pg_dump executable |
| `pg_restore_path` | `/usr/bin/pg_restore` | Path to pg_restore executable |
| `max_upload_size_gb` | `5` | Maximum upload file size in GB |
| `context_path` | (empty) | URL prefix for reverse proxy deployment (e.g., `/magikup`) |

#### `[auth]` - Authentication Settings

| Key | Default | Description |
|-----|---------|-------------|
| `session_timeout_minutes` | `480` | Session timeout (8 hours) |

#### `[aws]` - AWS Credentials (optional)

Only needed if any endpoint uses SSM tunneling.

| Key | Default | Description |
|-----|---------|-------------|
| `access_key_id` | (empty) | AWS Access Key ID |
| `secret_access_key` | (empty) | AWS Secret Access Key |
| `region` | `us-east-1` | AWS Region |

#### `[jumphosts]` - Jump Host Servers

EC2 instances with SSM agent for port forwarding.

```ini
[jumphosts]
# Format: alias = instance_id
production-jh = i-0123456789abcdef0
staging-jh = i-0abc123def456789
```

#### `[query]` - Query Editor Settings

| Key | Default | Description |
|-----|---------|-------------|
| `autocommit` | `false` | Default autocommit state for the Query Editor |

#### `[endpoints]` - Database Endpoints

```ini
[endpoints]
# Format: name = host|port|username|password|use_ssm|jumphost_alias|read_only
#
# Direct connection (no SSM):
local-db = 10.0.1.100|5432|postgres|mypassword|false||false
#
# SSM tunnel connection:
prod-aurora = aurora-cluster.rds.amazonaws.com|5432|admin|ENC:...|true|production-jh|false
#
# Read-only endpoint (query editor read-only; restore/transfer refused):
prod-readonly = reporting.rds.amazonaws.com|5432|readonly|ENC:...|false||true
```

| Field | Description |
|-------|-------------|
| `name` | Endpoint identifier (used in dropdowns) |
| `host` | Database host/endpoint |
| `port` | Database port (typically 5432) |
| `username` | PostgreSQL username |
| `password` | Password (plain or `ENC:` encrypted) |
| `use_ssm` | `true` or `false` - whether to use SSM tunnel |
| `jumphost_alias` | Reference to `[jumphosts]` key (empty if direct) |
| `read_only` | `true` or `false` (optional, default `false`) - blocks writes: query editor read-only, restore/transfer to it refused |

> Backward compatible: existing 6-field entries (without `read_only`) are read as `read_only = false`.

### Configuration Import/Export

From the Admin page:
- **Download**: Click "Download Configuration" to export `config.ini`
- **Import**: Upload a `config.ini` file to replace current config

This makes it easy to migrate settings between environments.

## Context Path / Reverse Proxy

MagikUp can be served under a URL prefix (e.g., `https://example.com/magikup`) instead of the root. This is useful when deploying behind a reverse proxy that routes multiple applications on different paths.

### Configuration Methods (priority order)

| Method | How to set | Takes effect |
|--------|-----------|--------------|
| **`ROOT_PATH` env var** (highest priority) | `ROOT_PATH=/magikup` | On container/process start |
| **`context_path` in config.ini** | `[settings]` section: `context_path = /magikup` | After restart |
| **Admin UI** | Settings > Network > Context Path | After restart |

When `ROOT_PATH` is set, it overrides the config file value. The Admin UI shows a badge indicating the override.

### Nginx Reverse Proxy Example

```nginx
location /magikup/ {
    proxy_pass         http://localhost:8000/;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Real-IP         $remote_addr;
    proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;

    # WebSocket support
    proxy_http_version 1.1;
    proxy_set_header   Upgrade    $http_upgrade;
    proxy_set_header   Connection "upgrade";

    # Large backup uploads
    client_max_body_size 5g;
}
```

Set `ROOT_PATH=/magikup` so the application generates correct URLs and redirects.

### Docker Compose Example

```yaml
services:
  magikup:
    image: magikup:latest
    ports:
      - "8000:8000"
    environment:
      - ROOT_PATH=/magikup
    volumes:
      - magikup-backups:/backups
      - magikup-config:/app/config
      - magikup-logs:/app/logs
```

### Health Check

The `/health` endpoint always responds at the root path (without the prefix), so Kubernetes probes and Docker health checks do not need to include the context path:

```
http://localhost:8000/health   # always works, regardless of ROOT_PATH
```

## SSM Tunnel Setup

### Prerequisites

1. **AWS CLI v2** installed in the container (included in Dockerfile)
2. **Session Manager Plugin** installed (included in Dockerfile)
3. **EC2 Instance** with SSM agent running (the jump host)
4. **IAM Permissions**: `ssm:StartSession` on the jump host instance
5. **Network**: Jump host must have network access to the target database

### How It Works

1. You configure a jump host (EC2 instance ID) in the Admin panel
2. You mark an endpoint as "Requires SSM Tunnel" and assign a jump host
3. When you start a backup/restore/transfer, the app automatically:
   - Opens an SSM port-forwarding session through the jump host
   - Routes the pg_dump/pg_restore connection through the tunnel
   - Reuses existing tunnels if one is already active
4. The tunnel stays alive until stopped or the pod restarts

### Network Flow

```
App Pod → SSM Session → EC2 Jump Host → VPC Network → RDS/Aurora DB
(localhost:15432)                                     (db.rds:5432)
```

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster with `kubectl` access
- Nginx Ingress Controller installed
- Storage class for PVCs
- Access to a container registry (e.g., GHCR / GitHub Container Registry)

### Quick Deploy

```bash
# 1. Build and push image
docker build -t ghcr.io/fpellizz/magikup:4.4.1 .
docker push ghcr.io/fpellizz/magikup:4.4.1

# 2. Create the Secret (fresh Fernet key) — out-of-band, never committed to git
./scripts/create-secret.sh

# 3. Pick an overlay (adjust the ingress host if needed):
#    kubernetes/overlays/panservice → RKE2: magikup.decisyon.com + cert-manager, NO NetworkPolicy
#    kubernetes/overlays/generic    → base + NetworkPolicy (edit host in kubernetes/base/ingress.yaml)

# 4. Deploy: Secret (out-of-band) + the kustomize overlay — or just ./scripts/deploy.sh
kubectl apply -f kubernetes/secret.yaml -n magikup
kubectl apply -k kubernetes/overlays/panservice

# 5. Verify
kubectl -n magikup rollout status deploy/magikup
kubectl -n magikup get pods -l app=magikup

# 6. Access (port-forward or via ingress)
kubectl -n magikup port-forward svc/magikup 8000:8000
```

### Manifest layout (Kustomize base + overlays)

The manifests live in a Kustomize **base** with per-cluster **overlays**. GitHub is the single source of truth; deploy with `kubectl apply -k kubernetes/overlays/<name>`.

| Path | Contents |
|------|----------|
| `kubernetes/base/` | `rbac.yaml`, `configmap.yaml`, `pvc.yaml`, `deployment.yaml`, `service.yaml`, `ingress.yaml` (+ `kustomization.yaml`). Namespace `magikup`, label `app=magikup`. **No** Secret, **no** NetworkPolicy. |
| `kubernetes/overlays/panservice/` | Base + an ingress patch (host `magikup.decisyon.com` + cert-manager issuer). No NetworkPolicy — RKE2 ingress-nginx runs hostNetwork, so it would block traffic. This is what runs in production. |
| `kubernetes/overlays/generic/` | Base + `networkpolicy.yaml`, for clusters with normal pod networking. |
| `kubernetes/secret.yaml` | Secret `magikup-secret` (Fernet key). **Out-of-band, gitignored** — generated by `scripts/create-secret.sh`, applied with `kubectl apply -f`, never part of a kustomization. |

### Persistent Volumes

| PVC | Size | Mount Path | Purpose |
|-----|------|------------|---------|
| `magikup-backups` | 50Gi | `/backups` | Backup files |
| `magikup-config` | 1Gi | `/app/config` | config.ini, users.json, audit.log |
| `magikup-logs` | 1Gi | `/app/logs` | Application logs |

### Resource Defaults

- **CPU**: 250m request / 2 cores limit
- **Memory**: 512Mi request / 2Gi limit
- **Strategy**: Recreate (required for RWO PVCs)
- **Health checks**: Liveness and readiness probes on `/health`

### Init Container

The deployment includes an init container that copies the default `config.ini` from the ConfigMap to the config PVC on first deploy only. Subsequent deploys preserve the existing configuration (endpoints, users, etc.).

## API Reference

### Pages

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | All | Dashboard |
| GET | `/backup` | Operator+ | Backup page |
| GET | `/restore` | Operator+ | Restore page |
| GET | `/transfer` | Operator+ | Transfer page |
| GET | `/files` | Operator+ | File manager |
| GET | `/query-editor` | Operator+ | Query editor |
| GET | `/admin` | Admin | Administration |
| GET | `/info` | All | Info page |
| GET | `/about` | All | Redirects to `/info` (backwards compatibility) |
| GET | `/docs/manual` | All | Serves HTML manual (opens in new tab) |
| GET | `/docs/manual.pdf` | All | Downloads PDF manual |
| GET | `/login` | Public | Login page |
| GET | `/change-password` | All | Change password |

### User Management API (Admin only)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/users` | List all users |
| POST | `/api/users` | Create user |
| PUT | `/api/users/{username}` | Update user (role, enabled) |
| DELETE | `/api/users/{username}` | Delete user |
| POST | `/api/users/{username}/reset-password` | Reset user password |
| POST | `/api/users/{username}/unlock` | Unlock locked account |
| GET | `/api/audit-log` | View security audit log |

### Endpoints API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/endpoints` | All | List all endpoints |
| GET | `/api/endpoints/{name}` | Admin | Get endpoint details (with decrypted password) |
| POST | `/api/endpoints` | Admin | Add/update endpoint |
| DELETE | `/api/endpoints/{name}` | Admin | Delete endpoint |

### Jump Hosts API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/jumphosts` | All | List jump hosts |
| POST | `/api/jumphosts` | Admin | Add/update jump host |
| DELETE | `/api/jumphosts/{alias}` | Admin | Delete jump host |

### AWS API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/aws/status` | Test AWS connection |
| GET | `/api/aws/clusters` | List Aurora clusters |
| GET | `/api/aws/instances` | List Aurora instances |
| GET | `/api/aws/ssm-instances` | List SSM-capable EC2 instances |

### Tunnels API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/tunnels` | All | List active tunnels |
| POST | `/api/tunnels/start` | Operator+ | Start SSM tunnel |
| POST | `/api/tunnels/stop/{id}` | Operator+ | Stop tunnel |

### Database API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/databases/{endpoint}` | List databases |
| GET | `/api/schemas/{endpoint}/{db}` | List schemas |
| GET | `/api/users/{endpoint}` | List users/roles |
| GET | `/api/test-connection/{endpoint}` | Test connection |

### Query Editor API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/query/execute` | Operator+ | Execute SQL query |
| GET | `/api/tables/{endpoint}/{db}/{schema}` | All | List tables |
| GET | `/api/columns/{endpoint}/{db}/{schema}/{table}` | All | List table columns |
| GET | `/api/views/{endpoint}/{db}/{schema}` | All | List views |
| GET | `/api/functions/{endpoint}/{db}/{schema}` | All | List functions |
| GET | `/api/indexes/{endpoint}/{db}/{schema}` | All | List indexes |

### Backup Files API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/backups` | All | List backup files |
| POST | `/api/backups/upload` | Operator+ | Upload backup file |
| GET | `/api/backups/{file}/download` | All | Download backup |
| DELETE | `/api/backups/{file}` | Operator+ | Delete backup |

### Configuration API (Admin only)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/config/download` | Download config.ini |
| POST | `/api/config/import` | Import config.ini |
| GET | `/api/config/aws` | Get AWS config |
| POST | `/api/config/aws` | Save AWS config |
| GET | `/api/config/settings` | Get app settings |
| POST | `/api/config/settings` | Save app settings |
| GET | `/api/config/query-settings` | Get query editor settings (autocommit default) |
| POST | `/api/config/query-settings` | Save query editor settings |
| POST | `/api/encrypt-passwords` | Encrypt plain passwords |

### WebSocket Endpoints

| Path | Auth | Description |
|------|------|-------------|
| `/ws/backup` | Operator+ | Backup with real-time progress |
| `/ws/restore` | Operator+ | Restore with real-time progress |
| `/ws/transfer` | Operator+ | Transfer with real-time progress |
| `/ws/operation/{id}/follow` | All | Follow running or view completed operation |

## Security

- **Multi-User Auth**: Role-based access control (Admin, Operator, Viewer)
- **Session Tokens**: Signed with `itsdangerous.URLSafeTimedSerializer`, include role, dynamic Secure flag
- **Password Hashing**: bcrypt with automatic salt
- **Password Policy**: Min 8 chars, 1 uppercase, 1 lowercase, 1 digit
- **Rate Limiting**: IP-based brute-force protection (5 attempts / 5 min)
- **Account Lockout**: Locks account after 10 failed attempts
- **Audit Log**: All security events logged (login, user changes, lockouts)
- **Password Encryption**: Fernet (AES-128) for database passwords at rest
- **Path Traversal Prevention**: Backup file paths validated against backup directory
- **Non-root Container**: Runs as UID 1000 in Kubernetes
- **SQL Injection Prevention**: Parameterized queries via psycopg2

## Troubleshooting

### SSM Tunnel Issues

- **"No jumphost ID configured"**: Add a jump host in Admin > Jump Hosts
- **"Tunnel failed to start"**: Check AWS credentials and jump host SSM agent status
- **"Port not accessible"**: Verify the jump host can reach the target database
- **Tunnel dies after start**: Check `aws ssm start-session` works from the pod

### Connection Issues

- **"Connection failed"**: Verify host/port/credentials in endpoint config
- **Timeout**: Check network connectivity (firewall, security groups)
- **"Authentication failed"**: Verify PostgreSQL username/password

### Backup/Restore Issues

- **"pg_dump not found"**: Check `pg_dump_path` in settings
- **"Restore completed with warnings"**: Normal with `--clean` flag (tries to drop non-existent objects)
- **Large file uploads fail**: Check `max_upload_size_gb` setting and ingress body size annotation

### Auth Issues

- **Account locked**: Admin can unlock from Admin > Users tab
- **Rate limited**: Wait 5 minutes or restart the pod to clear in-memory rate limits
- **Forgot password**: Admin can reset any user's password from Admin > Users tab

## Scripts

| Script | Description |
| ------ | ----------- |
| `scripts/create-secret.sh` | Generate `kubernetes/secret.yaml` with a Fernet encryption key |
| `scripts/build.sh` | Build Docker image |
| `scripts/deploy.sh` | Deploy to Kubernetes cluster |

## Version History

### 4.4.1

- **Fix: user email now persists.** Creating or editing a user silently dropped the `email` field (the API models/handlers never forwarded it), so no user ever had an email and self-service password recovery could never send. The create/update user endpoints now accept and store `email` (validated), so recovery works. Passwords were always saved correctly; this only affected the email address.

### 4.4.0

- **Password recovery (self-service)** — a **Forgot password?** link on the login page starts an email-based reset: a signed, expiring (30 min), single-use token (via `itsdangerous`, `pwv` password-hash fingerprint) is emailed as a reset link; the reset page enforces the password policy and a successful reset also clears any account lockout. Strict **no-user-enumeration** (always a generic response), per-IP rate limiting, and audit logging. New `forgot-password` / `reset-password` pages styled like login. Reset links are built from a configured **SMTP base URL** (or a locked-down `ALLOWED_HOSTS`) — never from an attacker-controllable `Host` header — and the send happens after the response to avoid a timing oracle.
- **Scheduled-backup email notifications** — each schedule can email on a **policy** (Off / On failure / On success / Always) to one or more recipients, with built-in success/failure templates (endpoint, database, filename, size, duration, destination, error). Sending is best-effort and never blocks or fails a backup. Configure it in the schedule dialog (Admin → Schedules); a bell chip in the list shows the active policy.
- The user **email** field is now surfaced as needed for password recovery (still technically optional so a no-email bootstrap admin isn't locked out).

### 4.3.0

- **Email sending (SMTP)** — MagikUp can now send email. A new encrypted `[smtp]` config section (host, port, security STARTTLS/SSL/none, username, Fernet-encrypted password, from/reply-to, timeout) is managed from an **Email (SMTP)** card in **Admin → Settings**, with a **Send test email** action that reports specific, actionable errors (auth, connection, TLS, timeout). Sending is provided by a small stdlib `app/email_service.py` (`send_email`), with header-injection defenses and no secrets in logs. Users gained an optional **email** field (Admin → Users). This is the foundation for the upcoming password-recovery flow and future alerts; the password is masked on read and preserved when left blank on save.

### 4.2.0

- **Query page — database & user management** — when the role connected to a database is a superuser or has the relevant attribute (`CREATEDB` / `CREATEROLE`), the Query page now lets you **create databases**, **create users (roles)**, and **modify user permissions** (role attributes, password reset, role membership, and database-level `CONNECT`/`CREATE`/`TEMP` grants) from capability-gated dialogs that match the app's design system. The actions are hidden on read-only endpoints and disabled when the connected role lacks the privilege (the database remains the final authority).
- **See all databases on the server** — the database list is no longer restricted to the databases you can connect to; every database on the server is shown (those without `CONNECT` are marked and greyed).
- New endpoints under `/api/db/*` (capabilities, roles, create database, create/alter role, role membership, database privileges). All mutating operations require operator rights, are refused on read-only endpoints, validate identifiers up-front, and build SQL exclusively with `psycopg2.sql` (no string interpolation); passwords are never logged.

### 4.1.1

- **Consistent page width** — every page now centers to a single shared max-width (a global `.app-main` container in `base.html`/`static/style.css`). Previously some pages (Backup, Transfer, Files) were centered at a narrower width while others (Dashboard, Restore, Query, Schedules, Admin) ran full-width, so screens drifted out of alignment; the per-page width wrappers were removed in favour of one page shell. Presentation-only fix.

### 4.1.0

- **UI redesign (usability + visual pass)** — implements the MagikUp redesign handoff on top of the v4.0.0 violet system: denser, calmer, more consistent screens with the gradient washes removed. Highlights: a solid dark navbar (`#101114`) with a violet active-link underline; one button/badge hierarchy (violet primaries — the green Upload/Run buttons are gone — soft tinted badges, uniform 30×30 table icon actions); a two-column **login**; a **dashboard** with four stat cards + endpoints/operations lists; **Backup/Restore/Transfer** with pg flags as monospace pills and an **empty-state Output panel** (no more idle black void) that becomes a terminal only while running; a redesigned **Query editor**, **Admin** tables (underlined sub-tabs, connection/role/status badges — Admin role is violet, not red), and aligned Schedules/Info/Change-password. Centralized tokens + reusable component classes in `static/style.css`; purely presentational, no functional changes.

### 4.0.0

- **App-wide design system** — the entire UI is realigned to the Backup Files page as the reference: a single **violet** accent, neutral surfaces, `0.625rem` card radius with a soft shadow, a solid dark navbar with a violet active-link underline, monospace for data (sizes, paths, ids, timestamps), and consistent buttons, cards, tables, form controls, badges, and segmented controls. Design tokens are centralized in `static/style.css` (light + dark) so every page inherits the same look; each page's local styles were migrated off the old indigo/navy palette onto the shared tokens. Purely presentational — no functional changes.

### 3.9.0

- **Backup Files page redesign** — the Files page was rebuilt to the "stat cards + collapsible remote" layout with a violet accent: three stat cards (backup directory, max upload size, total storage used with a volume-fullness bar), a collapsed-by-default "Retrieve from remote storage" card (S3 / filebrowser / link tabs), and a cleaner backup table (type badge, relative + absolute created time, per-row actions). Theme-aware (light/dark).
- **Backup type** — each backup is now classified as **Manual**, **Scheduled**, or **Imported**: `list_backup_files()` derives the origin from the operation history (scheduled vs manual); files with no matching backup operation (uploaded or pulled from remote) are shown as imported.
- **Volume usage** — `get_backup_stats()` now reports the hosting volume's capacity/usage (via `shutil.disk_usage`) so the page can show how full the backup volume is.
- **Restore from Files** — a per-row **Restore** action opens the Restore page with the backup preselected (`/restore?backup=<name>`). The existing "Send to remote storage" and Download/Delete actions are retained.

### 3.8.0

- **Duplicate endpoint** — a new "duplicate" action on each endpoint clones an existing definition (host, port, SSM/jumphost, read-only, replica, pg client version, sslmode, and password) into the add dialog with an editable, pre-suggested name (`<name>-copy`). Typical use: reuse the same connection with a different user.
- **Admin tab persistence** — the active Admin tab is now remembered across the page reloads that follow a save. Previously any change bounced the user back to the first "Endpoints" tab; now you stay on the tab you were working in (e.g. Users) to see the result.

### 3.7.0

- **Selectable PostgreSQL client version per endpoint** — the image now bundles the official PGDG `pg_dump`/`pg_restore` tools for versions **14, 15, 16 and 17**. Each endpoint carries a **PostgreSQL client version** (default **17**), so a backup/restore against an older server can use a matching client. Cross-version flags are handled automatically (`--blobs` instead of the 16/17-only `--large-objects`; `--no-table-access-method` only on client ≥ 15).
- **Per-endpoint `sslmode`** — endpoints gained an **SSL mode** property (`disable` / `allow` / `prefer` (default) / `require` / `verify-ca` / `verify-full`), applied both to in-app connections (`db_service`) and to `pg_dump`/`pg_restore` via `PGSSLMODE`.
- Both settings are editable from **Admin → Endpoints** (add/edit dialog) and shown as compact badges in the endpoint list. Values are validated server-side and stored backward-compatibly — endpoints saved before 3.7.0 default to client 17 / `prefer`.

### 3.6.1

- **Durable encryption key** — the Fernet key is now persisted on the config volume (`config/.encryption_key`) and preferred over the `ENCRYPTION_KEY` env/Secret, which is used only to *seed* the file on first run. The key now shares fate with the encrypted passwords stored next to it, so a redeploy — or a lost/regenerated Kubernetes Secret — no longer silently makes every stored password undecryptable. If the env key diverges from the persisted one, the persisted key wins (a warning is logged; rotating is a deliberate replace-file + re-encrypt).
- **Schedule UI** — removed the redundant "Enabled" toggle from the create/edit dialog (enable/disable is managed from the list); the list column is now labelled **Enabled**.

### 3.6.0

- **Scheduled backups** — automate recurring backups from a dedicated **Schedules** page.
  - **Graphical cron builder** — Hourly / Daily / Weekly / Monthly presets with a plain-language preview ("Every day at 02:30") and the next fire times, plus a raw-cron field for power users. Zero new dependencies: a small in-house 5-field cron parser (`app/cron.py`).
  - **In-process scheduler** — a single asyncio tick (30s) evaluates enabled schedules in UTC; single-replica so no leader election, no back-fill of runs missed while the pod was down, one heavy `pg_dump` at a time.
  - **Destinations** — a scheduled backup stays in the local backup directory by default, or is pushed to a configured **S3 / WebDAV / filebrowser** target, with an optional **delete-local-after-verified-copy** (never deleted unless the upload succeeded and the size matches). Optional local retention (`keep last N`).
  - **Management** — enable/disable toggle, **Run now**, live next-run countdown, status (incl. "upload failed — saved locally"), recent-runs history; reuses the live transfer-progress bars. Definitions in `[schedule:<name>]`; run-state in a separate `schedule_state.json` (kept out of the exportable config).
  - **Security** — schedule CRUD is admin-only, run-now is operator (re-checked against per-user endpoint scoping); cron + name validation, a 15-minute minimum interval, impossible-cron rejection, a 50-schedule cap, auto-disable after 5 consecutive failures, and audit logging.

### 3.5.0

- **Remote backup storage** — archive and retrieve backup files from remote targets, keeping the local backup directory as the working area. Configure targets under **Admin → Remote Storage**; both secrets are encrypted at rest.
  - **S3 (and S3-compatible)** — one or more buckets (MinIO, Ceph, Wasabi… via optional endpoint URL + path-style addressing). Credentials can be dedicated per bucket or reuse an existing AWS Account. Push a backup to a bucket, browse the `.backup` objects under a prefix, and pull one back into the local directory.
  - **WebDAV / HTTP(S) file shares** — one or more instances (base URL + optional basic-auth). Push a backup via HTTP `PUT`; retrieve one from a pasted link (credentials auto-applied when the link matches a configured share).
  - **filebrowser** ([github.com/filebrowser/filebrowser](https://github.com/filebrowser/filebrowser)) — one or more instances via its native HTTP + JWT API (login → `X-Auth`). Push (`POST /api/resources`), browse the `.backup` files in a configured folder, and pull one back (`GET /api/raw`).
  - **Live progress bars** — every remote push/pull shows a real-percentage progress bar on the Backup Files page (one per in-flight operation). Transfers run in a threadpool and report bytes as they stream (boto3's transfer callback for S3; chunked body/stream for WebDAV & filebrowser), polled via `GET /api/storage/operations`.
  - Engine-agnostic and dependency-light: S3 via the existing `boto3`; WebDAV and filebrowser via `urllib3` (already bundled) — no new dependencies. All transfers reuse the same filename/size/path-traversal guards as local uploads.

### 3.4.0

- **Backup lock-wait timeout** — new `lock_wait_timeout_seconds` setting (Admin → Settings, default 60s). `pg_dump` is run with `--lock-wait-timeout`, so a backup fails fast instead of blocking forever when it can't acquire shared table locks (e.g. behind a migration / `VACUUM FULL`). `0` = wait forever.
- **Backup from a read replica** — endpoints can be flagged to back up from a read replica instead of the primary. For Aurora hosts the endpoint form detects the cluster endpoint and suggests the reader (`.cluster-` → `.cluster-ro-`); enable it with a switch. Keeps dump locks off the writer. Stays engine-agnostic (still plain `pg_dump`).

### 3.3.0

- **Read-only endpoints** — flag an endpoint as read-only: the Query Editor connects with `default_transaction_read_only=on` (writes rejected by PostgreSQL) and restore/transfer to it are refused
- **Per-user endpoint scoping** — each non-admin user has an endpoint allowlist; scoped users only see and act on their assigned endpoints
- **Security hardening** — pg_dump/pg_restore path allowlist, SSM tunnel host validation, same-origin CSRF check, `TrustedHostMiddleware`, proxy-header aware rate limiting/audit, operator-only backup download, atomic user-store writes, destructive-restore confirmation, and more

### 3.2.0

- **TimescaleDB-aware restore** — new TimescaleDB toggle in the Restore and Transfer advanced parameters. When enabled, the app runs `SELECT timescaledb_pre_restore()` before and `SELECT timescaledb_post_restore()` after pg_restore, and adds `--disable-triggers` to the pg_restore command
- **Robust error handling** — if `timescaledb_pre_restore()` fails the restore is aborted before pg_restore runs; if `timescaledb_post_restore()` fails the operation is reported as failed even when pg_restore succeeded (the DB is left in inconsistent state)
- **Requirements** — the target database must have the `timescaledb` extension installed and the connecting user must be a superuser

### 3.1.0

- **Context Path / Reverse Proxy** — deploy under a URL prefix (e.g., `/magikup`) via `ROOT_PATH` env var or `context_path` in config.ini
- **Admin Network section** — manage context path from the Administration UI with restart warning and env var override indicator
- **Dual-source priority** — `ROOT_PATH` env var > config.ini `context_path` > empty (solves first-run bootstrap)
- **Updated Kubernetes manifests** — Deployment, Ingress, and ConfigMap with context path examples

### 3.0.0

- **Query Editor** with SQL syntax highlighting (Ace editor with PostgreSQL mode)
- **Object Browser** for exploring schemas, tables, views, functions, and indexes
- **Query Execution** with role switching, configurable timeout, and row limit
- **Autocommit Toggle** in the Query Editor toolbar with configurable default via `[query]` config section
- **Query History** (last 50 queries in browser localStorage) and **CSV Export** for results
- **Info Page** with application info, version history, technology stack, and documentation links (HTML manual opens in new tab, PDF manual downloads)
- **Contextual Tooltips** on all Query Editor buttons, dropdowns, and form elements
- **Dark/Light Theme Toggle** for the entire application

## To Do

- **Environment variable overrides for config.ini** — Allow all configuration settings to be overridden via environment variables (useful when config.ini is mounted as a read-only ConfigMap in Kubernetes)

## License

MIT License.
