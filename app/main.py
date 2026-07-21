"""
FastAPI application for PostgreSQL Backup/Restore (Full).
Unified application supporting both direct and SSM tunnel connections.
"""

import os
import re
import json
import asyncio
import logging
import dataclasses
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, File, UploadFile, Depends, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, ConfigDict

from . import config as cfg
from . import email_service
from . import db_service as db
from . import backup_restore as br
from . import auth
from . import operation_logger as op_logger
from . import aws_service as aws
from . import remote_storage as rs
from . import progress as progress_registry
from . import cron
from . import scheduler as sched_engine
from . import schedule_state
from .ssm_tunnel import tunnel_manager
from .broadcaster import broadcaster

# Configure logging (initial setup, will be updated from config)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def apply_log_level(level_name: str) -> None:
    """Apply log level to the root logger and all app loggers."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.getLogger().setLevel(level)
    for name in logging.Logger.manager.loggerDict:
        if name.startswith('app.'):
            logging.getLogger(name).setLevel(level)


# Apply configured log level at import time
try:
    _startup_settings = cfg.get_settings()
    apply_log_level(_startup_settings.log_level)
except Exception:
    pass

# Resolve context path (env var takes priority over config.ini)
_context_path = cfg.get_context_path()
logger.info(f"Context path: '{_context_path}' (empty = root)")

app = FastAPI(
    title="PostgreSQL Backup/Restore",
    description="Backup and restore PostgreSQL databases via direct or SSM tunnel connections",
    version="4.4.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    root_path=_context_path,
)


# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all HTTP responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none'"
        )
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


app.add_middleware(SecurityHeadersMiddleware)


# ---------------------------------------------------------------------------
# CSRF defense-in-depth: same-origin check on state-changing requests
# ---------------------------------------------------------------------------

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
_CSRF_ORIGIN_CHECK = os.environ.get("CSRF_ORIGIN_CHECK", "on").strip().lower() not in ("0", "off", "false", "no")


class CSRFOriginMiddleware(BaseHTTPMiddleware):
    """Reject state-changing requests whose Origin/Referer host doesn't match the
    request Host. Defense-in-depth on top of the SameSite=Lax session cookie.

    Requests that carry neither Origin nor Referer (e.g. curl/automation) are
    allowed: a browser always sends one of them on a cross-origin state change,
    so their absence is not a CSRF vector. Disable via CSRF_ORIGIN_CHECK=off.
    """

    async def dispatch(self, request: Request, call_next):
        if _CSRF_ORIGIN_CHECK and request.method not in _SAFE_METHODS:
            host = request.headers.get("host", "").split(":")[0].lower()
            source = request.headers.get("origin") or request.headers.get("referer")
            if source and host:
                src_host = (urlsplit(source).hostname or "").lower()
                if src_host and src_host != host:
                    logger.warning("Blocked cross-origin %s %s (origin/referer host %r != %r)",
                                   request.method, request.url.path, src_host, host)
                    return JSONResponse(status_code=403, content={"detail": "Cross-origin request blocked"})
        return await call_next(request)


if _CSRF_ORIGIN_CHECK:
    app.add_middleware(CSRFOriginMiddleware)

# Host header validation. Defaults to permissive ("*") so existing deployments
# keep working; set ALLOWED_HOSTS (comma-separated) to lock it down, e.g.
# ALLOWED_HOSTS="magikup.example.com". Added last so it runs outermost and
# rejects forged Host headers before any other processing.
#
# NOTE: when locked down, the Docker HEALTHCHECK and local probes hit
# Host "localhost", so we always keep localhost/127.0.0.1 allowed. Kubernetes
# httpGet probes send the pod IP as Host — either keep "*", set the probe's
# httpHeaders Host to your hostname, or add the pod IP range here.
_allowed_hosts = [h.strip() for h in os.environ.get("ALLOWED_HOSTS", "*").split(",") if h.strip()] or ["*"]
if _allowed_hosts != ["*"]:
    for _h in ("localhost", "127.0.0.1"):
        if _h not in _allowed_hosts:
            _allowed_hosts.append(_h)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts)
logger.info(f"Allowed hosts: {_allowed_hosts}")

# Registry of running operation tasks and their cancel events
_running_operations: dict[str, asyncio.Event] = {}

BASE_DIR = Path(__file__).parent.parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.mount("/docs/screenshots", StaticFiles(directory=BASE_DIR / "docs" / "screenshots"), name="docs_screenshots")
templates = Jinja2Templates(directory=BASE_DIR / "templates")
templates.env.globals["base_path"] = _context_path


# =============================================================================
# Pydantic Models
# =============================================================================

class BackupRequest(BaseModel):
    endpoint_name: str
    database: str
    large_objects: bool = True
    no_owner: bool = True
    no_privileges: bool = True


class RestoreRequest(BaseModel):
    backup_file: str
    endpoint_name: str
    database: str
    role: Optional[str] = None
    clean: bool = True
    exclude_schema: str = "public"


class TransferRequest(BaseModel):
    source_endpoint: str
    source_database: str
    dest_endpoint: str
    dest_database: str
    dest_role: Optional[str] = None


class DatabaseEndpointModel(BaseModel):
    name: str
    host: str
    port: int = 5432
    username: str
    password: str
    use_ssm: bool = False
    jumphost_alias: Optional[str] = ""
    read_only: bool = False
    backup_use_replica: bool = False
    replica_host: Optional[str] = ""
    pg_version: str = "17"
    sslmode: str = "prefer"


class JumphostModel(BaseModel):
    alias: str
    instance_id: str
    aws_account_alias: str = ""


class TunnelRequest(BaseModel):
    remote_host: str
    remote_port: int = 5432
    local_port: Optional[int] = None
    jumphost_alias: Optional[str] = None


class AWSAccountModel(BaseModel):
    alias: str
    access_key_id: str = ""
    secret_access_key: str = ""
    region: str = "us-east-1"


class S3StorageModel(BaseModel):
    name: str
    bucket: str
    region: str = "us-east-1"
    endpoint_url: Optional[str] = ""
    prefix: Optional[str] = ""
    path_style: bool = False
    cred_mode: str = "dedicated"  # "dedicated" | "aws_account"
    aws_account_alias: Optional[str] = ""
    access_key_id: Optional[str] = ""
    secret_access_key: Optional[str] = ""


class FileShareModel(BaseModel):
    name: str
    base_url: str
    username: Optional[str] = ""
    password: Optional[str] = ""
    verify_ssl: bool = True


class FileBrowserModel(BaseModel):
    name: str
    base_url: str
    root_path: Optional[str] = ""
    username: Optional[str] = ""
    password: Optional[str] = ""
    verify_ssl: bool = True


class SMTPConfigIn(BaseModel):
    enabled: bool = False
    host: Optional[str] = ""
    port: int = 587
    security: str = "starttls"  # starttls | ssl | none
    username: Optional[str] = ""
    password: Optional[str] = ""  # blank on save => keep existing
    from_address: Optional[str] = ""
    from_name: Optional[str] = "MagikUp"
    reply_to: Optional[str] = ""
    timeout_seconds: int = 15
    base_url: Optional[str] = ""


class SMTPTestModel(BaseModel):
    recipient: str


class RemotePushModel(BaseModel):
    target: str  # S3 storage name or file share name


class S3PullModel(BaseModel):
    key: str


class LinkPullModel(BaseModel):
    url: str
    fileshare: Optional[str] = None


class SettingsModel(BaseModel):
    backup_dir: str = "/backups"
    pg_dump_path: str = "/usr/bin/pg_dump"
    pg_restore_path: str = "/usr/bin/pg_restore"
    max_upload_size_gb: int = 5
    lock_wait_timeout_seconds: int = 60
    log_level: str = "INFO"
    context_path: str = ""


class UserCreateModel(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    endpoints: Optional[List[str]] = None  # None/["*"] = all endpoints


class UserUpdateModel(BaseModel):
    role: Optional[str] = None
    enabled: Optional[bool] = None
    endpoints: Optional[List[str]] = None


class UserPasswordResetModel(BaseModel):
    new_password: str


class QueryExecuteRequest(BaseModel):
    endpoint_name: str
    database: str
    query: str
    role: Optional[str] = None
    timeout_seconds: int = 30
    row_limit: int = 1000
    autocommit: bool = False


# DB / user management (v4.2.0)
class CreateDatabaseRequest(BaseModel):
    endpoint_name: str
    database: str = "postgres"  # DB to connect to for issuing the statement
    name: str
    owner: Optional[str] = None
    encoding: Optional[str] = None
    template: Optional[str] = None


class CreateRoleRequest(BaseModel):
    endpoint_name: str
    database: str = "postgres"
    name: str
    password: str
    login: bool = True
    createdb: bool = False
    createrole: bool = False
    superuser: bool = False
    valid_until: Optional[str] = None


class AlterRoleRequest(BaseModel):
    endpoint_name: str
    database: str = "postgres"
    name: str
    login: Optional[bool] = None
    createdb: Optional[bool] = None
    createrole: Optional[bool] = None
    superuser: Optional[bool] = None
    password: Optional[str] = None
    valid_until: Optional[str] = None


class RoleMembershipRequest(BaseModel):
    endpoint_name: str
    database: str = "postgres"
    role: str
    member: str
    grant: bool = True


class DatabasePrivilegesRequest(BaseModel):
    endpoint_name: str
    database: str = "postgres"  # DB to connect to for issuing the statement
    target_database: str        # DB the privileges apply to
    role: str
    privileges: List[str]
    grant: bool = True


class ScheduleModel(BaseModel):
    # Reject unknown keys so no arbitrary option string can reach pg_dump.
    model_config = ConfigDict(extra="forbid")
    name: str
    cron: str
    endpoint: str
    database: str
    enabled: bool = True
    large_objects: bool = True
    no_owner: bool = True
    no_privileges: bool = True
    no_tablespaces: bool = True
    no_comments: bool = True
    data_only: bool = False
    schema_only: bool = False
    clean: bool = False
    create: bool = False
    schemas: List[str] = []
    exclude_table: Optional[str] = None
    exclude_table_data: Optional[str] = None
    exclude_schema: Optional[str] = None
    dest_kind: str = "none"
    dest_target: Optional[str] = None
    delete_local_after_copy: bool = False
    keep_last_n: int = 0
    # Email notifications (v4.4.0).
    notify: str = "off"                       # off|on_failure|on_success|always
    notify_recipients: List[str] = []         # list of recipient email addresses


class ScheduleToggleModel(BaseModel):
    enabled: bool


class CronPreviewModel(BaseModel):
    cron: str
    count: int = 5


# =============================================================================
# Helpers
# =============================================================================

def resolve_endpoint_connection(endpoint: cfg.DatabaseConfig) -> Tuple[str, int]:
    """
    Resolve the actual host/port for a database endpoint.
    If the endpoint uses SSM, check for an active tunnel and route through it.
    If no tunnel is active, raise an error.
    For direct endpoints, return the endpoint's host/port.
    """
    if endpoint.use_ssm:
        tunnel = tunnel_manager.get_tunnel_for_endpoint(endpoint.host, endpoint.port)
        if tunnel:
            logger.info(f"Using SSM tunnel for {endpoint.name}: localhost:{tunnel.local_port}")
            return ("localhost", tunnel.local_port)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"SSM tunnel required for endpoint '{endpoint.name}' but no active tunnel found. Start a tunnel first."
            )
    else:
        return (endpoint.host, endpoint.port)


def ensure_tunnel_sync(endpoint: cfg.DatabaseConfig) -> Optional[dict]:
    """
    Ensure an SSM tunnel is active for the endpoint (if required).
    Starts a new tunnel if none exists. Returns tunnel result or None for direct.
    """
    if not endpoint.use_ssm:
        return None

    # Check for existing tunnel
    existing = tunnel_manager.get_tunnel_for_endpoint(endpoint.host, endpoint.port)
    if existing:
        logger.info(f"Reusing existing tunnel for {endpoint.name}: localhost:{existing.local_port}")
        return {
            "success": True,
            "tunnel_id": existing.tunnel_id,
            "local_port": existing.local_port,
            "message": "Tunnel already active",
        }

    # Need to start a new tunnel
    jumphost = cfg.get_jumphost(endpoint.jumphost_alias)
    if not jumphost:
        raise ValueError(
            f"Jump host '{endpoint.jumphost_alias}' not found for endpoint '{endpoint.name}'. "
            f"Configure the jump host in Admin settings."
        )

    result = tunnel_manager.start_tunnel(
        remote_host=endpoint.host,
        remote_port=endpoint.port,
        jumphost_id=jumphost.instance_id,
        aws_account_alias=jumphost.aws_account_alias,
    )

    if not result.get("success"):
        raise ValueError(f"Failed to start SSM tunnel: {result.get('error', 'Unknown error')}")

    logger.info(f"Started new tunnel for {endpoint.name}: localhost:{result['local_port']}")
    return result


def get_endpoint_host_port(endpoint: cfg.DatabaseConfig) -> Tuple[str, int]:
    """
    Get the effective host/port for an endpoint, starting a tunnel if needed.
    This is the main entry point for resolving connections in WebSocket handlers.
    """
    if endpoint.use_ssm:
        tunnel_result = ensure_tunnel_sync(endpoint)
        if tunnel_result:
            return ("localhost", tunnel_result["local_port"])
    return (endpoint.host, endpoint.port)


# WebSocket authentication helper
async def check_websocket_auth(websocket: WebSocket) -> Optional[dict]:
    """Check WebSocket authentication from cookies. Returns {"username": str, "role": str} or None."""
    session_token = websocket.cookies.get("session_token")
    if not session_token:
        return None
    max_age = auth.get_session_timeout() * 60
    token_data = auth.verify_session_token(session_token, max_age=max_age)
    if not token_data:
        return None
    # Validate user still exists and is active
    user = auth.get_user(token_data["username"])
    if not user or not user.enabled or user.locked:
        return None
    return {"username": user.username, "role": user.role, "endpoints": user.endpoints}


# Endpoint access control (F-01: per-user endpoint scoping)
def user_can_access_endpoint(user: dict, endpoint_name: str) -> bool:
    """Admins can access every endpoint; others only those in their allowlist
    (['*'] means all). Backward compatible: users without a list default to all."""
    if user.get("role") == "admin":
        return True
    allowed = user.get("endpoints") or ["*"]
    return "*" in allowed or endpoint_name in allowed


def require_endpoint_access(user: dict, endpoint_name: str) -> None:
    """Raise 403 if the user is not allowed to use this endpoint."""
    if not user_can_access_endpoint(user, endpoint_name):
        raise HTTPException(status_code=403, detail=f"Access to endpoint '{endpoint_name}' is not allowed")


# =============================================================================
# Health & Static
# =============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint for Kubernetes probes."""
    return {"status": "ok"}


@app.get("/favicon.ico")
async def favicon():
    """Serve favicon from static directory."""
    favicon_path = BASE_DIR / "static" / "magikarp.png"
    if favicon_path.exists():
        return FileResponse(favicon_path, media_type="image/png")
    return JSONResponse(status_code=204, content=None)


# =============================================================================
# Authentication Pages
# =============================================================================

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page."""
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """Handle login form submission."""
    ip = request.client.host if request.client else "unknown"

    # Check rate limit before attempting login
    is_blocked, seconds_remaining = auth._check_rate_limit(ip)
    if is_blocked:
        minutes = (seconds_remaining // 60) + 1
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": f"Too many failed attempts. Try again in {minutes} minute(s)."
        })

    # Check if account is locked
    user_obj = auth.get_user(username)
    if user_obj and user_obj.locked:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Account is locked. Contact an administrator."
        })
    if user_obj and not user_obj.enabled:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Account is disabled. Contact an administrator."
        })

    session_token = auth.handle_login(username, password, ip)

    if session_token:
        response = RedirectResponse(url=f"{_context_path}/", status_code=303)
        is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
        response.set_cookie(
            key="session_token",
            value=session_token,
            httponly=True,
            secure=is_https,
            max_age=auth.get_session_timeout() * 60,
            samesite="lax",
        )
        return response
    else:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password"
        })


@app.get("/logout")
async def logout(request: Request):
    """Logout and redirect to login page."""
    user = auth.get_current_user(request)
    if user:
        ip = request.client.host if request.client else "unknown"
        auth.audit_log("logout", user["username"], ip)
    response = RedirectResponse(url=f"{_context_path}/login", status_code=303)
    response.delete_cookie(key="session_token")
    return response


# =============================================================================
# Password Recovery (self-service reset via email) — all unauthenticated
# =============================================================================

def _reset_link(request: Request, token: str) -> Optional[str]:
    """Build the absolute reset link from a TRUSTED base only.

    The reset link is a bearer secret emailed to the user, so its host must not be
    attacker-controllable (Host-header poisoning → token exfiltration). Priority:
      1. the configured SMTP ``base_url`` (server-controlled, authoritative);
      2. else the request Host, but ONLY when ALLOWED_HOSTS is a real allowlist
         (TrustedHostMiddleware then guarantees the Host is one we trust).
    Returns None when no trusted base exists (ALLOWED_HOSTS == ['*'] and no
    base_url) — the caller then skips sending rather than mail an untrusted link."""
    base = cfg.get_smtp_config().base_url.strip()
    if base:
        return f"{base.rstrip('/')}/reset-password?token={token}"
    if _allowed_hosts != ["*"]:
        scheme = (request.headers.get("x-forwarded-proto")
                  or request.url.scheme or "https").split(",")[0].strip()
        host = request.headers.get("host") or request.url.netloc
        return f"{scheme}://{host}{_context_path}/reset-password?token={token}"
    return None


@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    """Render the 'forgot password' request form (unauthenticated)."""
    return templates.TemplateResponse("forgot_password.html", {"request": request})


@app.post("/forgot-password", response_class=HTMLResponse)
async def forgot_password(request: Request, background_tasks: BackgroundTasks, identifier: str = Form(...)):
    """Accept a username or email and ALWAYS return the same generic
    confirmation (no user enumeration). An email is dispatched only when the
    identifier resolves to an enabled user WITH an email AND SMTP is enabled."""
    ip = request.client.host if request.client else "unknown"

    # Per-IP rate limit (reuses the shared login limiter). When blocked we still
    # return the generic confirmation but skip the resolve/send work entirely.
    is_blocked, _ = auth._check_rate_limit(ip)
    if not is_blocked:
        auth._record_failed_attempt(ip)
        try:
            payload = auth.request_password_reset(identifier, ip)
            if payload:
                smtp = cfg.get_smtp_config()
                link = _reset_link(request, payload["token"]) if (smtp.enabled and smtp.host) else None
                if smtp.enabled and smtp.host and link is None:
                    # No trusted base URL to build the link from — do not mail an
                    # attacker-controllable host. Admin must set SMTP base_url or a
                    # non-wildcard ALLOWED_HOSTS.
                    auth.audit_log("password_reset_email_suppressed", payload["username"], ip, "no_trusted_base_url")
                    logger.warning("Password-reset email suppressed: configure SMTP base_url "
                                   "(or a non-wildcard ALLOWED_HOSTS) to build a trusted reset link.")
                elif link is not None:
                    subject = "Reset your MagikUp password"
                    text = (
                        "We received a request to reset your MagikUp password.\n\n"
                        f"Open this link to choose a new password (valid for 30 minutes):\n{link}\n\n"
                        "If you didn't request this, you can safely ignore this email — "
                        "your password will not change."
                    )
                    html = (
                        "<html><body style=\"font-family:-apple-system,Segoe UI,Roboto,sans-serif;"
                        "color:#111827;\">"
                        "<p>We received a request to reset your <strong>MagikUp</strong> password.</p>"
                        f'<p><a href="{link}" style="background:#7c3aed;color:#fff;padding:10px 18px;'
                        'border-radius:6px;text-decoration:none;display:inline-block;">'
                        "Choose a new password</a></p>"
                        "<p style=\"color:#6b7280;font-size:13px;\">This link is valid for 30 minutes. "
                        "If the button doesn't work, copy and paste this URL:</p>"
                        f'<p style="font-family:monospace;font-size:12px;word-break:break-all;">{link}</p>'
                        "<p style=\"color:#9ca3af;font-size:12px;margin-top:16px;\">"
                        "If you didn't request this, you can safely ignore this email — "
                        "your password will not change.</p>"
                        "</body></html>"
                    )

                    # Send AFTER the response (BackgroundTasks) so the HTTP
                    # response time is identical whether or not an email goes out,
                    # closing the timing side-channel that would otherwise reveal
                    # "valid account with an email".
                    def _send(username, recipient):
                        try:
                            email_service.send_email(recipient, subject, html, text)
                            auth.audit_log("password_reset_email_sent", username, ip)
                        except Exception as exc:
                            auth.audit_log("password_reset_email_error", username, ip,
                                           exc.__class__.__name__)
                            logger.warning("Password-reset email to %s failed: %s",
                                           username, exc.__class__.__name__)
                    background_tasks.add_task(_send, payload["username"], payload["email"])
        except Exception:
            # Any unexpected failure must still yield the generic response.
            logger.warning("forgot-password handling error (suppressed)")

    return templates.TemplateResponse("forgot_password.html",
                                      {"request": request, "submitted": True})


@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str = ""):
    """Validate the token and render the reset form, or a generic invalid/expired
    state. Does not reveal which condition failed."""
    user = auth.verify_reset_token(token)
    if not user:
        return templates.TemplateResponse("reset_password.html",
                                          {"request": request, "valid": False})
    return templates.TemplateResponse("reset_password.html",
                                      {"request": request, "valid": True, "token": token})


@app.post("/reset-password", response_class=HTMLResponse)
async def reset_password(request: Request, token: str = Form(...),
                         password: str = Form(...),
                         confirm_password: str = Form(...)):
    """Validate token + policy, set the new password, clear lockout. Redirects
    to /login on success (no auto-login)."""
    ip = request.client.host if request.client else "unknown"

    # Confirm-match first (cheap; token preserved for re-submit).
    if password != confirm_password:
        # Only re-render the form if the token is still valid; else generic state.
        if auth.verify_reset_token(token):
            return templates.TemplateResponse("reset_password.html", {
                "request": request, "valid": True, "token": token,
                "error": "The passwords do not match.",
            })
        return templates.TemplateResponse("reset_password.html",
                                          {"request": request, "valid": False})

    success, error_msg, category = auth.reset_password_with_token(token, password, ip)
    if success:
        return templates.TemplateResponse("reset_password.html",
                                          {"request": request, "success": True})
    if category == "policy":
        return templates.TemplateResponse("reset_password.html", {
            "request": request, "valid": True, "token": token, "error": error_msg,
        })
    # invalid_token (or anything else) -> generic invalid/expired state.
    return templates.TemplateResponse("reset_password.html",
                                      {"request": request, "valid": False})


# =============================================================================
# Page Routes
# =============================================================================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: dict = Depends(auth.require_auth)):
    """Dashboard page."""
    endpoints = {name: ep for name, ep in cfg.get_database_endpoints().items()
                 if user_can_access_endpoint(user, name)}
    settings = cfg.get_settings()
    backup_stats = br.get_backup_stats()
    tunnels = tunnel_manager.list_tunnels()

    return templates.TemplateResponse("index.html", {
        "request": request,
        "endpoints": endpoints,
        "settings": settings,
        "backup_stats": backup_stats,
        "tunnels": tunnels,
        "user": user["username"],
        "user_role": user["role"],
    })


@app.get("/backup", response_class=HTMLResponse)
async def backup_page(request: Request, user: dict = Depends(auth.require_operator)):
    """Backup page."""
    endpoints = {name: ep for name, ep in cfg.get_database_endpoints().items()
                 if user_can_access_endpoint(user, name)}
    jumphosts = cfg.get_jumphosts()

    return templates.TemplateResponse("backup.html", {
        "request": request,
        "endpoints": endpoints,
        "jumphosts": jumphosts,
        "user": user["username"],
        "user_role": user["role"],
    })


@app.get("/restore", response_class=HTMLResponse)
async def restore_page(request: Request, user: dict = Depends(auth.require_operator)):
    """Restore page."""
    endpoints = {name: ep for name, ep in cfg.get_database_endpoints().items()
                 if user_can_access_endpoint(user, name)}
    backups = br.list_backup_files()
    jumphosts = cfg.get_jumphosts()

    return templates.TemplateResponse("restore.html", {
        "request": request,
        "endpoints": endpoints,
        "backups": backups,
        "jumphosts": jumphosts,
        "user": user["username"],
        "user_role": user["role"],
    })


@app.get("/transfer", response_class=HTMLResponse)
async def transfer_page(request: Request, user: dict = Depends(auth.require_operator)):
    """Transfer page (backup + restore)."""
    endpoints = {name: ep for name, ep in cfg.get_database_endpoints().items()
                 if user_can_access_endpoint(user, name)}
    jumphosts = cfg.get_jumphosts()

    return templates.TemplateResponse("transfer.html", {
        "request": request,
        "endpoints": endpoints,
        "jumphosts": jumphosts,
        "user": user["username"],
        "user_role": user["role"],
    })


@app.get("/files", response_class=HTMLResponse)
async def files_page(request: Request, user: dict = Depends(auth.require_operator)):
    """Backup files management page."""
    settings = cfg.get_settings()
    backup_stats = br.get_backup_stats()

    return templates.TemplateResponse("files.html", {
        "request": request,
        "settings": settings,
        "backup_stats": backup_stats,
        "user": user["username"],
        "user_role": user["role"],
    })


@app.get("/scheduled", response_class=HTMLResponse)
async def scheduled_page(request: Request, user: dict = Depends(auth.require_operator)):
    """Scheduled backups management page."""
    settings = cfg.get_settings()

    return templates.TemplateResponse("scheduled.html", {
        "request": request,
        "settings": settings,
        "user": user["username"],
        "user_role": user["role"],
    })


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request, user: dict = Depends(auth.require_admin)):
    """Admin/configuration page."""
    endpoints = {name: ep for name, ep in cfg.get_database_endpoints().items()
                 if user_can_access_endpoint(user, name)}
    jumphosts = cfg.get_jumphosts()
    settings = cfg.get_settings()
    query_settings = cfg.get_query_settings()
    aws_accounts = cfg.get_aws_configs()
    s3_stores = cfg.get_s3_storage_configs()
    fileshares = cfg.get_fileshare_configs()
    filebrowsers = cfg.get_filebrowser_configs()
    all_users = auth.get_all_users()

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "endpoints": endpoints,
        "jumphosts": jumphosts,
        "settings": settings,
        "query_settings": query_settings,
        "aws_accounts": aws_accounts,
        "s3_stores": s3_stores,
        "fileshares": fileshares,
        "filebrowsers": filebrowsers,
        "all_users": all_users,
        "user": user["username"],
        "user_role": user["role"],
        "context_path_from_env": bool(os.environ.get('ROOT_PATH', '').strip()),
        "effective_context_path": cfg.get_context_path(),
    })


@app.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request, user: dict = Depends(auth.require_auth)):
    """Change password page."""
    return templates.TemplateResponse("change_password.html", {
        "request": request,
        "user": user["username"],
        "user_role": user["role"],
    })


@app.post("/change-password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: dict = Depends(auth.require_auth),
):
    """Handle password change."""
    if new_password != confirm_password:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "user": user["username"],
            "user_role": user["role"],
            "error": "New passwords do not match",
        })

    success, error_msg = auth.change_password(user["username"], current_password, new_password)
    if success:
        ip = request.client.host if request.client else "unknown"
        auth.audit_log("password_changed", user["username"], ip)
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "user": user["username"],
            "user_role": user["role"],
            "success": "Password changed successfully",
        })
    else:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "user": user["username"],
            "user_role": user["role"],
            "error": error_msg,
        })


@app.get("/query-editor", response_class=HTMLResponse)
async def query_editor_page(request: Request, user: dict = Depends(auth.require_operator)):
    """Query Editor page."""
    endpoints = {name: ep for name, ep in cfg.get_database_endpoints().items()
                 if user_can_access_endpoint(user, name)}
    jumphosts = cfg.get_jumphosts()
    query_settings = cfg.get_query_settings()

    return templates.TemplateResponse("query_editor.html", {
        "request": request,
        "endpoints": endpoints,
        "jumphosts": jumphosts,
        "query_settings": query_settings,
        "user": user["username"],
        "user_role": user["role"],
    })


@app.get("/info", response_class=HTMLResponse)
async def info_page(request: Request, user: dict = Depends(auth.require_auth)):
    """Info page."""
    from . import __version__
    docs_dir = BASE_DIR / "docs"
    return templates.TemplateResponse("info.html", {
        "request": request,
        "version": __version__,
        "has_html_manual": (docs_dir / "MagikUp_User_Manual.html").exists(),
        "has_pdf_manual": (docs_dir / "MagikUp_User_Manual.pdf").exists(),
        "user": user["username"],
        "user_role": user["role"],
    })


@app.get("/about")
async def about_redirect():
    """Redirect /about to /info for backwards compatibility."""
    return RedirectResponse(url=f"{_context_path}/info", status_code=301)


@app.get("/docs/manual")
async def docs_manual_html(user: dict = Depends(auth.require_auth)):
    """Serve the HTML user manual."""
    manual_path = BASE_DIR / "docs" / "MagikUp_User_Manual.html"
    if not manual_path.exists():
        raise HTTPException(status_code=404, detail="User manual not found")
    return FileResponse(manual_path, media_type="text/html")


@app.get("/docs/manual.pdf")
async def docs_manual_pdf(user: dict = Depends(auth.require_auth)):
    """Download the PDF user manual."""
    pdf_path = BASE_DIR / "docs" / "MagikUp_User_Manual.pdf"
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="PDF manual not found")
    return FileResponse(pdf_path, media_type="application/pdf", filename="MagikUp_User_Manual.pdf")


# =============================================================================
# Endpoints API
# =============================================================================

@app.get("/api/endpoints")
async def api_list_endpoints(user: dict = Depends(auth.require_auth)):
    """List configured database endpoints."""
    endpoints = {name: ep for name, ep in cfg.get_database_endpoints().items()
                 if user_can_access_endpoint(user, name)}
    return [
        {
            "name": name,
            "host": endpoint.host,
            "port": endpoint.port,
            "username": endpoint.username,
            "use_ssm": endpoint.use_ssm,
            "jumphost_alias": endpoint.jumphost_alias,
            "read_only": endpoint.read_only,
            "backup_use_replica": endpoint.backup_use_replica,
            "replica_host": endpoint.replica_host,
            "pg_version": endpoint.pg_version,
            "sslmode": endpoint.sslmode,
        }
        for name, endpoint in endpoints.items()
        if user_can_access_endpoint(user, name)
    ]


@app.post("/api/endpoints")
async def api_save_endpoint(endpoint: DatabaseEndpointModel, user: dict = Depends(auth.require_admin)):
    """Save a database endpoint."""
    try:
        pg_version = cfg.validate_pg_version(endpoint.pg_version)
        sslmode = cfg.validate_sslmode(endpoint.sslmode)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    cfg.save_database_config(cfg.DatabaseConfig(
        name=endpoint.name,
        host=endpoint.host,
        port=endpoint.port,
        username=endpoint.username,
        password=endpoint.password,
        use_ssm=endpoint.use_ssm,
        jumphost_alias=endpoint.jumphost_alias or "",
        read_only=endpoint.read_only,
        backup_use_replica=endpoint.backup_use_replica,
        replica_host=(endpoint.replica_host or ""),
        pg_version=pg_version,
        sslmode=sslmode,
    ))
    return {"success": True, "message": f"Endpoint '{endpoint.name}' saved"}


@app.get("/api/endpoints/{name}")
async def api_get_endpoint(name: str, user: dict = Depends(auth.require_admin)):
    """Get a single endpoint's details (including password) for editing."""
    endpoint = cfg.get_database_endpoint(name)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {
        "name": endpoint.name,
        "host": endpoint.host,
        "port": endpoint.port,
        "username": endpoint.username,
        "password": endpoint.password,
        "use_ssm": endpoint.use_ssm,
        "jumphost_alias": endpoint.jumphost_alias,
        "read_only": endpoint.read_only,
        "backup_use_replica": endpoint.backup_use_replica,
        "replica_host": endpoint.replica_host,
        "pg_version": endpoint.pg_version,
        "sslmode": endpoint.sslmode,
    }


@app.delete("/api/endpoints/{name}")
async def api_delete_endpoint(name: str, user: dict = Depends(auth.require_admin)):
    """Delete a database endpoint."""
    cfg.delete_database_config(name)
    return {"success": True, "message": f"Endpoint '{name}' deleted"}


# =============================================================================
# Jump Hosts API
# =============================================================================

@app.get("/api/jumphosts")
async def api_list_jumphosts(user: dict = Depends(auth.require_auth)):
    """List configured jump hosts."""
    jumphosts = cfg.get_jumphosts()
    return [
        {"alias": jh.alias, "instance_id": jh.instance_id, "aws_account_alias": jh.aws_account_alias}
        for jh in jumphosts.values()
    ]


@app.post("/api/jumphosts")
async def api_save_jumphost(jumphost: JumphostModel, user: dict = Depends(auth.require_admin)):
    """Save or update a jump host."""
    cfg.save_jumphost(cfg.JumphostConfig(
        alias=jumphost.alias,
        instance_id=jumphost.instance_id,
        aws_account_alias=jumphost.aws_account_alias,
    ))
    return {"success": True, "message": f"Jump host '{jumphost.alias}' saved"}


@app.delete("/api/jumphosts/{alias}")
async def api_delete_jumphost(alias: str, user: dict = Depends(auth.require_admin)):
    """Delete a jump host."""
    cfg.delete_jumphost(alias)
    return {"success": True, "message": f"Jump host '{alias}' deleted"}


# =============================================================================
# AWS API
# =============================================================================

@app.get("/api/aws/status")
async def api_aws_status(account: Optional[str] = None, user: dict = Depends(auth.require_auth)):
    """Test AWS connection for a specific account."""
    return aws.test_aws_connection(aws_account_alias=account)


@app.get("/api/aws/clusters")
async def api_aws_clusters(account: Optional[str] = None, user: dict = Depends(auth.require_auth)):
    """List Aurora PostgreSQL clusters."""
    return aws.list_aurora_clusters(aws_account_alias=account)


@app.get("/api/aws/instances")
async def api_aws_instances(account: Optional[str] = None, user: dict = Depends(auth.require_auth)):
    """List Aurora PostgreSQL instances."""
    return aws.list_aurora_instances(aws_account_alias=account)


@app.get("/api/aws/ssm-instances")
async def api_aws_ssm_instances(account: Optional[str] = None, user: dict = Depends(auth.require_auth)):
    """List EC2 instances available for SSM."""
    return aws.list_ssm_instances(aws_account_alias=account)


# =============================================================================
# Tunnels API
# =============================================================================

@app.get("/api/tunnels")
async def api_list_tunnels(user: dict = Depends(auth.require_auth)):
    """List active SSM tunnels."""
    return tunnel_manager.list_tunnels()


@app.post("/api/tunnels/start")
async def api_start_tunnel(req: TunnelRequest, user: dict = Depends(auth.require_operator)):
    """Start an SSM tunnel."""
    jumphost_id = None
    aws_account_alias = None
    if req.jumphost_alias:
        jumphost = cfg.get_jumphost(req.jumphost_alias)
        if not jumphost:
            raise HTTPException(status_code=404, detail=f"Jump host '{req.jumphost_alias}' not found")
        jumphost_id = jumphost.instance_id
        aws_account_alias = jumphost.aws_account_alias

    result = tunnel_manager.start_tunnel(
        remote_host=req.remote_host,
        remote_port=req.remote_port,
        local_port=req.local_port,
        jumphost_id=jumphost_id,
        aws_account_alias=aws_account_alias,
    )
    return result


@app.post("/api/tunnels/stop/{tunnel_id:path}")
async def api_stop_tunnel(tunnel_id: str, user: dict = Depends(auth.require_operator)):
    """Stop an SSM tunnel."""
    return tunnel_manager.stop_tunnel(tunnel_id)


# =============================================================================
# Database Operations API (with tunnel resolution)
# =============================================================================

@app.get("/api/databases/{endpoint_name}")
async def api_list_databases(endpoint_name: str, user: dict = Depends(auth.require_auth)):
    """List databases for an endpoint."""
    endpoint = cfg.get_database_endpoint(endpoint_name)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    require_endpoint_access(user, endpoint_name)

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)

    return db.list_databases(
        host=host,
        port=port,
        username=endpoint.username,
        password=endpoint.password,
        sslmode=endpoint.sslmode,
    )


@app.get("/api/users/{endpoint_name}")
async def api_list_users(endpoint_name: str, database: str = "postgres", user: dict = Depends(auth.require_auth)):
    """List users for an endpoint."""
    endpoint = cfg.get_database_endpoint(endpoint_name)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    require_endpoint_access(user, endpoint_name)

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)

    return db.list_users(
        host=host,
        port=port,
        username=endpoint.username,
        password=endpoint.password,
        database=database,
        sslmode=endpoint.sslmode,
    )


@app.get("/api/schemas/{endpoint_name}/{database}")
async def api_list_schemas(endpoint_name: str, database: str, user: dict = Depends(auth.require_auth)):
    """List schemas for a specific database."""
    endpoint = cfg.get_database_endpoint(endpoint_name)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    require_endpoint_access(user, endpoint_name)

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)

    schemas = db.list_schemas(
        host=host,
        port=port,
        database=database,
        username=endpoint.username,
        password=endpoint.password,
        sslmode=endpoint.sslmode,
    )
    return {"success": True, "schemas": schemas}


# =============================================================================
# Query Editor API
# =============================================================================


@app.post("/api/query/execute")
async def api_execute_query(req: QueryExecuteRequest, user: dict = Depends(auth.require_operator)):
    """Execute a SQL query against a database endpoint."""
    endpoint = cfg.get_database_endpoint(req.endpoint_name)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    require_endpoint_access(user, req.endpoint_name)

    timeout = min(req.timeout_seconds, 300)
    row_limit = min(req.row_limit, 10000)

    query = req.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)

    logger.info(
        f"Query executed by {user['username']} on {req.endpoint_name}/{req.database}: "
        f"{query[:200]}{'...' if len(query) > 200 else ''}"
    )

    result = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: db.execute_query(
            query=query,
            host=host,
            port=port,
            database=req.database,
            username=endpoint.username,
            password=endpoint.password,
            timeout_seconds=timeout,
            row_limit=row_limit,
            role=req.role if req.role else None,
            autocommit=req.autocommit,
            read_only=endpoint.read_only,
            sslmode=endpoint.sslmode,
        )
    )

    return result


# =============================================================================
# DB / user management API (v4.2.0)
# =============================================================================
# Every mutating endpoint below: require_operator + require_endpoint_access +
# refuse read-only endpoints + validate identifiers BEFORE resolving the tunnel
# or opening any DB connection. psycopg2.sql is used for all statement building
# in db_service. The DB itself is the final authority on CREATEDB/CREATEROLE.


def _resolve_mgmt_endpoint(user: dict, endpoint_name: str, require_writable: bool) -> cfg.DatabaseConfig:
    """Shared preamble for DB-management endpoints: 404 if unknown, 403 if the
    user cannot access it, 403 if it is read-only (for mutating actions). Does
    NOT open a DB connection so it is testable without a live database."""
    endpoint = cfg.get_database_endpoint(endpoint_name)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    require_endpoint_access(user, endpoint_name)
    if require_writable and endpoint.read_only:
        raise HTTPException(status_code=403, detail="Endpoint is read-only")
    return endpoint


@app.get("/api/db/capabilities/{endpoint_name}")
async def api_db_capabilities(endpoint_name: str, database: str = "postgres", user: dict = Depends(auth.require_operator)):
    """Report the connected role's capabilities (superuser / createdb / createrole)."""
    endpoint = _resolve_mgmt_endpoint(user, endpoint_name, require_writable=False)

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)
    result = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: db.get_role_capabilities(
            host=host, port=port,
            username=endpoint.username, password=endpoint.password,
            sslmode=endpoint.sslmode, database=database,
        ),
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to get capabilities"))
    return result


@app.get("/api/db/roles/{endpoint_name}")
async def api_db_roles(endpoint_name: str, database: str = "postgres", user: dict = Depends(auth.require_operator)):
    """List roles on the server (excluding internal pg_* roles)."""
    endpoint = _resolve_mgmt_endpoint(user, endpoint_name, require_writable=False)

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)
    result = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: db.list_roles(
            host=host, port=port,
            username=endpoint.username, password=endpoint.password,
            sslmode=endpoint.sslmode, database=database,
        ),
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to list roles"))
    return result


@app.post("/api/db/database")
async def api_db_create_database(req: CreateDatabaseRequest, user: dict = Depends(auth.require_operator)):
    """Create a database. Requires the connected role to have CREATEDB (or be a
    superuser) — the DB enforces this; a failure is surfaced as 400."""
    endpoint = _resolve_mgmt_endpoint(user, req.endpoint_name, require_writable=True)

    # Validate identifiers BEFORE touching the DB / tunnel.
    try:
        db._validate_ident(req.name, "database name")
        if req.owner:
            db._validate_ident(req.owner, "owner")
        if req.template:
            db._validate_ident(req.template, "template")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)
    logger.info(f"CREATE DATABASE '{req.name}' requested by {user['username']} on {req.endpoint_name}")
    result = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: db.create_database(
            host=host, port=port,
            username=endpoint.username, password=endpoint.password,
            sslmode=endpoint.sslmode, database=req.database,
            name=req.name, owner=req.owner, encoding=req.encoding, template=req.template,
        ),
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to create database"))
    return result


@app.post("/api/db/role")
async def api_db_create_role(req: CreateRoleRequest, user: dict = Depends(auth.require_operator)):
    """Create a role/user. Granting SUPERUSER requires the connected role to be a
    superuser (guarded here and enforced by the DB)."""
    endpoint = _resolve_mgmt_endpoint(user, req.endpoint_name, require_writable=True)

    try:
        db._validate_ident(req.name, "role name")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)

    # Superuser guard: only a superuser may create a superuser role.
    if req.superuser:
        caps = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: db.get_role_capabilities(
                host=host, port=port,
                username=endpoint.username, password=endpoint.password,
                sslmode=endpoint.sslmode, database=req.database,
            ),
        )
        if not caps.get("success"):
            raise HTTPException(status_code=400, detail=caps.get("error", "Failed to verify capabilities"))
        if not caps.get("is_superuser"):
            raise HTTPException(status_code=403, detail="Only a superuser can create a superuser role")

    logger.info(f"CREATE ROLE '{req.name}' requested by {user['username']} on {req.endpoint_name}")  # never log password
    result = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: db.create_role(
            host=host, port=port,
            username=endpoint.username, password=endpoint.password,
            sslmode=endpoint.sslmode, database=req.database,
            name=req.name, role_password=req.password,
            login=req.login, createdb=req.createdb, createrole=req.createrole,
            superuser=req.superuser, valid_until=req.valid_until,
        ),
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to create role"))
    return result


@app.post("/api/db/role/alter")
async def api_db_alter_role(req: AlterRoleRequest, user: dict = Depends(auth.require_operator)):
    """Alter a role's attributes / reset its password. Granting SUPERUSER
    requires the connected role to be a superuser."""
    endpoint = _resolve_mgmt_endpoint(user, req.endpoint_name, require_writable=True)

    try:
        db._validate_ident(req.name, "role name")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)

    # Superuser guard: only a superuser may grant SUPERUSER.
    if req.superuser is True:
        caps = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: db.get_role_capabilities(
                host=host, port=port,
                username=endpoint.username, password=endpoint.password,
                sslmode=endpoint.sslmode, database=req.database,
            ),
        )
        if not caps.get("success"):
            raise HTTPException(status_code=400, detail=caps.get("error", "Failed to verify capabilities"))
        if not caps.get("is_superuser"):
            raise HTTPException(status_code=403, detail="Only a superuser can grant superuser")

    logger.info(f"ALTER ROLE '{req.name}' requested by {user['username']} on {req.endpoint_name}")  # never log password
    result = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: db.alter_role(
            host=host, port=port,
            username=endpoint.username, password=endpoint.password,
            sslmode=endpoint.sslmode, database=req.database,
            name=req.name, login=req.login, createdb=req.createdb,
            createrole=req.createrole, superuser=req.superuser,
            role_password=req.password, valid_until=req.valid_until,
        ),
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to alter role"))
    return result


@app.post("/api/db/role/membership")
async def api_db_role_membership(req: RoleMembershipRequest, user: dict = Depends(auth.require_operator)):
    """Grant/revoke membership of one role in another."""
    endpoint = _resolve_mgmt_endpoint(user, req.endpoint_name, require_writable=True)

    try:
        db._validate_ident(req.role, "role")
        db._validate_ident(req.member, "member")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)
    logger.info(
        f"{'GRANT' if req.grant else 'REVOKE'} membership '{req.role}' / '{req.member}' "
        f"requested by {user['username']} on {req.endpoint_name}"
    )
    result = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: db.grant_role_membership(
            host=host, port=port,
            username=endpoint.username, password=endpoint.password,
            sslmode=endpoint.sslmode, database=req.database,
            role=req.role, member=req.member, grant=req.grant,
        ),
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to change membership"))
    return result


@app.post("/api/db/database/privileges")
async def api_db_database_privileges(req: DatabasePrivilegesRequest, user: dict = Depends(auth.require_operator)):
    """Grant/revoke database-level privileges (CONNECT/CREATE/TEMP/ALL)."""
    endpoint = _resolve_mgmt_endpoint(user, req.endpoint_name, require_writable=True)

    try:
        db._validate_ident(req.target_database, "target database")
        db._validate_ident(req.role, "role")
        db._validate_privileges(req.privileges)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)
    logger.info(
        f"{'GRANT' if req.grant else 'REVOKE'} {req.privileges} on '{req.target_database}' "
        f"/ '{req.role}' requested by {user['username']} on {req.endpoint_name}"
    )
    result = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: db.grant_database_privileges(
            host=host, port=port,
            username=endpoint.username, password=endpoint.password,
            sslmode=endpoint.sslmode, database=req.database,
            target_database=req.target_database, role=req.role,
            privileges=req.privileges, grant=req.grant,
        ),
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to change privileges"))
    return result


@app.get("/api/tables/{endpoint_name}/{database}/{schema}")
async def api_list_tables(endpoint_name: str, database: str, schema: str, user: dict = Depends(auth.require_auth)):
    """List tables in a schema."""
    endpoint = cfg.get_database_endpoint(endpoint_name)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    require_endpoint_access(user, endpoint_name)

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)
    tables = db.list_tables(host=host, port=port, database=database,
                            username=endpoint.username, password=endpoint.password, schema=schema,
                            sslmode=endpoint.sslmode)
    return {"success": True, "tables": tables}


@app.get("/api/columns/{endpoint_name}/{database}/{schema}/{table}")
async def api_list_columns(endpoint_name: str, database: str, schema: str, table: str, user: dict = Depends(auth.require_auth)):
    """List columns for a table."""
    endpoint = cfg.get_database_endpoint(endpoint_name)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    require_endpoint_access(user, endpoint_name)

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)
    columns = db.list_table_columns(host=host, port=port, database=database,
                                    username=endpoint.username, password=endpoint.password,
                                    schema=schema, table=table, sslmode=endpoint.sslmode)
    return {"success": True, "columns": columns}


@app.get("/api/views/{endpoint_name}/{database}/{schema}")
async def api_list_views(endpoint_name: str, database: str, schema: str, user: dict = Depends(auth.require_auth)):
    """List views in a schema."""
    endpoint = cfg.get_database_endpoint(endpoint_name)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    require_endpoint_access(user, endpoint_name)

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)
    views = db.list_views(host=host, port=port, database=database,
                          username=endpoint.username, password=endpoint.password, schema=schema,
                          sslmode=endpoint.sslmode)
    return {"success": True, "views": views}


@app.get("/api/functions/{endpoint_name}/{database}/{schema}")
async def api_list_functions(endpoint_name: str, database: str, schema: str, user: dict = Depends(auth.require_auth)):
    """List functions in a schema."""
    endpoint = cfg.get_database_endpoint(endpoint_name)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    require_endpoint_access(user, endpoint_name)

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)
    functions = db.list_functions(host=host, port=port, database=database,
                                 username=endpoint.username, password=endpoint.password, schema=schema,
                                 sslmode=endpoint.sslmode)
    return {"success": True, "functions": functions}


@app.get("/api/indexes/{endpoint_name}/{database}/{schema}")
async def api_list_indexes(endpoint_name: str, database: str, schema: str, table: Optional[str] = None, user: dict = Depends(auth.require_auth)):
    """List indexes in a schema, optionally filtered by table."""
    endpoint = cfg.get_database_endpoint(endpoint_name)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    require_endpoint_access(user, endpoint_name)

    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)
    indexes = db.list_indexes(host=host, port=port, database=database,
                              username=endpoint.username, password=endpoint.password,
                              schema=schema, table=table, sslmode=endpoint.sslmode)
    return {"success": True, "indexes": indexes}


@app.get("/api/test-connection/{endpoint_name}")
async def api_test_connection(endpoint_name: str, user: dict = Depends(auth.require_auth)):
    """Test database connection for an endpoint."""
    endpoint = cfg.get_database_endpoint(endpoint_name)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    require_endpoint_access(user, endpoint_name)

    # Ensure SSM tunnel is active if needed (auto-start)
    try:
        ensure_tunnel_sync(endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    host, port = resolve_endpoint_connection(endpoint)

    return db.test_connection(
        host=host,
        port=port,
        username=endpoint.username,
        password=endpoint.password,
        sslmode=endpoint.sslmode,
    )


# =============================================================================
# Backup Files API
# =============================================================================

@app.get("/api/backups")
async def api_list_backups(user: dict = Depends(auth.require_auth)):
    """List backup files."""
    return br.list_backup_files()


@app.delete("/api/backups/{filename}")
async def api_delete_backup(filename: str, user: dict = Depends(auth.require_operator)):
    """Delete a backup file."""
    return br.delete_backup(filename)


@app.get("/api/backups/{filename}/download")
async def api_download_backup(filename: str, user: dict = Depends(auth.require_operator)):
    """Download a backup file. Restricted to operator/admin: backup files contain
    full database contents, so viewers (read-only UI) must not be able to export them."""
    backup_dir = br.get_backup_dir()
    file_path = backup_dir / filename

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    try:
        file_path.resolve().relative_to(backup_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Invalid file path")

    if not filename.endswith('.backup'):
        raise HTTPException(status_code=400, detail="Invalid file type")

    return FileResponse(
        path=str(file_path),
        media_type='application/octet-stream',
        filename=filename,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.post("/api/backups/upload")
async def api_upload_backup(file: UploadFile = File(...), user: dict = Depends(auth.require_operator)):
    """Upload a backup file (up to configured max size). Streams to disk."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    if not file.filename.endswith('.backup'):
        raise HTTPException(status_code=400, detail="Only .backup files are allowed")

    # Validate and sanitize filename
    is_valid, error_msg = br.validate_backup_filename(file.filename)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)
    safe_filename = br.sanitize_backup_filename(file.filename)

    settings = cfg.get_settings()
    max_size_gb = getattr(settings, 'max_upload_size_gb', 5)
    max_bytes = max_size_gb * 1024 * 1024 * 1024

    backup_dir = br.get_backup_dir()
    target_path = backup_dir / safe_filename
    temp_path = backup_dir / f".upload_{safe_filename}.tmp"

    if target_path.exists():
        raise HTTPException(status_code=400, detail=f"File {safe_filename} already exists")

    chunk_size = 1024 * 1024  # 1MB chunks
    total_size = 0

    try:
        with open(temp_path, 'wb') as f:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > max_bytes:
                    raise HTTPException(status_code=413, detail=f"File too large. Maximum size is {max_size_gb}GB")
                f.write(chunk)

        # Enforce a cumulative backup-storage quota (defense against disk
        # exhaustion). Configurable via MAX_TOTAL_BACKUP_GB (default 100GB).
        max_total_gb = int(os.environ.get("MAX_TOTAL_BACKUP_GB", "100"))
        existing_total = br.get_backup_stats().get("total_size", 0)
        if existing_total + total_size > max_total_gb * 1024 * 1024 * 1024:
            raise HTTPException(
                status_code=413,
                detail=f"Backup storage quota exceeded (limit {max_total_gb}GB). "
                       f"Delete old backups or raise MAX_TOTAL_BACKUP_GB.",
            )

        # Atomic rename
        temp_path.rename(target_path)

        return {
            "success": True,
            "message": f"Uploaded {safe_filename}",
            "filename": safe_filename,
            "size": total_size,
            "size_human": br._format_size(total_size),
        }

    except HTTPException:
        if temp_path.exists():
            temp_path.unlink()
        raise
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        logger.error(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail="Upload failed")
    finally:
        await file.close()


# =============================================================================
# Backup remote storage actions (push to / pull from S3 + file shares)
# =============================================================================
# NOTE: the push/pull endpoints below are sync `def` on purpose. FastAPI runs
# sync endpoints in a threadpool, so the (blocking) network transfer doesn't
# stall the event loop — letting the /api/storage/operations poll be served
# concurrently for live progress bars.

def _run_with_progress(direction: str, kind: str, target: str, label: str, fn):
    """Register a progress entry, run the transfer (fn receives a (done, total)
    callback), finalize the entry, and return the transfer result dict."""
    op_id = progress_registry.start(direction, kind, target, label)

    def cb(done, total):
        progress_registry.update(op_id, done=done, total=total)

    try:
        result = fn(cb)
    except Exception as e:
        progress_registry.finish(op_id, "error", str(e))
        raise
    if result.get("success"):
        progress_registry.finish(op_id, "done")
    else:
        progress_registry.finish(op_id, "error", result.get("error", ""))
    return result


@app.get("/api/storage/operations")
async def api_storage_operations(user: dict = Depends(auth.require_operator)):
    """Snapshot of in-flight (and just-finished) remote transfers, for progress bars."""
    return {"operations": progress_registry.snapshot()}


@app.get("/api/storage/targets")
async def api_storage_targets(user: dict = Depends(auth.require_operator)):
    """List configured remote storage target names (no secrets) for the UI."""
    return {
        "s3": [
            {"name": s.name, "bucket": s.bucket}
            for s in cfg.get_s3_storage_configs().values()
        ],
        "fileshare": [
            {"name": s.name, "base_url": s.base_url}
            for s in cfg.get_fileshare_configs().values()
        ],
        "filebrowser": [
            {"name": s.name, "base_url": s.base_url}
            for s in cfg.get_filebrowser_configs().values()
        ],
    }


@app.post("/api/backups/{filename}/push/s3")
def api_push_backup_s3(filename: str, req: RemotePushModel, user: dict = Depends(auth.require_operator)):
    """Upload a local backup file to an S3 storage target."""
    result = _run_with_progress("upload", "s3", req.target, filename,
                                lambda cb: rs.s3_upload_backup(req.target, filename, progress_cb=cb))
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Upload failed"))
    return result


@app.post("/api/backups/{filename}/push/fileshare")
def api_push_backup_fileshare(filename: str, req: RemotePushModel, user: dict = Depends(auth.require_operator)):
    """Upload a local backup file to a WebDAV file share target."""
    result = _run_with_progress("upload", "fileshare", req.target, filename,
                                lambda cb: rs.webdav_upload_backup(req.target, filename, progress_cb=cb))
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Upload failed"))
    return result


@app.post("/api/backups/{filename}/push/filebrowser")
def api_push_backup_filebrowser(filename: str, req: RemotePushModel, user: dict = Depends(auth.require_operator)):
    """Upload a local backup file to a filebrowser target."""
    result = _run_with_progress("upload", "filebrowser", req.target, filename,
                                lambda cb: rs.filebrowser_upload_backup(req.target, filename, progress_cb=cb))
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Upload failed"))
    return result


@app.get("/api/storage/s3/{name}/objects")
def api_s3_objects(name: str, user: dict = Depends(auth.require_operator)):
    """List .backup objects available in an S3 storage target."""
    result = rs.s3_list_backups(name)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "List failed"))
    return result


@app.post("/api/storage/s3/{name}/pull")
def api_s3_pull(name: str, req: S3PullModel, user: dict = Depends(auth.require_operator)):
    """Download an object from an S3 storage target into the local backup dir."""
    label = req.key.rsplit('/', 1)[-1] or req.key
    result = _run_with_progress("download", "s3", name, label,
                                lambda cb: rs.s3_download_backup(name, req.key, progress_cb=cb))
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Download failed"))
    return result


@app.post("/api/storage/fileshare/pull")
def api_fileshare_pull(req: LinkPullModel, user: dict = Depends(auth.require_operator)):
    """Download a backup from an http(s) link, optionally using a file share's credentials."""
    label = req.url.rsplit('/', 1)[-1].split('?')[0] or req.url
    result = _run_with_progress("download", "link", req.fileshare or "link", label,
                                lambda cb: rs.download_from_link(req.url, req.fileshare, progress_cb=cb))
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Download failed"))
    return result


@app.get("/api/storage/filebrowser/{name}/objects")
def api_filebrowser_objects(name: str, user: dict = Depends(auth.require_operator)):
    """List .backup objects available in a filebrowser target."""
    result = rs.filebrowser_list_backups(name)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "List failed"))
    return result


@app.post("/api/storage/filebrowser/{name}/pull")
def api_filebrowser_pull(name: str, req: S3PullModel, user: dict = Depends(auth.require_operator)):
    """Download an object from a filebrowser target into the local backup dir."""
    result = _run_with_progress("download", "filebrowser", name, req.key,
                                lambda cb: rs.filebrowser_download_backup(name, req.key, progress_cb=cb))
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Download failed"))
    return result


# =============================================================================
# Configuration API (download/import, no raw editing)
# =============================================================================

@app.get("/api/config/download")
async def api_config_download(user: dict = Depends(auth.require_admin)):
    """Download the configuration file."""
    config_path = cfg.CONFIG_FILE
    if not config_path.exists():
        raise HTTPException(status_code=404, detail="Configuration file not found")

    return FileResponse(
        path=str(config_path),
        media_type='text/plain',
        filename='config.ini',
        headers={"Content-Disposition": "attachment; filename=config.ini"}
    )


@app.post("/api/config/import")
async def api_config_import(file: UploadFile = File(...), user: dict = Depends(auth.require_admin)):
    """Import a configuration file (replaces current config)."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    try:
        content = await file.read()
        content_str = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Invalid file encoding. Must be UTF-8.")
    finally:
        await file.close()

    result = cfg.import_config_content(content_str)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])

    return result


@app.post("/api/encrypt-passwords")
async def api_encrypt_passwords(user: dict = Depends(auth.require_admin)):
    """Encrypt all existing plain-text passwords."""
    try:
        count = cfg.encrypt_existing_passwords()
        return {
            "success": True,
            "message": f"Encrypted {count} password(s)" if count > 0 else "All passwords are already encrypted",
            "encrypted_count": count,
        }
    except Exception as e:
        logger.error(f"Error encrypting passwords: {e}")
        raise HTTPException(status_code=500, detail="Internal server error (see server logs)")


@app.get("/api/config/aws")
async def api_get_aws_accounts(user: dict = Depends(auth.require_admin)):
    """Get all AWS account configurations (admin only)."""
    accounts = cfg.get_aws_configs()
    return [
        {
            "alias": acc.alias,
            "access_key_id": acc.access_key_id,
            "secret_access_key": "***" if acc.secret_access_key else "",
            "region": acc.region,
        }
        for acc in accounts.values()
    ]


@app.post("/api/config/aws")
async def api_save_aws_account(account: AWSAccountModel, user: dict = Depends(auth.require_admin)):
    """Save an AWS account configuration."""
    cfg.save_aws_config(cfg.AWSConfig(
        alias=account.alias,
        access_key_id=account.access_key_id,
        secret_access_key=account.secret_access_key,
        region=account.region,
    ))
    return {"success": True, "message": f"AWS account '{account.alias}' saved"}


@app.delete("/api/config/aws/{alias}")
async def api_delete_aws_account(alias: str, user: dict = Depends(auth.require_admin)):
    """Delete an AWS account configuration."""
    cfg.delete_aws_config(alias)
    return {"success": True, "message": f"AWS account '{alias}' deleted"}


# =============================================================================
# Remote Storage config API (S3 buckets + WebDAV file shares)
# =============================================================================

@app.get("/api/config/s3")
async def api_get_s3_stores(user: dict = Depends(auth.require_admin)):
    """List S3 storage configs (secret masked)."""
    stores = cfg.get_s3_storage_configs()
    return [
        {
            "name": s.name,
            "bucket": s.bucket,
            "region": s.region,
            "endpoint_url": s.endpoint_url,
            "prefix": s.prefix,
            "path_style": s.path_style,
            "cred_mode": s.cred_mode,
            "aws_account_alias": s.aws_account_alias,
            "access_key_id": s.access_key_id,
            "secret_access_key": "***" if s.secret_access_key else "",
        }
        for s in stores.values()
    ]


@app.get("/api/config/s3/{name}")
async def api_get_s3_store(name: str, user: dict = Depends(auth.require_admin)):
    """Get a single S3 storage config for editing. The secret is masked; a blank
    secret on save preserves the stored value (see api_save_s3_store)."""
    s = cfg.get_s3_storage_config(name)
    if not s:
        raise HTTPException(status_code=404, detail="S3 storage not found")
    return {
        "name": s.name,
        "bucket": s.bucket,
        "region": s.region,
        "endpoint_url": s.endpoint_url,
        "prefix": s.prefix,
        "path_style": s.path_style,
        "cred_mode": s.cred_mode,
        "aws_account_alias": s.aws_account_alias,
        "access_key_id": s.access_key_id,
        "has_secret": bool(s.secret_access_key),
    }


@app.post("/api/config/s3")
async def api_save_s3_store(store: S3StorageModel, user: dict = Depends(auth.require_admin)):
    """Save an S3 storage config. Keeps the existing secret when left blank on edit."""
    secret = store.secret_access_key or ""
    if store.cred_mode == 'dedicated' and not secret:
        existing = cfg.get_s3_storage_config(store.name)
        if existing:
            secret = existing.secret_access_key
    cfg.save_s3_storage_config(cfg.S3StorageConfig(
        name=store.name,
        bucket=store.bucket,
        region=store.region,
        endpoint_url=store.endpoint_url or "",
        prefix=store.prefix or "",
        path_style=store.path_style,
        cred_mode=store.cred_mode,
        aws_account_alias=store.aws_account_alias or "",
        access_key_id=store.access_key_id or "",
        secret_access_key=secret,
    ))
    return {"success": True, "message": f"S3 storage '{store.name}' saved"}


@app.delete("/api/config/s3/{name}")
async def api_delete_s3_store(name: str, user: dict = Depends(auth.require_admin)):
    """Delete an S3 storage config."""
    cfg.delete_s3_storage_config(name)
    return {"success": True, "message": f"S3 storage '{name}' deleted"}


@app.post("/api/config/s3/{name}/test")
async def api_test_s3_store(name: str, user: dict = Depends(auth.require_admin)):
    """Test connectivity to a saved S3 storage config."""
    return rs.s3_test_connection(store_name=name)


@app.get("/api/config/fileshare")
async def api_get_fileshares(user: dict = Depends(auth.require_admin)):
    """List file share configs (password masked)."""
    shares = cfg.get_fileshare_configs()
    return [
        {
            "name": s.name,
            "base_url": s.base_url,
            "username": s.username,
            "password": "***" if s.password else "",
            "verify_ssl": s.verify_ssl,
        }
        for s in shares.values()
    ]


@app.get("/api/config/fileshare/{name}")
async def api_get_fileshare(name: str, user: dict = Depends(auth.require_admin)):
    """Get a single file share config for editing. The password is masked; a blank
    password on save preserves the stored value (see api_save_fileshare)."""
    s = cfg.get_fileshare_config(name)
    if not s:
        raise HTTPException(status_code=404, detail="File share not found")
    return {
        "name": s.name,
        "base_url": s.base_url,
        "username": s.username,
        "has_password": bool(s.password),
        "verify_ssl": s.verify_ssl,
    }


@app.post("/api/config/fileshare")
async def api_save_fileshare(share: FileShareModel, user: dict = Depends(auth.require_admin)):
    """Save a file share config. Keeps the existing password when left blank on edit."""
    password = share.password or ""
    if not password:
        existing = cfg.get_fileshare_config(share.name)
        if existing:
            password = existing.password
    cfg.save_fileshare_config(cfg.FileShareConfig(
        name=share.name,
        base_url=share.base_url,
        username=share.username or "",
        password=password,
        verify_ssl=share.verify_ssl,
    ))
    return {"success": True, "message": f"File share '{share.name}' saved"}


@app.delete("/api/config/fileshare/{name}")
async def api_delete_fileshare(name: str, user: dict = Depends(auth.require_admin)):
    """Delete a file share config."""
    cfg.delete_fileshare_config(name)
    return {"success": True, "message": f"File share '{name}' deleted"}


@app.post("/api/config/fileshare/{name}/test")
async def api_test_fileshare(name: str, user: dict = Depends(auth.require_admin)):
    """Test connectivity to a saved file share config."""
    return rs.webdav_test_connection(share_name=name)


@app.get("/api/config/filebrowser")
async def api_get_filebrowsers(user: dict = Depends(auth.require_admin)):
    """List filebrowser configs (password masked)."""
    return [
        {
            "name": s.name,
            "base_url": s.base_url,
            "root_path": s.root_path,
            "username": s.username,
            "password": "***" if s.password else "",
            "verify_ssl": s.verify_ssl,
        }
        for s in cfg.get_filebrowser_configs().values()
    ]


@app.get("/api/config/filebrowser/{name}")
async def api_get_filebrowser(name: str, user: dict = Depends(auth.require_admin)):
    """Get a single filebrowser config for editing. The password is masked; a
    blank password on save preserves the stored value (see api_save_filebrowser)."""
    s = cfg.get_filebrowser_config(name)
    if not s:
        raise HTTPException(status_code=404, detail="filebrowser instance not found")
    return {
        "name": s.name,
        "base_url": s.base_url,
        "root_path": s.root_path,
        "username": s.username,
        "has_password": bool(s.password),
        "verify_ssl": s.verify_ssl,
    }


@app.post("/api/config/filebrowser")
async def api_save_filebrowser(fb: FileBrowserModel, user: dict = Depends(auth.require_admin)):
    """Save a filebrowser config. Keeps the existing password when left blank on edit."""
    password = fb.password or ""
    if not password:
        existing = cfg.get_filebrowser_config(fb.name)
        if existing:
            password = existing.password
    cfg.save_filebrowser_config(cfg.FileBrowserConfig(
        name=fb.name,
        base_url=fb.base_url,
        root_path=fb.root_path or "",
        username=fb.username or "",
        password=password,
        verify_ssl=fb.verify_ssl,
    ))
    return {"success": True, "message": f"filebrowser '{fb.name}' saved"}


@app.delete("/api/config/filebrowser/{name}")
async def api_delete_filebrowser(name: str, user: dict = Depends(auth.require_admin)):
    """Delete a filebrowser config."""
    cfg.delete_filebrowser_config(name)
    return {"success": True, "message": f"filebrowser '{name}' deleted"}


@app.post("/api/config/filebrowser/{name}/test")
async def api_test_filebrowser(name: str, user: dict = Depends(auth.require_admin)):
    """Test connectivity to a saved filebrowser config."""
    return rs.filebrowser_test_connection(name=name)


# =============================================================================
# Email (SMTP) config API
# =============================================================================

@app.get("/api/config/smtp")
async def api_get_smtp(user: dict = Depends(auth.require_admin)):
    """Get the SMTP config (admin only). The password is masked: returned as
    "***" when a secret is stored, else "". ``configured`` is true when email is
    enabled and a host is set. A blank password on save preserves the stored
    value (see api_save_smtp)."""
    s = cfg.get_smtp_config()
    return {
        "enabled": s.enabled,
        "host": s.host,
        "port": s.port,
        "security": s.security,
        "username": s.username,
        "password": "***" if s.password else "",
        "has_password": bool(s.password),
        "from_address": s.from_address,
        "from_name": s.from_name,
        "reply_to": s.reply_to,
        "timeout_seconds": s.timeout_seconds,
        "base_url": s.base_url,
        "configured": bool(s.enabled and s.host),
    }


@app.post("/api/config/smtp")
async def api_save_smtp(smtp: SMTPConfigIn, user: dict = Depends(auth.require_admin)):
    """Save the SMTP config. A blank password keeps the existing encrypted value
    (handled in cfg.save_smtp_config). Validates security, port, timeout and the
    from-address (when set)."""
    security = (smtp.security or "").lower().strip()
    if security not in cfg.VALID_SMTP_SECURITY:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid security '{smtp.security}'. Allowed: {', '.join(cfg.VALID_SMTP_SECURITY)}")
    if not (1 <= smtp.port <= 65535):
        raise HTTPException(status_code=400, detail="Port must be between 1 and 65535")
    if not (cfg.SMTP_TIMEOUT_MIN <= smtp.timeout_seconds <= cfg.SMTP_TIMEOUT_MAX):
        raise HTTPException(
            status_code=400,
            detail=f"Timeout must be between {cfg.SMTP_TIMEOUT_MIN} and {cfg.SMTP_TIMEOUT_MAX} seconds")
    from_address = (smtp.from_address or "").strip()
    if from_address and not email_service.is_valid_email(from_address):
        raise HTTPException(status_code=400, detail="From address is not a valid email")

    reply_to = (smtp.reply_to or "").strip()
    if reply_to and not email_service.is_valid_email(reply_to):
        raise HTTPException(status_code=400, detail="Reply-To is not a valid email")

    base_url = (smtp.base_url or "").strip()
    if base_url and not (base_url.startswith("http://") or base_url.startswith("https://")):
        raise HTTPException(status_code=400, detail="Base URL must start with http:// or https://")

    cfg.save_smtp_config(cfg.SMTPConfig(
        enabled=smtp.enabled,
        host=(smtp.host or "").strip(),
        port=smtp.port,
        security=security,
        username=smtp.username or "",
        password=smtp.password or "",  # blank => cfg preserves existing
        from_address=from_address,
        from_name=smtp.from_name or "",
        reply_to=reply_to,
        timeout_seconds=smtp.timeout_seconds,
        base_url=base_url,
    ))
    return {"status": "ok"}


@app.post("/api/config/smtp/test")
async def api_test_smtp(body: SMTPTestModel, user: dict = Depends(auth.require_admin)):
    """Send a test email using the SAVED SMTP config (no secrets travel in the
    request). Maps typed email errors to specific, user-safe messages."""
    recipient = (body.recipient or "").strip()
    try:
        await asyncio.to_thread(email_service.send_test_email, recipient)
        return {"status": "sent", "recipient": recipient}
    except email_service.EmailError as e:
        # not_configured / invalid_recipient are client errors (400);
        # everything else is an upstream/relay failure (502).
        status_code = 400 if e.code in ("not_configured", "invalid_recipient") else 502
        return JSONResponse(
            status_code=status_code,
            content={"status": "error", "code": e.code, "message": e.message},
        )


@app.get("/api/config/settings")
async def api_get_settings(user: dict = Depends(auth.require_auth)):
    """Get application settings."""
    settings = cfg.get_settings()
    return {
        "backup_dir": settings.backup_dir,
        "pg_dump_path": settings.pg_dump_path,
        "pg_restore_path": settings.pg_restore_path,
        "max_upload_size_gb": settings.max_upload_size_gb,
        "lock_wait_timeout_seconds": settings.lock_wait_timeout_seconds,
        "log_level": settings.log_level,
        "context_path": settings.context_path,
        "effective_context_path": cfg.get_context_path(),
        "context_path_from_env": bool(os.environ.get('ROOT_PATH', '').strip()),
    }


@app.post("/api/config/settings")
async def api_save_settings(settings: SettingsModel, user: dict = Depends(auth.require_admin)):
    """Save application settings."""
    try:
        cfg.save_settings(cfg.Settings(
            backup_dir=settings.backup_dir,
            pg_dump_path=settings.pg_dump_path,
            pg_restore_path=settings.pg_restore_path,
            max_upload_size_gb=settings.max_upload_size_gb,
            lock_wait_timeout_seconds=settings.lock_wait_timeout_seconds,
            log_level=settings.log_level,
            context_path=settings.context_path,
        ))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # Apply log level change immediately
    apply_log_level(settings.log_level)
    restart_required = cfg._normalize_context_path(settings.context_path) != _context_path
    return {"success": True, "message": "Settings saved", "restart_required": restart_required}


@app.get("/api/config/query-settings")
async def api_get_query_settings(user: dict = Depends(auth.require_auth)):
    """Get query editor settings."""
    qs = cfg.get_query_settings()
    return {"autocommit": qs.autocommit}


@app.post("/api/config/query-settings")
async def api_save_query_settings(data: dict, user: dict = Depends(auth.require_admin)):
    """Save query editor settings."""
    cfg.save_query_settings(cfg.QuerySettings(
        autocommit=bool(data.get("autocommit", False)),
    ))
    return {"success": True, "message": "Query settings saved"}


# =============================================================================
# Operation History API
# =============================================================================

@app.get("/api/operations")
async def api_operations_history(limit: int = 10, user: dict = Depends(auth.require_auth)):
    """Get operation history."""
    try:
        operation_logger = op_logger.get_logger()
        history = operation_logger.get_operation_history(limit=limit)
        return {"success": True, "operations": history}
    except Exception as e:
        logger.error(f"Error retrieving operation history: {e}")
        raise HTTPException(status_code=500, detail="Internal server error (see server logs)")


@app.get("/api/operations/{operation_id}")
async def api_operation_detail(operation_id: str, user: dict = Depends(auth.require_auth)):
    """Get details of a specific operation."""
    try:
        operation_logger = op_logger.get_logger()
        operation = operation_logger.get_operation(operation_id)
        if operation is None:
            raise HTTPException(status_code=404, detail="Operation not found")
        return {"success": True, "operation": operation}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving operation details: {e}")
        raise HTTPException(status_code=500, detail="Internal server error (see server logs)")


@app.get("/api/operations/{operation_id}/log")
async def api_operation_log_download(operation_id: str, user: dict = Depends(auth.require_auth)):
    """Download the log file for a specific operation."""
    try:
        operation_logger = op_logger.get_logger()
        log_path = operation_logger.get_log_file_path(operation_id)
        if log_path is None or not log_path.exists():
            raise HTTPException(status_code=404, detail="Log file not found")
        return FileResponse(
            path=str(log_path),
            filename=f"operation_{operation_id}.log",
            media_type="text/plain"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading log file: {e}")
        raise HTTPException(status_code=500, detail="Internal server error (see server logs)")


@app.post("/api/operations/{operation_id}/cancel")
async def api_cancel_operation(operation_id: str, user: dict = Depends(auth.require_operator)):
    """Cancel a running operation."""
    cancel_event = _running_operations.get(operation_id)
    if cancel_event:
        cancel_event.set()
        logger.info(f"Cancel requested for operation {operation_id}")
        return {"success": True, "message": "Cancel signal sent"}

    # Operation not in memory — check if it's a stale "running" entry in history
    operation_logger = op_logger.get_logger()
    op = operation_logger.get_operation(operation_id)
    if op and op.get("status") == "running":
        operation_logger.complete_operation(operation_id, status="failed", error="Operation was no longer running (server restarted)")
        logger.info(f"Marked stale operation {operation_id} as failed")
        return {"success": True, "message": "Stale operation marked as failed"}

    raise HTTPException(status_code=404, detail="Operation not found")


@app.post("/api/operations/clear")
async def api_clear_operations_history(user: dict = Depends(auth.require_admin)):
    """Clear all completed/failed/cancelled operations from history."""
    try:
        operation_logger = op_logger.get_logger()
        removed = operation_logger.clear_history(keep_running=True)
        logger.info(f"Cleared {removed} operations from history")
        return {"success": True, "removed": removed}
    except Exception as e:
        logger.error(f"Error clearing operations history: {e}")
        raise HTTPException(status_code=500, detail="Internal server error (see server logs)")


# =============================================================================
# Scheduled Backups
# =============================================================================
#
# Definitions live in config.ini under [schedule:<name>]; mutable run-state
# lives in config/schedule_state.json. The in-process Scheduler (app/scheduler)
# ticks every 30s and calls _execute_schedule for each due, enabled schedule.
# All management mutations are admin; list / run-now / history / preview are
# operator-level. Run-now additionally re-checks per-user endpoint scoping.

_MAX_SCHEDULES = 50
_MIN_INTERVAL_MINUTES = 15
_AUTO_DISABLE_AFTER = 5


def _schedule_to_dict(sched: cfg.ScheduleConfig) -> dict:
    """Full schedule config as a JSON dict (schemas echoed as a list, matching
    the ScheduleModel input shape so the edit form round-trips)."""
    return {
        "name": sched.name,
        "cron": sched.cron,
        "endpoint": sched.endpoint,
        "database": sched.database,
        "enabled": sched.enabled,
        "large_objects": sched.large_objects,
        "no_owner": sched.no_owner,
        "no_privileges": sched.no_privileges,
        "no_tablespaces": sched.no_tablespaces,
        "no_comments": sched.no_comments,
        "data_only": sched.data_only,
        "schema_only": sched.schema_only,
        "clean": sched.clean,
        "create": sched.create,
        "schemas": [s.strip() for s in sched.schemas.split(",") if s.strip()],
        "exclude_table": sched.exclude_table,
        "exclude_table_data": sched.exclude_table_data,
        "exclude_schema": sched.exclude_schema,
        "dest_kind": sched.dest_kind,
        "dest_target": sched.dest_target,
        "delete_local_after_copy": sched.delete_local_after_copy,
        "keep_last_n": sched.keep_last_n,
        "notify": sched.notify,
        "notify_recipients": [r.strip() for r in sched.notify_recipients.split(",") if r.strip()],
    }


def _validate_and_build_schedule(model: ScheduleModel) -> cfg.ScheduleConfig:
    """Enforce every save-time constraint (see plan section 7) and return the
    ScheduleConfig to persist. Raises HTTPException(400) on any violation."""
    # Name (charset + reserved-prefix guard).
    try:
        cfg.validate_schedule_name(model.name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Cron: parseable, and at least the minimum interval between fires.
    expr = (model.cron or "").strip()
    try:
        cron.parse(expr)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid cron expression: {e}")
    if cron.min_interval_minutes(expr) < _MIN_INTERVAL_MINUTES:
        raise HTTPException(
            status_code=400,
            detail=f"Schedule must not run more often than every {_MIN_INTERVAL_MINUTES} minutes",
        )
    # Reject expressions that can never fire (e.g. Feb 30) — otherwise next_run
    # would scan the whole horizon on every subsequent list poll.
    if cron.next_run(expr, datetime.now(timezone.utc)) is None:
        raise HTTPException(status_code=400,
                            detail="This cron expression never fires (impossible date)")

    # Endpoint must resolve.
    if not cfg.get_database_endpoint(model.endpoint):
        raise HTTPException(status_code=400, detail=f"Endpoint '{model.endpoint}' not found")

    # Database + identifiers/patterns.
    schemas = [s.strip() for s in model.schemas if s and s.strip()]
    try:
        br._validate_identifier(model.database, "database")
        for s in schemas:
            br._validate_identifier(s, "schema")
        for label, val in (
            ("exclude_table", model.exclude_table),
            ("exclude_table_data", model.exclude_table_data),
            ("exclude_schema", model.exclude_schema),
        ):
            if val and val.strip():
                br._validate_table_pattern(val.strip(), label)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # data-only / schema-only are mutually exclusive (mirrors the manual path).
    if model.data_only and model.schema_only:
        raise HTTPException(status_code=400, detail="data-only and schema-only are mutually exclusive")

    # Destination.
    if model.dest_kind not in ("none", "s3", "fileshare", "filebrowser"):
        raise HTTPException(status_code=400, detail="Invalid destination kind")
    dest_target = (model.dest_target or "").strip()
    if model.dest_kind == "none":
        if model.delete_local_after_copy:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the local copy when there is no remote destination",
            )
        dest_target = ""
    else:
        if not dest_target:
            raise HTTPException(status_code=400, detail="A destination target is required")
        resolver = {
            "s3": cfg.get_s3_storage_config,
            "fileshare": cfg.get_fileshare_config,
            "filebrowser": cfg.get_filebrowser_config,
        }[model.dest_kind]
        if not resolver(dest_target):
            raise HTTPException(status_code=400, detail=f"Destination target '{dest_target}' not found")

    if model.keep_last_n < 0:
        raise HTTPException(status_code=400, detail="keep_last_n must be zero or greater")

    # Notifications: policy against the fixed set + each recipient address.
    notify = (model.notify or "off").strip().lower()
    if notify not in cfg.NOTIFY_POLICIES:
        raise HTTPException(status_code=400,
                            detail=f"Invalid notify policy. Allowed: {', '.join(cfg.NOTIFY_POLICIES)}")
    notify_recipients = [r.strip() for r in model.notify_recipients if r and r.strip()]
    for addr in notify_recipients:
        if not email_service.is_valid_email(addr):
            raise HTTPException(status_code=400,
                                detail=f"Invalid notification recipient address: {addr}")

    return cfg.ScheduleConfig(
        name=model.name,
        cron=expr,
        endpoint=model.endpoint,
        database=model.database,
        enabled=model.enabled,
        large_objects=model.large_objects,
        no_owner=model.no_owner,
        no_privileges=model.no_privileges,
        no_tablespaces=model.no_tablespaces,
        no_comments=model.no_comments,
        data_only=model.data_only,
        schema_only=model.schema_only,
        clean=model.clean,
        create=model.create,
        schemas=",".join(schemas),
        exclude_table=(model.exclude_table or "").strip(),
        exclude_table_data=(model.exclude_table_data or "").strip(),
        exclude_schema=(model.exclude_schema or "").strip(),
        dest_kind=model.dest_kind,
        dest_target=dest_target,
        delete_local_after_copy=model.delete_local_after_copy,
        keep_last_n=model.keep_last_n,
        notify=notify,
        notify_recipients=",".join(notify_recipients),
    )


# ---------------------------------------------------------------------------
# Execution (called by the scheduler tick and by run-now)
# ---------------------------------------------------------------------------

def _record_schedule_failure(name: str, sched: cfg.ScheduleConfig, status: str, error: str) -> None:
    """Persist a failure, bump consecutive_failures, and auto-disable at the
    threshold. Never deletes local data."""
    now = datetime.now(timezone.utc)
    entry = schedule_state.load().get(name, {})
    failures = int(entry.get("consecutive_failures", 0) or 0) + 1
    schedule_state.mark(
        name,
        last_status=status,
        last_error=error,
        last_run=now.isoformat(),
        consecutive_failures=failures,
    )
    if failures >= _AUTO_DISABLE_AFTER and sched.enabled:
        try:
            cfg.save_schedule(dataclasses.replace(sched, enabled=False))
            logger.warning("Schedule '%s' auto-disabled after %d consecutive failures", name, failures)
        except Exception as exc:
            logger.error("Failed to auto-disable schedule '%s': %s", name, exc)


def apply_local_retention(sched: cfg.ScheduleConfig) -> None:
    """Keep only the newest keep_last_n local backups for this schedule's DB.
    keep_last_n == 0 means unlimited. Deletes only files matching the DB prefix,
    always through the traversal-guarded deleter."""
    if sched.keep_last_n <= 0:
        return
    try:
        # Anchored match on the exact generated pattern "{database}_YYYYMMDD_HHMMSS.backup"
        # — a prefix match would delete another DB's backups (e.g. "sales" vs
        # "sales_archive"), since DB names may contain '_'/'-'/'.'.
        pat = re.compile(rf"^{re.escape(sched.database)}_\d{{8}}_\d{{6}}\.backup$")
        # list_backup_files() is already sorted newest-first (modified desc).
        matching = [f for f in br.list_backup_files() if pat.match(f["name"])]
        for f in matching[sched.keep_last_n:]:
            br.delete_backup(f["name"])
    except Exception as exc:
        logger.warning("Local retention for schedule '%s' failed: %s", sched.name, exc)


def _notify_schedule_outcome(sched: cfg.ScheduleConfig, *, status: str, trigger: str,
                             filename=None, size=None, duration_seconds=None,
                             error: str = None) -> None:
    """Best-effort email notification for a finished schedule run. Applies the
    schedule's policy, checks SMTP is enabled and that recipients exist, then
    hands off to email_service.send_schedule_notification (which itself never
    raises). This whole function is wrapped so it can NEVER fail a backup.

    Policy match: always -> any outcome; on_failure -> any failure (incl.
    copy_failed); on_success -> success only. ``status == "success"`` is the
    only success; everything else is a failure."""
    try:
        policy = (sched.notify or "off").strip().lower()
        if policy == "off":
            return
        succeeded = status == "success"
        if policy == "on_success" and not succeeded:
            return
        if policy == "on_failure" and succeeded:
            return
        recipients = [r.strip() for r in (sched.notify_recipients or "").split(",") if r.strip()]
        if not recipients:
            return
        smtp = cfg.get_smtp_config()
        if not smtp.enabled or not smtp.host:
            return
        destination = sched.dest_kind if sched.dest_kind and sched.dest_kind != "none" else "local"
        email_service.send_schedule_notification(
            recipients,
            schedule_name=sched.name,
            status=status,
            endpoint=sched.endpoint,
            database=sched.database,
            filename=filename,
            size=size,
            duration_seconds=duration_seconds,
            destination=destination,
            trigger=trigger,
            error=error,
        )
    except Exception as exc:
        logger.warning("Schedule notification for '%s' skipped: %s",
                       getattr(sched, "name", "?"), exc.__class__.__name__)


async def _execute_schedule(name, sched, *, trigger="schedule", operation_id=None, filename=None):
    """Run a single backup for schedule ``name``. Reuses the manual backup
    machinery (run_backup generator + broadcaster + _running_operations) and
    adds the optional remote-push + verified-delete phases.

    Called by the scheduler tick (trigger="schedule", no operation_id) and by
    run-now (trigger="manual-schedule", pre-created operation_id + filename)."""
    now = datetime.now(timezone.utc)
    minute_key = now.strftime("%Y%m%d%H%M")
    ol = op_logger.get_logger()

    # Same-minute de-dup: only for tick-driven runs (the 30s tick sees each
    # minute ~twice). Manual runs are intentional and always proceed.
    if trigger == "schedule":
        prev = schedule_state.load().get(name, {})
        if prev.get("last_fired_minute") == minute_key:
            return
    schedule_state.mark(name, last_fired_minute=minute_key, last_status="running", last_error="")

    # 1. Endpoint must still exist.
    endpoint = cfg.get_database_endpoint(sched.endpoint)
    if not endpoint:
        if operation_id:
            ol.complete_operation(operation_id, status="failed", error="Endpoint not found")
        _record_schedule_failure(name, sched, "failed", "Endpoint not found")
        _notify_schedule_outcome(
            sched, status="failed", trigger=trigger,
            duration_seconds=(datetime.now(timezone.utc) - now).total_seconds(),
            error="Endpoint not found")
        return

    # 2. Replica + SSM tunnel resolution (mirrors the manual path).
    conn_endpoint = endpoint
    from_replica = bool(endpoint.backup_use_replica and endpoint.replica_host)
    if from_replica:
        conn_endpoint = dataclasses.replace(endpoint, host=endpoint.replica_host)
    try:
        host, port = await asyncio.to_thread(get_endpoint_host_port, conn_endpoint)
    except Exception as exc:
        if operation_id:
            ol.complete_operation(operation_id, status="failed", error=f"Connection failed: {exc}")
        _record_schedule_failure(name, sched, "failed", f"Connection failed: {exc}")
        _notify_schedule_outcome(
            sched, status="failed", trigger=trigger,
            duration_seconds=(datetime.now(timezone.utc) - now).total_seconds(),
            error=f"Connection failed: {exc}")
        return

    # 3. Options + output file.
    schemas = [s.strip() for s in sched.schemas.split(",") if s.strip()] or None
    options = br.BackupOptions(
        large_objects=sched.large_objects,
        no_owner=sched.no_owner,
        no_privileges=sched.no_privileges,
        no_tablespaces=sched.no_tablespaces,
        no_comments=sched.no_comments,
        data_only=sched.data_only,
        schema_only=sched.schema_only,
        clean=sched.clean,
        create=sched.create,
        exclude_table=sched.exclude_table or None,
        exclude_table_data=sched.exclude_table_data or None,
        exclude_schema=sched.exclude_schema or None,
        schemas=schemas,
    )
    if not filename:
        filename = br.generate_backup_filename(sched.database)
    output_file = str(br.get_backup_dir() / filename)

    # 4. Operation record (pre-created by run-now, else created here).
    if operation_id is None:
        operation_id = ol.start_operation(
            operation_type="backup",
            endpoint=sched.endpoint,
            database=sched.database,
            metadata={
                "trigger": trigger,
                "schedule": name,
                "scheduled": True,
                "filename": filename,
                "dest_kind": sched.dest_kind,
                "dest_target": sched.dest_target,
                "delete_local_after_copy": sched.delete_local_after_copy,
            },
        )
    _running_operations[operation_id] = asyncio.Event()
    schedule_state.mark(name, last_operation_id=operation_id, last_filename=filename)

    # --- Phase 1: pg_dump (reuse run_backup generator + broadcaster) ---
    broadcaster.start_operation(operation_id)
    backup_ok = False
    try:
        async for progress in br.run_backup(
            database=sched.database,
            host=host,
            port=port,
            username=endpoint.username,
            password=endpoint.password,
            output_file=output_file,
            options=options,
            operation_id=operation_id,
            cancel_event=_running_operations[operation_id],
            pg_dump_path=cfg.pg_tool_path("pg_dump", endpoint.pg_version),
            sslmode=endpoint.sslmode,
            pg_version=int(endpoint.pg_version),
        ):
            broadcaster.broadcast(operation_id, progress)
            if progress.get("type") == "complete":
                backup_ok = bool(progress.get("success"))
    except Exception as exc:
        logger.exception("Scheduled backup '%s' failed during pg_dump: %s", name, exc)
        ol.complete_operation(operation_id, status="failed", error=str(exc))
    finally:
        _running_operations.pop(operation_id, None)
        broadcaster.end_operation(operation_id)

    if not backup_ok:
        # run_backup already completed the operation as failed; ensure state too.
        _record_schedule_failure(name, sched, "failed", "Backup failed")
        _notify_schedule_outcome(
            sched, status="failed", trigger=trigger, filename=filename,
            duration_seconds=(datetime.now(timezone.utc) - now).total_seconds(),
            error="Backup failed (pg_dump)")
        return

    # --- Phase 2: remote push (only when a destination is configured) ---
    if sched.dest_kind == "none":
        ol.complete_operation(operation_id, status="completed")
        schedule_state.mark(name, last_status="success", last_run=now.isoformat(),
                            last_error="", consecutive_failures=0)
        try:
            final_size = os.path.getsize(output_file)
        except OSError:
            final_size = None
        _notify_schedule_outcome(
            sched, status="success", trigger=trigger, filename=filename, size=final_size,
            duration_seconds=(datetime.now(timezone.utc) - now).total_seconds())
        apply_local_retention(sched)
        return

    try:
        local_size = os.path.getsize(output_file)
    except OSError:
        local_size = -1
    upload_fn = {
        "s3": rs.s3_upload_backup,
        "fileshare": rs.webdav_upload_backup,
        "filebrowser": rs.filebrowser_upload_backup,
    }[sched.dest_kind]
    # _run_with_progress re-raises on exception, so wrap it: a background task
    # must never raise.
    try:
        result = await asyncio.to_thread(
            _run_with_progress, "upload", sched.dest_kind, sched.dest_target, filename,
            lambda cb: upload_fn(sched.dest_target, filename, progress_cb=cb),
        )
    except Exception as exc:
        result = {"success": False, "error": str(exc)}

    if not result.get("success"):
        # Backup is safe locally; complete the op as completed with a note and
        # NEVER delete the local file.
        err = f"remote push failed: {result.get('error')}"
        ol.complete_operation(operation_id, status="completed", error=err)
        ol.log_message(operation_id, f"Remote push failed; local copy kept: {result.get('error')}")
        _record_schedule_failure(name, sched, "copy_failed", err)
        _notify_schedule_outcome(
            sched, status="copy_failed", trigger=trigger, filename=filename,
            size=(local_size if local_size >= 0 else None),
            duration_seconds=(datetime.now(timezone.utc) - now).total_seconds(),
            error=err)
        return

    # --- Phase 3: verified delete-local (opt-in) ---
    verified = result.get("success") is True and result.get("size") == local_size
    if sched.delete_local_after_copy and verified:
        del_res = br.delete_backup(filename)
        ol.log_message(
            operation_id,
            "Local copy deleted after verified upload" if del_res.get("success")
            else f"Local delete note (harmless): {del_res.get('error')}",
        )
    elif sched.delete_local_after_copy and not verified:
        ol.log_message(operation_id, "Upload unverified (size mismatch); keeping local copy")

    ol.complete_operation(operation_id, status="completed")
    schedule_state.mark(name, last_status="success", last_run=now.isoformat(),
                        last_error="", consecutive_failures=0)
    _notify_schedule_outcome(
        sched, status="success", trigger=trigger, filename=filename,
        size=(local_size if local_size >= 0 else None),
        duration_seconds=(datetime.now(timezone.utc) - now).total_seconds())
    apply_local_retention(sched)


def _reconcile_schedule_state() -> None:
    """On boot, flip any schedule state entry stuck at 'running' (pod died
    mid-run) to 'failed' — mirrors the stale-operation cleanup."""
    try:
        state = schedule_state.load()
        for name, entry in state.items():
            if isinstance(entry, dict) and entry.get("last_status") == "running":
                schedule_state.mark(
                    name,
                    last_status="failed",
                    last_error="Server restarted while a scheduled run was in progress",
                )
    except Exception as exc:
        logger.warning("Could not reconcile schedule state: %s", exc)


# ---------------------------------------------------------------------------
# Schedule API
# ---------------------------------------------------------------------------
# NOTE: the static sub-paths (/runs, /cron/preview) are declared before the
# /{name} routes so they aren't captured as a schedule name.

@app.get("/api/schedules")
async def api_list_schedules(user: dict = Depends(auth.require_operator)):
    """List all schedules with computed next_run (UTC) and merged run-state."""
    schedules = cfg.get_schedules()
    state = schedule_state.load()
    now = datetime.now(timezone.utc)
    result = []
    for name, sched in schedules.items():
        # Respect per-user endpoint scoping (F-01): hide schedules whose endpoint
        # the caller may not access.
        if not user_can_access_endpoint(user, sched.endpoint):
            continue
        st = state.get(name, {}) if isinstance(state.get(name), dict) else {}
        next_run = None
        cron_human = ""
        try:
            # next_run can scan many minutes for sparse crons — off the event loop.
            nxt = await asyncio.to_thread(cron.next_run, sched.cron, now)
            if nxt is not None:
                next_run = nxt.isoformat()
            cron_human = cron.describe(sched.cron)
        except ValueError:
            cron_human = "Invalid schedule"
        result.append({
            "name": name,
            "cron": sched.cron,
            "cron_human": cron_human,
            "endpoint": sched.endpoint,
            "database": sched.database,
            "enabled": sched.enabled,
            "dest_kind": sched.dest_kind,
            "dest_target": sched.dest_target,
            "delete_local_after_copy": sched.delete_local_after_copy,
            "keep_last_n": sched.keep_last_n,
            "next_run": next_run,
            "last_run": st.get("last_run"),
            "last_status": st.get("last_status"),
            "last_error": st.get("last_error"),
            "last_filename": st.get("last_filename"),
            "last_operation_id": st.get("last_operation_id"),
            "consecutive_failures": int(st.get("consecutive_failures", 0) or 0),
            "running": sched_engine.is_running(name),
        })
    return {"success": True, "schedules": result}


@app.get("/api/schedules/runs")
async def api_schedule_runs(limit: int = 50, user: dict = Depends(auth.require_operator)):
    """All scheduled / run-now backup runs, for the Recent-runs table."""
    limit = max(1, min(limit, 500))
    history = op_logger.get_logger().get_operation_history(limit=500)
    runs = [
        op for op in history
        if (op.get("metadata") or {}).get("trigger") in ("schedule", "manual-schedule")
    ][:limit]
    return {"success": True, "runs": runs}


@app.post("/api/schedules/cron/preview")
async def api_cron_preview(payload: CronPreviewModel, user: dict = Depends(auth.require_operator)):
    """Validate a cron expression and preview the next fire times. No persistence."""
    expr = (payload.cron or "").strip()
    try:
        cron.parse(expr)
    except ValueError as e:
        return {"valid": False, "error": str(e), "human": "", "next_runs": [],
                "min_interval_minutes": 0, "warning": ""}
    count = max(1, min(payload.count, 20))
    now = datetime.now(timezone.utc)
    # Cron scans can be heavy for sparse expressions — run off the event loop.
    runs = await asyncio.to_thread(cron.next_runs, expr, now, count)
    next_runs = [dt.isoformat() for dt in runs]
    interval = await asyncio.to_thread(cron.min_interval_minutes, expr)
    warning = ""
    if not next_runs:
        warning = "This expression never fires (impossible date); it will be rejected on save"
    elif interval < _MIN_INTERVAL_MINUTES:
        warning = (f"Runs more often than every {_MIN_INTERVAL_MINUTES} minutes; "
                   f"this will be rejected on save")
    return {
        "valid": True,
        "error": "",
        "human": cron.describe(expr),
        "next_runs": next_runs,
        "min_interval_minutes": interval,
        "warning": warning,
    }


@app.post("/api/schedules")
async def api_save_schedule(schedule: ScheduleModel, request: Request,
                            user: dict = Depends(auth.require_admin)):
    """Create or update a schedule (the name is the key). Full validation."""
    existing = cfg.get_schedules()
    if schedule.name not in existing and len(existing) >= _MAX_SCHEDULES:
        raise HTTPException(status_code=400,
                            detail=f"Maximum number of schedules ({_MAX_SCHEDULES}) reached")
    # Validation includes cron next_run/min_interval scans; run off the event loop.
    sched_cfg = await asyncio.to_thread(_validate_and_build_schedule, schedule)
    cfg.save_schedule(sched_cfg)
    # A successful re-save (edit) clears the auto-disable failure streak.
    schedule_state.mark(schedule.name, consecutive_failures=0)
    ip = request.client.host if request.client else "unknown"
    auth.audit_log("schedule_saved", user["username"], ip,
                   f"name={schedule.name}, cron={sched_cfg.cron}, endpoint={schedule.endpoint}, "
                   f"database={schedule.database}, enabled={schedule.enabled}")
    return {"success": True, "name": schedule.name}


@app.get("/api/schedules/{name}")
async def api_get_schedule(name: str, user: dict = Depends(auth.require_admin)):
    """Full config for one schedule (admin only — echoes the whole definition)."""
    sched = cfg.get_schedule(name)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return _schedule_to_dict(sched)


@app.delete("/api/schedules/{name}")
async def api_delete_schedule(name: str, request: Request,
                              user: dict = Depends(auth.require_admin)):
    """Delete a schedule and its run-state."""
    if not cfg.get_schedule(name):
        raise HTTPException(status_code=404, detail="Schedule not found")
    cfg.delete_schedule(name)
    schedule_state.drop(name)
    ip = request.client.host if request.client else "unknown"
    auth.audit_log("schedule_deleted", user["username"], ip, f"name={name}")
    return {"success": True}


@app.patch("/api/schedules/{name}/enabled")
async def api_toggle_schedule(name: str, toggle: ScheduleToggleModel, request: Request,
                              user: dict = Depends(auth.require_admin)):
    """Enable/disable a schedule. Re-enabling clears the failure streak."""
    sched = cfg.get_schedule(name)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    cfg.save_schedule(dataclasses.replace(sched, enabled=toggle.enabled))
    if toggle.enabled:
        schedule_state.mark(name, consecutive_failures=0)
    ip = request.client.host if request.client else "unknown"
    auth.audit_log("schedule_enabled", user["username"], ip,
                   f"name={name}, enabled={toggle.enabled}")
    return {"success": True, "enabled": toggle.enabled}


@app.post("/api/schedules/{name}/run")
async def api_run_schedule_now(name: str, request: Request,
                               user: dict = Depends(auth.require_operator)):
    """Run a schedule immediately (operator, re-checked against endpoint scope)."""
    sched = cfg.get_schedule(name)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    require_endpoint_access(user, sched.endpoint)

    # Reserve atomically THROUGH the scheduler: this is what makes the 409 real
    # and keeps run-now inside the global single-backup concurrency guard, so a
    # double-click can't launch two concurrent pg_dumps into the same file.
    scheduler = sched_engine.get_scheduler()
    if not scheduler.reserve(name):
        raise HTTPException(status_code=409, detail="This schedule is already running")
    try:
        filename = br.generate_backup_filename(sched.database)
        operation_id = op_logger.get_logger().start_operation(
            operation_type="backup",
            endpoint=sched.endpoint,
            database=sched.database,
            metadata={
                "trigger": "manual-schedule",
                "schedule": name,
                "scheduled": True,
                "filename": filename,
                "dest_kind": sched.dest_kind,
                "dest_target": sched.dest_target,
                "delete_local_after_copy": sched.delete_local_after_copy,
            },
        )
    except Exception:
        scheduler.release(name)
        raise
    # run_reserved holds the global semaphore for the run and releases the
    # reservation when done.
    asyncio.create_task(scheduler.run_reserved(
        name, sched, trigger="manual-schedule", operation_id=operation_id, filename=filename))
    ip = request.client.host if request.client else "unknown"
    auth.audit_log("schedule_run_now", user["username"], ip, f"name={name}")
    return {"success": True, "operation_id": operation_id}


@app.get("/api/schedules/{name}/history")
async def api_schedule_history(name: str, user: dict = Depends(auth.require_operator)):
    """Recent runs for one schedule (filtered from the operation history)."""
    sched = cfg.get_schedule(name)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    require_endpoint_access(user, sched.endpoint)
    history = op_logger.get_logger().get_operation_history(limit=100)
    runs = [op for op in history if (op.get("metadata") or {}).get("schedule") == name]
    return {"success": True, "runs": runs}


# =============================================================================
# User Management API (admin only)
# =============================================================================

@app.get("/api/users")
async def api_list_app_users(user: dict = Depends(auth.require_admin)):
    """List all application users."""
    users = auth.get_all_users()
    return [
        {
            "username": u.username,
            "role": u.role,
            "enabled": u.enabled,
            "locked": u.locked,
            "failed_attempts": u.failed_attempts,
            "created_at": u.created_at,
            "last_login": u.last_login,
            "created_by": u.created_by,
            "endpoints": u.endpoints,
        }
        for u in users.values()
    ]


@app.post("/api/users")
async def api_create_user(req: UserCreateModel, request: Request, user: dict = Depends(auth.require_admin)):
    """Create a new application user."""
    result = auth.create_user(req.username, req.password, req.role,
                              created_by=user["username"], endpoints=req.endpoints)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    ip = request.client.host if request.client else "unknown"
    auth.audit_log("user_created", req.username, ip, f"role={req.role}, by={user['username']}")
    return result


@app.put("/api/users/{username}")
async def api_update_user(username: str, req: UserUpdateModel, request: Request, user: dict = Depends(auth.require_admin)):
    """Update user role/enabled status."""
    result = auth.update_user(username, role=req.role, enabled=req.enabled, endpoints=req.endpoints)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    ip = request.client.host if request.client else "unknown"
    changes = []
    if req.role is not None:
        changes.append(f"role={req.role}")
    if req.enabled is not None:
        changes.append(f"enabled={req.enabled}")
    if req.endpoints is not None:
        changes.append(f"endpoints={req.endpoints}")
    auth.audit_log("user_updated", username, ip, f"{', '.join(changes)}, by={user['username']}")
    return result


@app.delete("/api/users/{username}")
async def api_delete_user(username: str, request: Request, user: dict = Depends(auth.require_admin)):
    """Delete an application user."""
    if username == user["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    result = auth.delete_user(username)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    ip = request.client.host if request.client else "unknown"
    auth.audit_log("user_deleted", username, ip, f"by={user['username']}")
    return result


@app.post("/api/users/{username}/reset-password")
async def api_reset_user_password(username: str, req: UserPasswordResetModel, request: Request, user: dict = Depends(auth.require_admin)):
    """Admin-initiated password reset for a user."""
    result = auth.reset_user_password(username, req.new_password)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    ip = request.client.host if request.client else "unknown"
    auth.audit_log("password_reset", username, ip, f"by={user['username']}")
    return result


@app.post("/api/users/{username}/unlock")
async def api_unlock_user(username: str, request: Request, user: dict = Depends(auth.require_admin)):
    """Unlock a locked user account."""
    result = auth.update_user(username, locked=False)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    ip = request.client.host if request.client else "unknown"
    auth.audit_log("account_unlocked", username, ip, f"by={user['username']}")
    return result


@app.get("/api/audit-log")
async def api_get_audit_log(limit: int = 100, user: dict = Depends(auth.require_admin)):
    """Get recent audit log entries."""
    return auth.get_audit_log(limit=limit)


# =============================================================================
# WebSocket helpers
# =============================================================================

async def _stream_to_websocket(websocket: WebSocket, operation_id: str):
    """Subscribe to a running operation's broadcaster and stream messages to WebSocket."""
    history, queue = broadcaster.subscribe(operation_id)
    try:
        for msg in history:
            await websocket.send_json(msg)
        while True:
            msg = await queue.get()
            if msg is None:
                # Sentinel from end_operation() — operation is done
                break
            await websocket.send_json(msg)
    finally:
        broadcaster.unsubscribe(operation_id, queue)


# =============================================================================
# WebSocket: Backup
# =============================================================================

@app.websocket("/ws/backup")
async def websocket_backup(websocket: WebSocket):
    """WebSocket endpoint for backup with real-time progress."""
    await websocket.accept()

    user = await check_websocket_auth(websocket)
    if not user:
        await websocket.send_json({"type": "error", "message": "Authentication required"})
        await websocket.close()
        return
    if user["role"] == "viewer":
        await websocket.send_json({"type": "error", "message": "Operator access required"})
        await websocket.close()
        return

    try:
        data = await websocket.receive_json()

        endpoint_name = data.get("endpoint_name")
        database = data.get("database")
        backup_filename = data.get("backup_filename")

        endpoint = cfg.get_database_endpoint(endpoint_name)
        if not endpoint:
            await websocket.send_json({"type": "error", "message": "Endpoint not found"})
            await websocket.close()
            return
        if not user_can_access_endpoint(user, endpoint_name):
            await websocket.send_json({"type": "error", "message": f"Access to endpoint '{endpoint_name}' is not allowed"})
            await websocket.close()
            return

        # If configured, back up from the read replica instead of the primary.
        # Use a copy with host=replica_host so SSM tunnel resolution targets it too.
        conn_endpoint = endpoint
        from_replica = bool(endpoint.backup_use_replica and endpoint.replica_host)
        if from_replica:
            conn_endpoint = dataclasses.replace(endpoint, host=endpoint.replica_host)

        # Resolve connection (auto-start SSM tunnel if needed)
        try:
            host, port = get_endpoint_host_port(conn_endpoint)
        except ValueError as e:
            await websocket.send_json({"type": "error", "message": str(e)})
            await websocket.close()
            return

        # Handle custom backup filename
        output_file = None
        if backup_filename:
            is_valid, error_msg = br.validate_backup_filename(backup_filename)
            if not is_valid:
                await websocket.send_json({"type": "error", "message": f"Invalid filename: {error_msg}"})
                await websocket.close()
                return
            safe_filename = br.sanitize_backup_filename(backup_filename)
            backup_dir = br.get_backup_dir()
            output_file = str(backup_dir / safe_filename)

        # Get schemas if schema mode is enabled
        schemas = data.get("schemas")
        if schemas and not isinstance(schemas, list):
            schemas = None

        # Parse exclude patterns
        exclude_table = data.get("exclude_table") or None
        exclude_table_data = data.get("exclude_table_data") or None

        # Enforce mutual exclusivity server-side
        data_only = data.get("data_only", False)
        schema_only = data.get("schema_only", False)
        if data_only and schema_only:
            await websocket.send_json({
                "type": "error",
                "message": "data-only and schema-only are mutually exclusive"
            })
            await websocket.close()
            return

        options = br.BackupOptions(
            large_objects=data.get("large_objects", True),
            no_owner=data.get("no_owner", True),
            no_privileges=data.get("no_privileges", True),
            no_tablespaces=data.get("no_tablespaces", True),
            no_comments=data.get("no_comments", True),
            data_only=data_only,
            schema_only=schema_only,
            clean=data.get("clean", False),
            create=data.get("create", False),
            exclude_table=exclude_table,
            exclude_table_data=exclude_table_data,
            schemas=schemas if schemas else None,
        )

        # Create operation log
        operation_logger = op_logger.get_logger()
        metadata = {
            "filename": backup_filename or br.generate_backup_filename(database),
            "large_objects": options.large_objects,
            "no_owner": options.no_owner,
            "no_privileges": options.no_privileges,
            "no_tablespaces": options.no_tablespaces,
            "no_comments": options.no_comments,
            "data_only": options.data_only,
            "schema_only": options.schema_only,
            "clean": options.clean,
            "create": options.create,
            "use_ssm": endpoint.use_ssm,
        }
        if from_replica:
            metadata["from_replica"] = True
            metadata["replica_host"] = endpoint.replica_host
        if schemas:
            metadata["schemas"] = schemas
        if options.exclude_table:
            metadata["exclude_table"] = options.exclude_table
        if options.exclude_table_data:
            metadata["exclude_table_data"] = options.exclude_table_data

        operation_id = operation_logger.start_operation(
            operation_type="backup",
            endpoint=endpoint_name,
            database=database,
            metadata=metadata
        )

        # SSM tunnel info as first broadcast message
        ssm_msg = None
        if endpoint.use_ssm:
            ssm_msg = {
                "type": "progress",
                "message": f"SSM tunnel active via {endpoint.jumphost_alias} -> localhost:{port}"
            }

        # Replica info message
        replica_msg = None
        if from_replica:
            replica_msg = {
                "type": "progress",
                "message": f"Backing up from read replica: {endpoint.replica_host}"
            }

        # Launch operation as background task (survives WS disconnect)
        cancel_event = asyncio.Event()
        _running_operations[operation_id] = cancel_event

        async def _run():
            try:
                if ssm_msg:
                    broadcaster.broadcast(operation_id, ssm_msg)
                if replica_msg:
                    broadcaster.broadcast(operation_id, replica_msg)
                async for progress in br.run_backup(
                    database=database,
                    host=host,
                    port=port,
                    username=endpoint.username,
                    password=endpoint.password,
                    output_file=output_file,
                    options=options,
                    operation_id=operation_id,
                    cancel_event=cancel_event,
                    pg_dump_path=cfg.pg_tool_path("pg_dump", endpoint.pg_version),
                    sslmode=endpoint.sslmode,
                    pg_version=int(endpoint.pg_version),
                ):
                    broadcaster.broadcast(operation_id, progress)
            except Exception as exc:
                logger.exception(f"Background backup failed: {exc}")
                broadcaster.broadcast(operation_id, {
                    "type": "complete", "success": False, "message": str(exc)
                })
                op_logger.get_logger().complete_operation(
                    operation_id, status="failed", error=str(exc)
                )
            finally:
                _running_operations.pop(operation_id, None)
                broadcaster.end_operation(operation_id)

        broadcaster.start_operation(operation_id)
        asyncio.create_task(_run())

        # Subscribe to the broadcaster and stream to this client
        await _stream_to_websocket(websocket, operation_id)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass
    finally:
        try:
            await websocket.close()
        except:
            pass


# =============================================================================
# WebSocket: Restore
# =============================================================================

@app.websocket("/ws/restore")
async def websocket_restore(websocket: WebSocket):
    """WebSocket endpoint for restore with real-time progress."""
    await websocket.accept()

    user = await check_websocket_auth(websocket)
    if not user:
        await websocket.send_json({"type": "error", "message": "Authentication required"})
        await websocket.close()
        return
    if user["role"] == "viewer":
        await websocket.send_json({"type": "error", "message": "Operator access required"})
        await websocket.close()
        return

    try:
        data = await websocket.receive_json()

        backup_file = data.get("backup_file")
        endpoint_name = data.get("endpoint_name")
        database = data.get("database")
        role = data.get("role")

        # Validate backup_file path is within backup directory
        if backup_file:
            backup_dir = br.get_backup_dir()
            backup_path = (backup_dir / Path(backup_file).name).resolve()
            try:
                backup_path.relative_to(backup_dir.resolve())
            except ValueError:
                await websocket.send_json({"type": "error", "message": "Invalid backup file path"})
                await websocket.close()
                return
            backup_file = str(backup_path)

        endpoint = cfg.get_database_endpoint(endpoint_name)
        if not endpoint:
            await websocket.send_json({"type": "error", "message": "Endpoint not found"})
            await websocket.close()
            return
        if not user_can_access_endpoint(user, endpoint_name):
            await websocket.send_json({"type": "error", "message": f"Access to endpoint '{endpoint_name}' is not allowed"})
            await websocket.close()
            return

        # Resolve connection (auto-start SSM tunnel if needed)
        try:
            host, port = get_endpoint_host_port(endpoint)
        except ValueError as e:
            await websocket.send_json({"type": "error", "message": str(e)})
            await websocket.close()
            return

        # Get schemas if schema mode is enabled
        schemas = data.get("schemas")
        if schemas and not isinstance(schemas, list):
            schemas = None

        # Parse exclude_schema: accept string (newline/comma separated) or list
        raw_exclude_schema = data.get("exclude_schema") if not schemas else None
        exclude_schema_list = None
        if raw_exclude_schema:
            if isinstance(raw_exclude_schema, list):
                exclude_schema_list = [s.strip() for s in raw_exclude_schema if s.strip()]
            elif isinstance(raw_exclude_schema, str):
                exclude_schema_list = [s.strip() for s in re.split(r'[\n,]+', raw_exclude_schema) if s.strip()]
            if not exclude_schema_list:
                exclude_schema_list = None

        # Parse exclude_tables: accept string (newline separated) or list
        raw_exclude_tables = data.get("exclude_tables")
        exclude_tables_list = None
        if raw_exclude_tables:
            if isinstance(raw_exclude_tables, list):
                exclude_tables_list = [t.strip() for t in raw_exclude_tables if t.strip()]
            elif isinstance(raw_exclude_tables, str):
                exclude_tables_list = [t.strip() for t in raw_exclude_tables.split('\n') if t.strip()]
            if not exclude_tables_list:
                exclude_tables_list = None

        # Parse jobs
        raw_jobs = data.get("jobs")
        jobs_val = None
        if raw_jobs is not None:
            try:
                jobs_val = int(raw_jobs)
                if jobs_val < 1:
                    jobs_val = None
            except (ValueError, TypeError):
                jobs_val = None

        options = br.RestoreOptions(
            clean=data.get("clean", True),
            no_owner=data.get("no_owner", True),
            no_privileges=data.get("no_privileges", True),
            role=role,
            exclude_schema=exclude_schema_list,
            schemas=schemas if schemas else None,
            data_only=data.get("data_only", False),
            schema_only=data.get("schema_only", False),
            no_comments=data.get("no_comments", False),
            no_tablespaces=data.get("no_tablespaces", False),
            no_publications=data.get("no_publications", False),
            no_subscriptions=data.get("no_subscriptions", False),
            jobs=jobs_val,
            exit_on_error=data.get("exit_on_error", False),
            exclude_tables=exclude_tables_list,
            timescaledb=data.get("timescaledb", False),
        )

        # Refuse to write to a read-only endpoint.
        if endpoint.read_only:
            await websocket.send_json({
                "type": "error",
                "message": f"Endpoint '{endpoint_name}' is read-only; restore is not allowed.",
            })
            await websocket.close()
            return

        # Destructive restore (--clean drops existing objects): require the
        # caller to echo the target database name as an explicit confirmation.
        if options.clean and data.get("confirm_database") != database:
            await websocket.send_json({
                "type": "error",
                "message": ("Conferma richiesta: il restore con --clean è distruttivo. "
                            "Conferma digitando il nome del database di destinazione."),
            })
            await websocket.close()
            return

        # Create operation log
        operation_logger = op_logger.get_logger()
        metadata = {
            "backup_file": backup_file,
            "clean": options.clean,
            "no_owner": options.no_owner,
            "no_privileges": options.no_privileges,
            "role": role,
            "use_ssm": endpoint.use_ssm,
        }
        if schemas:
            metadata["schemas"] = schemas
        if options.data_only:
            metadata["data_only"] = True
        if options.schema_only:
            metadata["schema_only"] = True
        if options.no_comments:
            metadata["no_comments"] = True
        if options.no_tablespaces:
            metadata["no_tablespaces"] = True
        if options.no_publications:
            metadata["no_publications"] = True
        if options.no_subscriptions:
            metadata["no_subscriptions"] = True
        if options.jobs:
            metadata["jobs"] = options.jobs
        if options.exit_on_error:
            metadata["exit_on_error"] = True
        if exclude_schema_list:
            metadata["exclude_schemas"] = exclude_schema_list
        if exclude_tables_list:
            metadata["exclude_tables"] = exclude_tables_list
        if options.timescaledb:
            metadata["timescaledb"] = True

        operation_id = operation_logger.start_operation(
            operation_type="restore",
            endpoint=endpoint_name,
            database=database,
            metadata=metadata
        )

        # SSM tunnel info as first broadcast message
        ssm_msg = None
        if endpoint.use_ssm:
            ssm_msg = {
                "type": "progress",
                "message": f"SSM tunnel active via {endpoint.jumphost_alias} -> localhost:{port}"
            }

        # Launch operation as background task (survives WS disconnect)
        cancel_event = asyncio.Event()
        _running_operations[operation_id] = cancel_event

        async def _run():
            try:
                if ssm_msg:
                    broadcaster.broadcast(operation_id, ssm_msg)
                async for progress in br.run_restore(
                    backup_file=backup_file,
                    database=database,
                    host=host,
                    port=port,
                    username=endpoint.username,
                    password=endpoint.password,
                    options=options,
                    operation_id=operation_id,
                    cancel_event=cancel_event,
                    pg_restore_path=cfg.pg_tool_path("pg_restore", endpoint.pg_version),
                    sslmode=endpoint.sslmode,
                ):
                    broadcaster.broadcast(operation_id, progress)
            except Exception as exc:
                logger.exception(f"Background restore failed: {exc}")
                broadcaster.broadcast(operation_id, {
                    "type": "complete", "success": False, "message": str(exc)
                })
                op_logger.get_logger().complete_operation(
                    operation_id, status="failed", error=str(exc)
                )
            finally:
                _running_operations.pop(operation_id, None)
                broadcaster.end_operation(operation_id)

        broadcaster.start_operation(operation_id)
        asyncio.create_task(_run())

        # Subscribe to the broadcaster and stream to this client
        await _stream_to_websocket(websocket, operation_id)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass
    finally:
        try:
            await websocket.close()
        except:
            pass


# =============================================================================
# WebSocket: Transfer
# =============================================================================

@app.websocket("/ws/transfer")
async def websocket_transfer(websocket: WebSocket):
    """WebSocket endpoint for transfer (backup + restore) with real-time progress."""
    await websocket.accept()

    user = await check_websocket_auth(websocket)
    if not user:
        await websocket.send_json({"type": "error", "message": "Authentication required"})
        await websocket.close()
        return
    if user["role"] == "viewer":
        await websocket.send_json({"type": "error", "message": "Operator access required"})
        await websocket.close()
        return

    try:
        data = await websocket.receive_json()

        source_endpoint_name = data.get("source_endpoint")
        source_database = data.get("source_database")
        dest_endpoint_name = data.get("dest_endpoint")
        dest_database = data.get("dest_database")
        dest_role = data.get("dest_role")

        source_endpoint = cfg.get_database_endpoint(source_endpoint_name)
        dest_endpoint = cfg.get_database_endpoint(dest_endpoint_name)

        if not source_endpoint:
            await websocket.send_json({"type": "error", "message": "Source endpoint not found"})
            await websocket.close()
            return

        if not dest_endpoint:
            await websocket.send_json({"type": "error", "message": "Destination endpoint not found"})
            await websocket.close()
            return

        # Enforce per-user endpoint scoping on both source and destination.
        for _ep_name in (source_endpoint_name, dest_endpoint_name):
            if not user_can_access_endpoint(user, _ep_name):
                await websocket.send_json({"type": "error", "message": f"Access to endpoint '{_ep_name}' is not allowed"})
                await websocket.close()
                return

        # Refuse to write to a read-only destination endpoint.
        if dest_endpoint.read_only:
            await websocket.send_json({
                "type": "error",
                "message": f"Destination endpoint '{dest_endpoint_name}' is read-only; transfer is not allowed.",
            })
            await websocket.close()
            return

        # Resolve connections for both endpoints
        try:
            source_host, source_port = get_endpoint_host_port(source_endpoint)
        except ValueError as e:
            await websocket.send_json({"type": "error", "message": f"Source: {str(e)}"})
            await websocket.close()
            return

        try:
            dest_host, dest_port = get_endpoint_host_port(dest_endpoint)
        except ValueError as e:
            await websocket.send_json({"type": "error", "message": f"Destination: {str(e)}"})
            await websocket.close()
            return

        # Get schemas if schema mode is enabled
        schemas = data.get("schemas")
        if schemas and not isinstance(schemas, list):
            schemas = None

        # Parse backup advanced options
        raw_bk = data.get("backup_options", {})
        if not isinstance(raw_bk, dict):
            raw_bk = {}

        bk_data_only = raw_bk.get("data_only", False)
        bk_schema_only = raw_bk.get("schema_only", False)
        if bk_data_only and bk_schema_only:
            await websocket.send_json({
                "type": "error",
                "message": "Backup: data-only and schema-only are mutually exclusive"
            })
            await websocket.close()
            return

        backup_options = br.BackupOptions(
            large_objects=raw_bk.get("large_objects", True),
            no_owner=raw_bk.get("no_owner", True),
            no_privileges=raw_bk.get("no_privileges", True),
            no_tablespaces=raw_bk.get("no_tablespaces", True),
            no_comments=raw_bk.get("no_comments", True),
            data_only=bk_data_only,
            schema_only=bk_schema_only,
            clean=raw_bk.get("clean", False),
            create=raw_bk.get("create", False),
            exclude_table=raw_bk.get("exclude_table") or None,
            exclude_table_data=raw_bk.get("exclude_table_data") or None,
            schemas=schemas if schemas else None,
        )

        # Parse restore advanced options
        raw_rs = data.get("restore_options", {})
        if not isinstance(raw_rs, dict):
            raw_rs = {}

        rs_data_only = raw_rs.get("data_only", False)
        rs_schema_only = raw_rs.get("schema_only", False)
        if rs_data_only and rs_schema_only:
            await websocket.send_json({
                "type": "error",
                "message": "Restore: data-only and schema-only are mutually exclusive"
            })
            await websocket.close()
            return

        # Parse restore exclude_schema
        raw_rs_exclude_schema = raw_rs.get("exclude_schema")
        rs_exclude_schema_list = None
        if raw_rs_exclude_schema:
            if isinstance(raw_rs_exclude_schema, list):
                rs_exclude_schema_list = [s.strip() for s in raw_rs_exclude_schema if s.strip()]
            elif isinstance(raw_rs_exclude_schema, str):
                rs_exclude_schema_list = [s.strip() for s in re.split(r'[\n,]+', raw_rs_exclude_schema) if s.strip()]
            if not rs_exclude_schema_list:
                rs_exclude_schema_list = None

        # Parse restore exclude_tables
        raw_rs_exclude_tables = raw_rs.get("exclude_tables")
        rs_exclude_tables_list = None
        if raw_rs_exclude_tables:
            if isinstance(raw_rs_exclude_tables, list):
                rs_exclude_tables_list = [t.strip() for t in raw_rs_exclude_tables if t.strip()]
            elif isinstance(raw_rs_exclude_tables, str):
                rs_exclude_tables_list = [t.strip() for t in raw_rs_exclude_tables.split('\n') if t.strip()]
            if not rs_exclude_tables_list:
                rs_exclude_tables_list = None

        # Parse restore jobs
        raw_rs_jobs = raw_rs.get("jobs")
        rs_jobs_val = None
        if raw_rs_jobs is not None:
            try:
                rs_jobs_val = int(raw_rs_jobs)
                if rs_jobs_val < 1:
                    rs_jobs_val = None
            except (ValueError, TypeError):
                rs_jobs_val = None

        restore_options = br.RestoreOptions(
            clean=raw_rs.get("clean", True),
            no_owner=raw_rs.get("no_owner", True),
            no_privileges=raw_rs.get("no_privileges", True),
            role=None,  # dest_role is set by run_transfer itself
            exclude_schema=rs_exclude_schema_list,
            schemas=schemas if schemas else None,
            data_only=rs_data_only,
            schema_only=rs_schema_only,
            no_comments=raw_rs.get("no_comments", False),
            no_tablespaces=raw_rs.get("no_tablespaces", False),
            no_publications=raw_rs.get("no_publications", False),
            no_subscriptions=raw_rs.get("no_subscriptions", False),
            jobs=rs_jobs_val,
            exit_on_error=raw_rs.get("exit_on_error", False),
            exclude_tables=rs_exclude_tables_list,
            timescaledb=raw_rs.get("timescaledb", False),
        )

        # Create operation log
        operation_logger = op_logger.get_logger()
        metadata = {
            "source_endpoint": source_endpoint_name,
            "source_database": source_database,
            "dest_endpoint": dest_endpoint_name,
            "dest_database": dest_database,
            "source_use_ssm": source_endpoint.use_ssm,
            "dest_use_ssm": dest_endpoint.use_ssm,
        }
        if dest_role:
            metadata["dest_role"] = dest_role
        if schemas:
            metadata["schemas"] = schemas
        if backup_options.exclude_table:
            metadata["backup_exclude_table"] = backup_options.exclude_table
        if backup_options.exclude_table_data:
            metadata["backup_exclude_table_data"] = backup_options.exclude_table_data
        if backup_options.data_only:
            metadata["backup_data_only"] = True
        if backup_options.schema_only:
            metadata["backup_schema_only"] = True
        if restore_options.data_only:
            metadata["restore_data_only"] = True
        if restore_options.schema_only:
            metadata["restore_schema_only"] = True
        if restore_options.jobs:
            metadata["restore_jobs"] = restore_options.jobs
        if restore_options.exit_on_error:
            metadata["restore_exit_on_error"] = True
        if rs_exclude_schema_list:
            metadata["restore_exclude_schemas"] = rs_exclude_schema_list
        if rs_exclude_tables_list:
            metadata["restore_exclude_tables"] = rs_exclude_tables_list
        if restore_options.timescaledb:
            metadata["restore_timescaledb"] = True

        operation_id = operation_logger.start_operation(
            operation_type="transfer",
            endpoint=f"{source_endpoint_name} -> {dest_endpoint_name}",
            database=f"{source_database} -> {dest_database}",
            metadata=metadata
        )

        # SSM tunnel info messages
        ssm_msgs = []
        if source_endpoint.use_ssm:
            ssm_msgs.append({
                "type": "progress",
                "message": f"Source SSM tunnel active via {source_endpoint.jumphost_alias} -> localhost:{source_port}"
            })
        if dest_endpoint.use_ssm:
            ssm_msgs.append({
                "type": "progress",
                "message": f"Destination SSM tunnel active via {dest_endpoint.jumphost_alias} -> localhost:{dest_port}"
            })

        # Launch operation as background task (survives WS disconnect)
        cancel_event = asyncio.Event()
        _running_operations[operation_id] = cancel_event

        async def _run():
            try:
                for msg in ssm_msgs:
                    broadcaster.broadcast(operation_id, msg)
                async for progress in br.run_transfer(
                    source_database=source_database,
                    source_host=source_host,
                    source_port=source_port,
                    source_username=source_endpoint.username,
                    source_password=source_endpoint.password,
                    dest_database=dest_database,
                    dest_host=dest_host,
                    dest_port=dest_port,
                    dest_username=dest_endpoint.username,
                    dest_password=dest_endpoint.password,
                    dest_role=dest_role,
                    backup_options=backup_options,
                    restore_options=restore_options,
                    operation_id=operation_id,
                    cancel_event=cancel_event,
                ):
                    broadcaster.broadcast(operation_id, progress)
            except Exception as exc:
                logger.exception(f"Background transfer failed: {exc}")
                broadcaster.broadcast(operation_id, {
                    "type": "complete", "success": False, "message": str(exc)
                })
                op_logger.get_logger().complete_operation(
                    operation_id, status="failed", error=str(exc)
                )
            finally:
                _running_operations.pop(operation_id, None)
                broadcaster.end_operation(operation_id)

        broadcaster.start_operation(operation_id)
        asyncio.create_task(_run())

        # Subscribe to the broadcaster and stream to this client
        await _stream_to_websocket(websocket, operation_id)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass
    finally:
        try:
            await websocket.close()
        except:
            pass


# =============================================================================
# WebSocket: Follow Operation
# =============================================================================

@app.websocket("/ws/operation/{operation_id}/follow")
async def websocket_follow_operation(websocket: WebSocket, operation_id: str):
    """WebSocket endpoint to follow a running or view a completed operation."""
    await websocket.accept()

    user = await check_websocket_auth(websocket)
    if not user:
        await websocket.send_json({"type": "error", "message": "Authentication required"})
        await websocket.close()
        return

    try:
        operation_logger = op_logger.get_logger()
        op = operation_logger.get_operation(operation_id)

        if not op:
            await websocket.send_json({"type": "error", "message": "Operation not found"})
            return

        if broadcaster.is_active(operation_id):
            # Operation still running — stream live via broadcaster
            await _stream_to_websocket(websocket, operation_id)
        else:
            # Operation already finished — send static log
            log_path = operation_logger.get_log_file_path(operation_id)
            if log_path and log_path.exists():
                for line in log_path.read_text().splitlines():
                    await websocket.send_json({"type": "output", "message": line})

            await websocket.send_json({
                "type": "complete",
                "success": op.get("status") == "completed",
                "message": f"Operation {op.get('status', 'unknown')}"
            })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass
    finally:
        try:
            await websocket.close()
        except:
            pass


# =============================================================================
# Shutdown
# =============================================================================

@app.on_event("startup")
def startup_event():
    """Cleanup stale 'running' operations left over from a previous server session."""
    try:
        operation_logger = op_logger.get_logger()
        history = operation_logger._load_history()
        changed = False
        for op in history:
            if op.get("status") == "running":
                op["status"] = "failed"
                op["error"] = "Server restarted while operation was in progress"
                changed = True
        if changed:
            operation_logger._save_history(history)
            logger.info("Marked stale running operations as failed after server restart")
    except Exception as e:
        logger.warning(f"Could not clean up stale operations: {e}")

    # Start the backup scheduler. init_scheduler always runs (so run-now works);
    # the ticking loop is skipped when MAGIKUP_DISABLE_SCHEDULER is set (tests),
    # to avoid a background tick firing real backups during the suite.
    try:
        _reconcile_schedule_state()
        sched_engine.init_scheduler(run_one=_execute_schedule)
        if not os.environ.get("MAGIKUP_DISABLE_SCHEDULER"):
            sched_engine.get_scheduler().start()
    except Exception as e:
        logger.error(f"Failed to start backup scheduler: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    tunnel_manager.stop_all_tunnels()
    try:
        await sched_engine.get_scheduler().stop()
    except Exception as e:
        logger.warning(f"Error stopping backup scheduler: {e}")
