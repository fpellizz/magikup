"""
FastAPI application for PostgreSQL Backup/Restore (Full).
Unified application supporting both direct and SSM tunnel connections.
"""

import os
import re
import json
import asyncio
import logging
from pathlib import Path
from typing import Optional, List, Tuple
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, File, UploadFile, Depends, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel

from . import config as cfg
from . import db_service as db
from . import backup_restore as br
from . import auth
from . import operation_logger as op_logger
from . import aws_service as aws
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
    version="3.3.0",
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


class SettingsModel(BaseModel):
    backup_dir: str = "/backups"
    pg_dump_path: str = "/usr/bin/pg_dump"
    pg_restore_path: str = "/usr/bin/pg_restore"
    max_upload_size_gb: int = 5
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

    return templates.TemplateResponse("files.html", {
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
    all_users = auth.get_all_users()

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "endpoints": endpoints,
        "jumphosts": jumphosts,
        "settings": settings,
        "query_settings": query_settings,
        "aws_accounts": aws_accounts,
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
        }
        for name, endpoint in endpoints.items()
        if user_can_access_endpoint(user, name)
    ]


@app.post("/api/endpoints")
async def api_save_endpoint(endpoint: DatabaseEndpointModel, user: dict = Depends(auth.require_admin)):
    """Save a database endpoint."""
    cfg.save_database_config(cfg.DatabaseConfig(
        name=endpoint.name,
        host=endpoint.host,
        port=endpoint.port,
        username=endpoint.username,
        password=endpoint.password,
        use_ssm=endpoint.use_ssm,
        jumphost_alias=endpoint.jumphost_alias or "",
        read_only=endpoint.read_only,
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
        )
    )

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
                            username=endpoint.username, password=endpoint.password, schema=schema)
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
                                    schema=schema, table=table)
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
                          username=endpoint.username, password=endpoint.password, schema=schema)
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
                                 username=endpoint.username, password=endpoint.password, schema=schema)
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
                              schema=schema, table=table)
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


@app.get("/api/config/settings")
async def api_get_settings(user: dict = Depends(auth.require_auth)):
    """Get application settings."""
    settings = cfg.get_settings()
    return {
        "backup_dir": settings.backup_dir,
        "pg_dump_path": settings.pg_dump_path,
        "pg_restore_path": settings.pg_restore_path,
        "max_upload_size_gb": settings.max_upload_size_gb,
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

        # Resolve connection (auto-start SSM tunnel if needed)
        try:
            host, port = get_endpoint_host_port(endpoint)
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

        # Launch operation as background task (survives WS disconnect)
        cancel_event = asyncio.Event()
        _running_operations[operation_id] = cancel_event

        async def _run():
            try:
                if ssm_msg:
                    broadcaster.broadcast(operation_id, ssm_msg)
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


@app.on_event("shutdown")
def shutdown_event():
    """Cleanup on shutdown."""
    tunnel_manager.stop_all_tunnels()
