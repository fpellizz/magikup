"""
Authentication module for PostgreSQL Backup/Restore Application.

Multi-user authentication with roles (admin/operator/viewer),
rate limiting, account lockout, password policy, and audit logging.
"""

import json
import logging
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Tuple

import bcrypt
from fastapi import Request, HTTPException, status
from itsdangerous import URLSafeTimedSerializer

from . import config

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

CONFIG_DIR = Path(__file__).parent.parent / "config"
USERS_FILE = CONFIG_DIR / "users.json"
AUDIT_LOG_FILE = CONFIG_DIR / "audit.log"

RATE_LIMIT_MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW_SECONDS = 300  # 5 minutes
ACCOUNT_LOCKOUT_THRESHOLD = 10

VALID_ROLES = ("admin", "operator", "viewer")

# =============================================================================
# Session setup (unchanged)
# =============================================================================


def _get_secret_key() -> str:
    """Get or generate a persistent secret key."""
    env_key = os.environ.get('SESSION_SECRET_KEY')
    if env_key:
        return env_key

    key_file = CONFIG_DIR / ".session_key"
    if key_file.exists():
        return key_file.read_text().strip()

    new_key = secrets.token_urlsafe(32)
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text(new_key)
    try:
        os.chmod(key_file, 0o600)
    except Exception:
        pass
    return new_key


SECRET_KEY = _get_secret_key()
session_serializer = URLSafeTimedSerializer(SECRET_KEY)

# =============================================================================
# Data models
# =============================================================================


@dataclass
class User:
    username: str
    password_hash: str
    role: str  # "admin", "operator", "viewer"
    enabled: bool = True
    locked: bool = False
    failed_attempts: int = 0
    created_at: str = ""
    last_login: Optional[str] = None
    created_by: str = "system"
    # Endpoint allowlist for non-admin users. ["*"] = all endpoints (default,
    # backward compatible). Admins always have access to all endpoints.
    endpoints: list = field(default_factory=lambda: ["*"])


@dataclass
class _RateLimitRecord:
    count: int = 0
    first_attempt: float = 0.0
    blocked_until: float = 0.0


# =============================================================================
# Module-level state
# =============================================================================

# Reentrant so a read-modify-write op can hold the lock across _load_users()
# and _save_users() (which also acquires it) without deadlocking.
_users_lock = threading.RLock()
_rate_limit_store: Dict[str, _RateLimitRecord] = {}

# =============================================================================
# Password hashing (unchanged)
# =============================================================================


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception:
        return False


# =============================================================================
# Password policy
# =============================================================================


def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validate password meets policy requirements.

    Returns (is_valid, error_message).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    return True, ""


# =============================================================================
# User store (config/users.json)
# =============================================================================


def _load_users() -> dict:
    """Load users from users.json. Auto-creates from config.ini if needed."""
    _ensure_users_file()
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"version": 1, "users": {}}


def _save_users(data: dict) -> None:
    """Write users dict to users.json."""
    with _users_lock:
        USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


def _ensure_users_file() -> None:
    """Migrate from config.ini [auth] if users.json doesn't exist."""
    if USERS_FILE.exists():
        return

    cfg = config.read_config()
    username = cfg.get('auth', 'username', fallback='admin')
    password_hash = cfg.get('auth', 'password_hash', fallback=None)

    if not password_hash:
        initial_password = secrets.token_urlsafe(16)
        password_hash = hash_password(initial_password)
        logger.warning("=" * 60)
        logger.warning("INITIAL ADMIN PASSWORD: %s", initial_password)
        logger.warning("Change this password immediately via the admin panel!")
        logger.warning("=" * 60)

    now = datetime.now().isoformat()
    data = {
        "version": 1,
        "users": {
            username: {
                "username": username,
                "password_hash": password_hash,
                "role": "admin",
                "enabled": True,
                "locked": False,
                "failed_attempts": 0,
                "created_at": now,
                "last_login": None,
                "created_by": "migrated_from_config"
            }
        }
    }

    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    audit_log("user_migrated", username, "localhost",
              "Migrated from config.ini [auth]")


def get_user(username: str) -> Optional[User]:
    """Get a single user by username."""
    data = _load_users()
    user_data = data.get("users", {}).get(username)
    if not user_data:
        return None
    return User(
        username=user_data.get("username", username),
        password_hash=user_data.get("password_hash", ""),
        role=user_data.get("role", "viewer"),
        enabled=user_data.get("enabled", True),
        locked=user_data.get("locked", False),
        failed_attempts=user_data.get("failed_attempts", 0),
        created_at=user_data.get("created_at", ""),
        last_login=user_data.get("last_login"),
        created_by=user_data.get("created_by", "system"),
        endpoints=user_data.get("endpoints", ["*"]),
    )


def get_all_users() -> Dict[str, User]:
    """Get all users as a dict keyed by username."""
    data = _load_users()
    result = {}
    for uname, udata in data.get("users", {}).items():
        result[uname] = User(
            username=udata.get("username", uname),
            password_hash=udata.get("password_hash", ""),
            role=udata.get("role", "viewer"),
            enabled=udata.get("enabled", True),
            locked=udata.get("locked", False),
            failed_attempts=udata.get("failed_attempts", 0),
            created_at=udata.get("created_at", ""),
            last_login=udata.get("last_login"),
            created_by=udata.get("created_by", "system"),
            endpoints=udata.get("endpoints", ["*"]),
        )
    return result


def _normalize_endpoints(endpoints: Optional[list]) -> list:
    """Normalize an endpoint allowlist. None/empty -> ['*'] (all). '*' anywhere -> ['*']."""
    if not endpoints:
        return ["*"]
    cleaned = [str(e).strip() for e in endpoints if str(e).strip()]
    if not cleaned or "*" in cleaned:
        return ["*"]
    return cleaned


def create_user(username: str, password: str, role: str, created_by: str,
                endpoints: Optional[list] = None) -> dict:
    """Create a new user. Returns {"success": True} or {"success": False, "error": "..."}."""
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return {"success": False, "error": "Username must be alphanumeric (hyphens/underscores allowed)"}
    if len(username) < 2 or len(username) > 50:
        return {"success": False, "error": "Username must be 2-50 characters"}
    if role not in VALID_ROLES:
        return {"success": False, "error": f"Invalid role. Must be one of: {', '.join(VALID_ROLES)}"}

    valid, policy_error = validate_password(password)
    if not valid:
        return {"success": False, "error": policy_error}

    with _users_lock:
        data = _load_users()
        if username in data.get("users", {}):
            return {"success": False, "error": "Username already exists"}

        data["users"][username] = {
            "username": username,
            "password_hash": hash_password(password),
            "role": role,
            "enabled": True,
            "locked": False,
            "failed_attempts": 0,
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "created_by": created_by,
            "endpoints": _normalize_endpoints(endpoints),
        }
        _save_users(data)
        return {"success": True}


def update_user(username: str, role: Optional[str] = None,
                enabled: Optional[bool] = None, locked: Optional[bool] = None,
                endpoints: Optional[list] = None) -> dict:
    """Update user attributes. Returns {"success": True} or {"success": False, "error": "..."}."""
    with _users_lock:
        data = _load_users()
        if username not in data.get("users", {}):
            return {"success": False, "error": "User not found"}

        user_entry = data["users"][username]

        # Prevent removing the last admin
        if role is not None and role != "admin" and user_entry.get("role") == "admin":
            admin_count = sum(1 for u in data["users"].values() if u.get("role") == "admin")
            if admin_count <= 1:
                return {"success": False, "error": "Cannot change role of the last admin user"}

        if enabled is not None and not enabled and user_entry.get("role") == "admin":
            admin_count = sum(1 for u in data["users"].values()
                             if u.get("role") == "admin" and u.get("enabled", True))
            if admin_count <= 1:
                return {"success": False, "error": "Cannot disable the last admin user"}

        if role is not None:
            if role not in VALID_ROLES:
                return {"success": False, "error": f"Invalid role. Must be one of: {', '.join(VALID_ROLES)}"}
            user_entry["role"] = role
        if enabled is not None:
            user_entry["enabled"] = enabled
        if locked is not None:
            user_entry["locked"] = locked
            if not locked:
                user_entry["failed_attempts"] = 0
        if endpoints is not None:
            user_entry["endpoints"] = _normalize_endpoints(endpoints)

        _save_users(data)
        return {"success": True}


def delete_user(username: str) -> dict:
    """Delete a user. Returns {"success": True} or {"success": False, "error": "..."}."""
    with _users_lock:
        data = _load_users()
        if username not in data.get("users", {}):
            return {"success": False, "error": "User not found"}

        user_entry = data["users"][username]
        if user_entry.get("role") == "admin":
            admin_count = sum(1 for u in data["users"].values() if u.get("role") == "admin")
            if admin_count <= 1:
                return {"success": False, "error": "Cannot delete the last admin user"}

        del data["users"][username]
        _save_users(data)
        return {"success": True}


def reset_user_password(username: str, new_password: str) -> dict:
    """Admin-initiated password reset. Returns {"success": True} or {"success": False, "error": "..."}."""
    valid, policy_error = validate_password(new_password)
    if not valid:
        return {"success": False, "error": policy_error}

    with _users_lock:
        data = _load_users()
        if username not in data.get("users", {}):
            return {"success": False, "error": "User not found"}

        data["users"][username]["password_hash"] = hash_password(new_password)
        _save_users(data)
        return {"success": True}


def _update_last_login(username: str) -> None:
    """Update the last_login timestamp for a user."""
    with _users_lock:
        data = _load_users()
        if username in data.get("users", {}):
            data["users"][username]["last_login"] = datetime.now().isoformat()
            _save_users(data)


# =============================================================================
# Rate limiting (in-memory, per IP)
# =============================================================================


def _check_rate_limit(ip: str) -> Tuple[bool, int]:
    """Check if IP is rate-limited. Returns (is_blocked, seconds_remaining)."""
    now = time.time()

    # Cleanup expired entries
    expired = [k for k, v in _rate_limit_store.items()
               if now > v.blocked_until and now - v.first_attempt > RATE_LIMIT_WINDOW_SECONDS]
    for k in expired:
        del _rate_limit_store[k]

    record = _rate_limit_store.get(ip)
    if not record:
        return False, 0

    if now < record.blocked_until:
        return True, int(record.blocked_until - now)

    if now - record.first_attempt > RATE_LIMIT_WINDOW_SECONDS:
        del _rate_limit_store[ip]
        return False, 0

    return False, 0


def _record_failed_attempt(ip: str) -> None:
    """Record a failed login attempt from an IP."""
    now = time.time()
    record = _rate_limit_store.get(ip)

    if not record or (now - record.first_attempt > RATE_LIMIT_WINDOW_SECONDS):
        _rate_limit_store[ip] = _RateLimitRecord(count=1, first_attempt=now)
        return

    record.count += 1
    if record.count >= RATE_LIMIT_MAX_ATTEMPTS:
        record.blocked_until = now + RATE_LIMIT_WINDOW_SECONDS


def _clear_rate_limit(ip: str) -> None:
    """Clear rate limit for an IP after successful login."""
    _rate_limit_store.pop(ip, None)


# =============================================================================
# Account lockout (persisted in users.json)
# =============================================================================


def _record_failed_login(username: str) -> None:
    """Increment failed_attempts. Lock account if >= threshold."""
    with _users_lock:
        data = _load_users()
        if username not in data.get("users", {}):
            return

        user_entry = data["users"][username]
        user_entry["failed_attempts"] = user_entry.get("failed_attempts", 0) + 1

        if user_entry["failed_attempts"] >= ACCOUNT_LOCKOUT_THRESHOLD:
            user_entry["locked"] = True
            audit_log("account_locked", username, "",
                      f"{user_entry['failed_attempts']} failed attempts")

        _save_users(data)


def _clear_failed_attempts(username: str) -> None:
    """Reset failed_attempts to 0 after successful login."""
    with _users_lock:
        data = _load_users()
        if username in data.get("users", {}):
            data["users"][username]["failed_attempts"] = 0
            _save_users(data)


# =============================================================================
# Audit logging
# =============================================================================


def audit_log(event: str, username: str, ip: str, details: str = "") -> None:
    """Append an audit event to config/audit.log (newline-delimited JSON)."""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "username": username,
        "ip": ip,
        "details": details,
    }
    try:
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        # Don't let audit failures break the app, but don't lose them silently.
        logger.warning("Failed to write audit event %r for %r: %s", event, username, e)


def get_audit_log(limit: int = 100) -> list:
    """Read recent audit log entries."""
    if not AUDIT_LOG_FILE.exists():
        return []
    try:
        with open(AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        entries = []
        for line in reversed(lines):
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            if len(entries) >= limit:
                break
        return entries
    except Exception:
        return []


# =============================================================================
# Session tokens
# =============================================================================


def get_session_timeout() -> int:
    """Get session timeout in minutes from config.ini [auth]."""
    cfg = config.read_config()
    return cfg.getint('auth', 'session_timeout_minutes', fallback=480)


def create_session_token(username: str, role: str) -> str:
    """Create a signed session token containing username and role."""
    return session_serializer.dumps({'username': username, 'role': role})


def verify_session_token(token: str, max_age: int = 28800) -> Optional[dict]:
    """
    Verify a session token.

    Returns {"username": str, "role": str} or None.
    """
    try:
        data = session_serializer.loads(token, max_age=max_age)
        username = data.get('username')
        if not username:
            return None
        role = data.get('role')
        if not role:
            # Legacy token without role — look up from users.json
            user = get_user(username)
            if user:
                role = user.role
            else:
                return None
        return {"username": username, "role": role}
    except Exception:
        return None


# =============================================================================
# Current user & authentication
# =============================================================================


def get_current_user(request: Request) -> Optional[dict]:
    """
    Get current user from session cookie.

    Returns {"username": str, "role": str} or None.
    Also validates that the user still exists and is enabled.
    """
    session_token = request.cookies.get('session_token')
    if not session_token:
        return None

    max_age = get_session_timeout() * 60
    token_data = verify_session_token(session_token, max_age=max_age)
    if not token_data:
        return None

    # Validate user still exists and is active
    user = get_user(token_data["username"])
    if not user or not user.enabled or user.locked:
        return None

    # Use the live role/endpoints from users.json (in case they were changed)
    return {"username": user.username, "role": user.role, "endpoints": user.endpoints}


def authenticate_user(username: str, password: str) -> Optional[User]:
    """
    Authenticate a user with username and password.

    Returns User object if valid, None otherwise.
    Does NOT check locked/enabled — caller must do that.
    """
    user = get_user(username)
    if not user:
        return None
    if verify_password(password, user.password_hash):
        return user
    return None


def handle_login(username: str, password: str, ip: str) -> Optional[str]:
    """
    Handle login attempt with rate limiting, lockout, and audit.

    Returns session token if successful, None otherwise.
    """
    # Check rate limit
    is_blocked, _ = _check_rate_limit(ip)
    if is_blocked:
        audit_log("login_failed", username, ip, "rate limited")
        return None

    # Check if user exists
    user = get_user(username)

    if user:
        # Check locked/enabled
        if user.locked:
            audit_log("login_failed", username, ip, "account locked")
            _record_failed_attempt(ip)
            return None
        if not user.enabled:
            audit_log("login_failed", username, ip, "account disabled")
            _record_failed_attempt(ip)
            return None

    # Authenticate
    authenticated_user = authenticate_user(username, password)
    if not authenticated_user:
        _record_failed_attempt(ip)
        if user:
            _record_failed_login(username)
        audit_log("login_failed", username, ip, "invalid credentials")
        return None

    # Success
    _clear_rate_limit(ip)
    _clear_failed_attempts(username)
    _update_last_login(username)
    audit_log("login_success", username, ip)
    return create_session_token(username, authenticated_user.role)


def change_password(username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
    """
    Change user password.

    Returns (success, error_message).
    """
    user = authenticate_user(username, old_password)
    if not user:
        return False, "Current password is incorrect"

    valid, policy_error = validate_password(new_password)
    if not valid:
        return False, policy_error

    with _users_lock:
        data = _load_users()
        if username in data.get("users", {}):
            data["users"][username]["password_hash"] = hash_password(new_password)
            _save_users(data)
            return True, ""

    return False, "User not found"


# =============================================================================
# FastAPI dependencies
# =============================================================================


def require_auth(request: Request) -> dict:
    """
    Dependency: requires authentication.

    Returns {"username": str, "role": str}.
    Raises HTTPException 303 redirect to /login if not authenticated.
    """
    user = get_current_user(request)
    if not user:
        base_path = request.scope.get('root_path', '')
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": f"{base_path}/login"}
        )
    return user


def require_admin(request: Request) -> dict:
    """
    Dependency: requires admin role.

    Raises 303 redirect if not authenticated, 403 if not admin.
    """
    user = require_auth(request)
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return user


def require_operator(request: Request) -> dict:
    """
    Dependency: requires operator or admin role.

    Raises 303 redirect if not authenticated, 403 if viewer.
    """
    user = require_auth(request)
    if user["role"] not in ("admin", "operator"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator access required"
        )
    return user
