"""
Configuration management for PostgreSQL Backup/Restore Application (Full).
Unified single-file configuration with support for direct and SSM tunnel connections.
Includes password encryption for secure storage.
"""

import os
import re
import glob
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Optional
import configparser

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

# Configuration file paths
CONFIG_FILE = Path(__file__).parent.parent / 'config' / 'config.ini'
ENCRYPTION_KEY_FILE = Path(__file__).parent.parent / 'config' / '.encryption_key'

# Encryption prefix to identify encrypted passwords
ENCRYPTED_PREFIX = "ENC:"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class DatabaseConfig:
    """Database connection configuration."""
    name: str
    host: str
    port: int
    username: str
    password: str
    use_ssm: bool = False
    jumphost_alias: str = ""
    read_only: bool = False  # If True: query editor runs read-only; restore/transfer to it is refused
    backup_use_replica: bool = False  # If True: back up from replica_host instead of host
    replica_host: str = ""  # Read replica/reader host used for backups when backup_use_replica is True


@dataclass
class AWSConfig:
    """AWS configuration for SSM tunneling."""
    alias: str = ""
    access_key_id: str = ""
    secret_access_key: str = ""
    region: str = "us-east-1"


@dataclass
class JumphostConfig:
    """Jump host server configuration."""
    alias: str
    instance_id: str
    aws_account_alias: str = ""


@dataclass
class S3StorageConfig:
    """S3 (or S3-compatible) bucket used to archive/retrieve backup files."""
    name: str
    bucket: str
    region: str = "us-east-1"
    endpoint_url: str = ""          # S3-compatible endpoint (MinIO, Ceph, Wasabi...); empty = AWS S3
    prefix: str = ""                # optional key prefix/folder within the bucket
    path_style: bool = False        # path-style addressing (required by many S3-compatible servers)
    cred_mode: str = "dedicated"    # "dedicated" (keys below) | "aws_account" (reuse an [aws:*] account)
    aws_account_alias: str = ""     # used when cred_mode == "aws_account"
    access_key_id: str = ""         # used when cred_mode == "dedicated"
    secret_access_key: str = ""     # used when cred_mode == "dedicated" (encrypted at rest)


@dataclass
class ScheduleConfig:
    """A scheduled (unattended) backup definition. Stored under
    [schedule:<name>]; references an endpoint and an optional remote target by
    name only — no secrets are ever copied in."""
    name: str
    cron: str
    endpoint: str
    database: str
    enabled: bool = True
    # --- backup options (subset of BackupOptions) ---
    large_objects: bool = True
    no_owner: bool = True
    no_privileges: bool = True
    no_tablespaces: bool = True
    no_comments: bool = True
    data_only: bool = False
    schema_only: bool = False
    clean: bool = False
    create: bool = False
    schemas: str = ""               # CSV; "" = all
    exclude_table: str = ""
    exclude_table_data: str = ""
    exclude_schema: str = ""
    # --- destination ---
    dest_kind: str = "none"         # none|s3|fileshare|filebrowser
    dest_target: str = ""           # referenced storage-config name; empty when dest_kind=none
    delete_local_after_copy: bool = False
    keep_last_n: int = 0            # local retention for this DB; 0 = unlimited


@dataclass
class FileShareConfig:
    """WebDAV/HTTP(S) file share used to archive/retrieve backup files."""
    name: str
    base_url: str = ""              # e.g. https://host/remote.php/dav/files/user/backups
    username: str = ""
    password: str = ""              # encrypted at rest
    verify_ssl: bool = True


@dataclass
class FileBrowserConfig:
    """filebrowser (github.com/filebrowser/filebrowser) instance used to
    archive/retrieve backup files through its HTTP + JWT API."""
    name: str
    base_url: str = ""              # filebrowser root, e.g. https://files.example.com
    root_path: str = ""             # subdirectory within filebrowser for backups (optional)
    username: str = ""              # empty => no-auth instance
    password: str = ""              # encrypted at rest (JWT login password)
    verify_ssl: bool = True


APP_ROOT = Path(__file__).parent.parent

@dataclass
class Settings:
    """Application settings."""
    backup_dir: str = str(APP_ROOT / "backups")
    pg_dump_path: str = "/usr/bin/pg_dump"
    pg_restore_path: str = "/usr/bin/pg_restore"
    max_upload_size_gb: int = 5
    lock_wait_timeout_seconds: int = 60  # pg_dump --lock-wait-timeout (0 = wait forever)
    log_level: str = "INFO"
    context_path: str = ""


@dataclass
class QuerySettings:
    """Query Editor settings."""
    autocommit: bool = False


# =============================================================================
# Encryption Functions
# =============================================================================

def _get_or_create_encryption_key() -> bytes:
    """
    Get or create the Fernet encryption key.

    Priority:
    1. ENCRYPTION_KEY environment variable (Fernet key format)
    2. .encryption_key file in config directory
    3. Generate new key and save to file
    """
    # Check environment variable first
    env_key = os.environ.get('ENCRYPTION_KEY')
    if env_key:
        try:
            Fernet(env_key.encode() if isinstance(env_key, str) else env_key)
            return env_key.encode() if isinstance(env_key, str) else env_key
        except Exception:
            logger.warning("Invalid ENCRYPTION_KEY in environment, using file-based key")

    # Check for existing key file
    if ENCRYPTION_KEY_FILE.exists():
        try:
            key_data = ENCRYPTION_KEY_FILE.read_text().strip()
            Fernet(key_data.encode())
            return key_data.encode()
        except Exception as e:
            logger.warning(f"Invalid encryption key in file, regenerating: {e}")

    # Generate new key
    key = Fernet.generate_key()

    ENCRYPTION_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    ENCRYPTION_KEY_FILE.write_text(key.decode())

    try:
        ENCRYPTION_KEY_FILE.chmod(0o600)
    except Exception:
        pass

    logger.info("Generated new encryption key")
    return key


def _get_fernet() -> Fernet:
    """Get Fernet instance for encryption/decryption."""
    key = _get_or_create_encryption_key()
    return Fernet(key)


def encrypt_password(password: str) -> str:
    """Encrypt a password for secure storage. Returns 'ENC:<token>'."""
    if not password:
        return password
    if password.startswith(ENCRYPTED_PREFIX):
        return password

    try:
        fernet = _get_fernet()
        encrypted = fernet.encrypt(password.encode())
        return f"{ENCRYPTED_PREFIX}{encrypted.decode()}"
    except Exception as e:
        logger.error(f"Error encrypting password: {e}")
        return password


def decrypt_password(encrypted_password: str) -> str:
    """Decrypt a password. Handles both ENC: and plain text."""
    if not encrypted_password:
        return encrypted_password
    if not encrypted_password.startswith(ENCRYPTED_PREFIX):
        return encrypted_password

    try:
        encrypted_data = encrypted_password[len(ENCRYPTED_PREFIX):]
        fernet = _get_fernet()
        decrypted = fernet.decrypt(encrypted_data.encode())
        return decrypted.decode()
    except InvalidToken:
        logger.error("Invalid encryption token - key may have changed")
        return ""
    except Exception as e:
        logger.error(f"Error decrypting password: {e}")
        return ""


def is_password_encrypted(password: str) -> bool:
    """Check if a password is encrypted."""
    return password.startswith(ENCRYPTED_PREFIX) if password else False


# =============================================================================
# Configuration File Management
# =============================================================================

def get_default_config() -> str:
    """Return default configuration template."""
    return f"""[settings]
# Application settings
backup_dir = {APP_ROOT / 'backups'}
pg_dump_path = /usr/bin/pg_dump
pg_restore_path = /usr/bin/pg_restore
max_upload_size_gb = 5
# pg_dump --lock-wait-timeout (seconds): fail fast if shared table locks can't be
# acquired at the start of a backup, instead of blocking forever. 0 = wait forever.
lock_wait_timeout_seconds = 60
log_level = INFO
context_path =

[auth]
# Authentication settings
# Default password: admin123 (CHANGE THIS IMMEDIATELY!)
username = admin
session_timeout_minutes = 480

[query]
# Query Editor defaults
autocommit = false

[aws:default]
# AWS credentials for SSM tunneling
# Create multiple accounts with [aws:alias] sections
access_key_id =
secret_access_key =
region = us-east-1

[jumphosts]
# Jump host servers for SSM port forwarding
# Format: alias = instance_id|aws_account_alias
# Example: production-jh = i-0123456789abcdef0|default

[endpoints]
# Database endpoints
# Format: name = host|port|username|password|use_ssm|jumphost_alias|read_only|backup_use_replica|replica_host
# use_ssm: true or false
# jumphost_alias: references a key in [jumphosts] (leave empty if use_ssm=false)
# read_only: true or false (optional, default false). When true the query editor
#            runs read-only and restore/transfer to this endpoint are refused.
# backup_use_replica: true or false (optional). When true, backups connect to
#            replica_host instead of host (e.g. an Aurora reader endpoint).
# replica_host: read replica/reader host used for backups (optional).
# Example (direct):     local-db = 10.0.1.100|5432|postgres|mypassword|false||false
# Example (SSM):        prod-aurora = aurora-cluster.rds.amazonaws.com|5432|admin|ENC:...|true|production-jh|false
# Example (read-only):  prod-ro = reporting.rds.amazonaws.com|5432|readonly|ENC:...|false||true

# Remote storage for backup files (optional). Add one section per target.
#
# S3 or S3-compatible (MinIO, Ceph, Wasabi...). One [s3:<name>] per bucket:
#   [s3:my-bucket]
#   bucket = my-backups
#   region = us-east-1
#   endpoint_url =            ; empty for AWS S3; set a URL for S3-compatible servers
#   prefix = magikup/         ; optional key prefix/folder within the bucket
#   path_style = false        ; set true for most S3-compatible servers
#   cred_mode = dedicated     ; "dedicated" (keys below) or "aws_account" (reuse an [aws:*] account)
#   aws_account_alias =       ; used when cred_mode = aws_account
#   access_key_id =           ; used when cred_mode = dedicated
#   secret_access_key =       ; used when cred_mode = dedicated (stored encrypted as ENC:...)
#
# WebDAV/HTTP(S) file share. One [fileshare:<name>] per instance:
#   [fileshare:my-share]
#   base_url = https://host/remote.php/dav/files/user/backups
#   username =
#   password =                ; stored encrypted as ENC:...
#   verify_ssl = true
#
# filebrowser (github.com/filebrowser/filebrowser). One [filebrowser:<name>] per instance:
#   [filebrowser:my-fb]
#   base_url = https://files.example.com   ; filebrowser root
#   root_path = backups                    ; subdirectory for backups (optional)
#   username =                             ; empty for a no-auth instance
#   password =                ; stored encrypted as ENC:...
#   verify_ssl = true
#
# Scheduled (unattended) backups. One [schedule:<name>] per job. The name must
# be 2-50 chars of [a-zA-Z0-9_-] and references an endpoint + optional remote
# target by name only (no secrets stored here):
#   [schedule:nightly-prod]
#   cron = 30 2 * * *         ; standard 5-field cron, evaluated in UTC
#   endpoint = prod-aurora    ; must reference an [endpoints] entry
#   database = appdb
#   enabled = true
#   large_objects = true      ; --- backup options (subset of BackupOptions) ---
#   no_owner = true
#   no_privileges = true
#   no_tablespaces = true
#   no_comments = true
#   data_only = false
#   schema_only = false
#   clean = false
#   create = false
#   schemas =                 ; CSV; empty = all schemas
#   exclude_table =
#   exclude_table_data =
#   exclude_schema =
#   dest_kind = none          ; none|s3|fileshare|filebrowser (none = local-only)
#   dest_target =             ; referenced storage-config name; empty when dest_kind=none
#   delete_local_after_copy = false  ; honored only when dest_kind != none
#   keep_last_n = 0           ; local retention for this DB; 0 = unlimited
"""


_migration_done = False

def ensure_config_exists() -> None:
    """Create config file with defaults if it doesn't exist. Migrates legacy format."""
    global _migration_done
    if not CONFIG_FILE.exists():
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(get_default_config())
    elif not _migration_done:
        _migration_done = True
        migrate_legacy_aws_config()


def read_config() -> configparser.ConfigParser:
    """Read configuration file.

    interpolation=None: values are stored verbatim. Without it, a literal '%'
    in a value (e.g. a percent-encoded WebDAV URL, or a '%' in a secret) would
    raise on ConfigParser.set()/get() as a broken interpolation token.
    """
    ensure_config_exists()
    config = configparser.ConfigParser(interpolation=None)
    config.read(CONFIG_FILE)
    return config


def write_config(config: configparser.ConfigParser) -> None:
    """Write configuration to file."""
    ensure_config_exists()
    with open(CONFIG_FILE, 'w') as f:
        config.write(f)


# =============================================================================
# Settings
# =============================================================================

# Directories from which the pg_dump / pg_restore binaries may be executed.
# Locking the path down prevents an admin from pointing the tool path at an
# arbitrary binary, which would otherwise yield code execution as the app user.
# Extra directories can be added via the ALLOWED_PG_BIN_DIRS env var (comma-separated).
_DEFAULT_PG_BIN_DIRS = ("/usr/bin", "/usr/local/bin", "/bin")
_PG_BIN_DIR_GLOBS = ("/usr/lib/postgresql/*/bin",)


def _allowed_pg_bin_dirs() -> set:
    """Resolve the set of directories allowed to hold pg_dump/pg_restore."""
    dirs = set(_DEFAULT_PG_BIN_DIRS)
    for pattern in _PG_BIN_DIR_GLOBS:
        dirs.update(glob.glob(pattern))
    extra = os.environ.get("ALLOWED_PG_BIN_DIRS", "").strip()
    if extra:
        dirs.update(d.strip() for d in extra.split(",") if d.strip())
    return {os.path.normpath(d) for d in dirs}


def validate_pg_tool_path(path: str, expected_basename: str) -> None:
    """Validate a pg_dump/pg_restore executable path against an allowlist.

    Raises ValueError if the path is not absolute, has an unexpected basename,
    contains shell/path-traversal characters, or lives outside an allowed dir.
    Symlinks are intentionally NOT resolved (the OS-packaged tools are symlinks
    to a wrapper with a different name).
    """
    if not path or not isinstance(path, str):
        raise ValueError(f"{expected_basename} path cannot be empty")
    if any(c in path for c in ('\x00', '\n', '\r', ';', '|', '&', '$', '`', '*', '?')):
        raise ValueError(f"Invalid {expected_basename} path: contains disallowed characters")
    norm = os.path.normpath(path)
    if not os.path.isabs(norm):
        raise ValueError(f"{expected_basename} path must be absolute")
    if os.path.basename(norm) != expected_basename:
        raise ValueError(f"{expected_basename} path must point to a binary named '{expected_basename}'")
    parent = os.path.dirname(norm)
    if parent not in _allowed_pg_bin_dirs():
        allowed = ", ".join(sorted(_allowed_pg_bin_dirs()))
        raise ValueError(
            f"{expected_basename} path '{path}' is not in an allowed directory. "
            f"Allowed: {allowed}"
        )


def get_settings() -> Settings:
    """Get application settings."""
    config = read_config()
    return Settings(
        backup_dir=config.get('settings', 'backup_dir', fallback=str(APP_ROOT / 'backups')),
        pg_dump_path=config.get('settings', 'pg_dump_path', fallback='/usr/bin/pg_dump'),
        pg_restore_path=config.get('settings', 'pg_restore_path', fallback='/usr/bin/pg_restore'),
        max_upload_size_gb=config.getint('settings', 'max_upload_size_gb', fallback=5),
        lock_wait_timeout_seconds=config.getint('settings', 'lock_wait_timeout_seconds', fallback=60),
        log_level=config.get('settings', 'log_level', fallback='INFO'),
        context_path=config.get('settings', 'context_path', fallback=''),
    )


def save_settings(settings: Settings) -> None:
    """Save application settings."""
    # Reject attempts to point the tool paths at arbitrary binaries.
    validate_pg_tool_path(settings.pg_dump_path, 'pg_dump')
    validate_pg_tool_path(settings.pg_restore_path, 'pg_restore')
    config = read_config()
    if 'settings' not in config:
        config.add_section('settings')
    config.set('settings', 'backup_dir', settings.backup_dir)
    config.set('settings', 'pg_dump_path', settings.pg_dump_path)
    config.set('settings', 'pg_restore_path', settings.pg_restore_path)
    config.set('settings', 'max_upload_size_gb', str(settings.max_upload_size_gb))
    config.set('settings', 'lock_wait_timeout_seconds', str(settings.lock_wait_timeout_seconds))
    config.set('settings', 'log_level', settings.log_level)
    config.set('settings', 'context_path', settings.context_path)
    write_config(config)


# =============================================================================
# Context Path
# =============================================================================

def _normalize_context_path(path: str) -> str:
    """Normalize a context path: ensure leading /, strip trailing /."""
    path = path.strip().rstrip('/')
    if path and not path.startswith('/'):
        path = '/' + path
    return path


def get_context_path() -> str:
    """Get the effective context path.
    Priority: ROOT_PATH env var > config.ini [settings] context_path > empty string.
    """
    env_path = os.environ.get('ROOT_PATH', '').strip()
    if env_path:
        return _normalize_context_path(env_path)
    config = read_config()
    config_path = config.get('settings', 'context_path', fallback='').strip()
    if config_path:
        return _normalize_context_path(config_path)
    return ""


# =============================================================================
# Query Settings
# =============================================================================

def get_query_settings() -> QuerySettings:
    """Get query editor settings."""
    config = read_config()
    return QuerySettings(
        autocommit=config.getboolean('query', 'autocommit', fallback=False),
    )


def save_query_settings(query_settings: QuerySettings) -> None:
    """Save query editor settings."""
    config = read_config()
    if 'query' not in config:
        config.add_section('query')
    config.set('query', 'autocommit', str(query_settings.autocommit).lower())
    write_config(config)


# =============================================================================
# AWS Configuration (Multi-Account)
# =============================================================================

def get_aws_configs() -> Dict[str, AWSConfig]:
    """Get all AWS account configurations from [aws:alias] sections."""
    config = read_config()
    accounts = {}
    for section in config.sections():
        if section.startswith('aws:'):
            alias = section[4:]  # strip 'aws:' prefix
            accounts[alias] = AWSConfig(
                alias=alias,
                access_key_id=config.get(section, 'access_key_id', fallback=''),
                secret_access_key=config.get(section, 'secret_access_key', fallback=''),
                region=config.get(section, 'region', fallback='us-east-1'),
            )
    # Backwards compatibility: legacy [aws] section without [aws:*]
    if not accounts and 'aws' in config:
        accounts['default'] = AWSConfig(
            alias='default',
            access_key_id=config.get('aws', 'access_key_id', fallback=''),
            secret_access_key=config.get('aws', 'secret_access_key', fallback=''),
            region=config.get('aws', 'region', fallback='us-east-1'),
        )
    return accounts


def get_aws_config(alias: str = None) -> Optional[AWSConfig]:
    """Get a specific AWS account configuration by alias.
    If alias is None/empty and only one account exists, return it."""
    accounts = get_aws_configs()
    if alias:
        return accounts.get(alias)
    if len(accounts) == 1:
        return next(iter(accounts.values()))
    return None


def save_aws_config(aws_config: AWSConfig) -> None:
    """Save an AWS account configuration under [aws:<alias>]."""
    config = read_config()
    section = f'aws:{aws_config.alias}'
    if section not in config:
        config.add_section(section)
    config.set(section, 'access_key_id', aws_config.access_key_id)
    config.set(section, 'secret_access_key', aws_config.secret_access_key)
    config.set(section, 'region', aws_config.region)
    write_config(config)


def delete_aws_config(alias: str) -> None:
    """Delete an AWS account configuration."""
    config = read_config()
    section = f'aws:{alias}'
    if config.has_section(section):
        config.remove_section(section)
        write_config(config)
        logger.info(f"Deleted AWS account '{alias}'")


# =============================================================================
# Remote Storage: S3 buckets and WebDAV file shares (for backup files)
# =============================================================================

def get_s3_storage_configs() -> Dict[str, S3StorageConfig]:
    """Get all S3 storage configs from [s3:<name>] sections (secret decrypted)."""
    config = read_config()
    stores: Dict[str, S3StorageConfig] = {}
    for section in config.sections():
        if section.startswith('s3:'):
            name = section[len('s3:'):]
            stores[name] = S3StorageConfig(
                name=name,
                bucket=config.get(section, 'bucket', fallback=''),
                region=config.get(section, 'region', fallback='us-east-1'),
                endpoint_url=config.get(section, 'endpoint_url', fallback=''),
                prefix=config.get(section, 'prefix', fallback=''),
                path_style=config.getboolean(section, 'path_style', fallback=False),
                cred_mode=config.get(section, 'cred_mode', fallback='dedicated'),
                aws_account_alias=config.get(section, 'aws_account_alias', fallback=''),
                access_key_id=config.get(section, 'access_key_id', fallback=''),
                secret_access_key=decrypt_password(config.get(section, 'secret_access_key', fallback='')),
            )
    return stores


def get_s3_storage_config(name: str) -> Optional[S3StorageConfig]:
    """Get a specific S3 storage config by name."""
    return get_s3_storage_configs().get(name)


def save_s3_storage_config(store: S3StorageConfig) -> None:
    """Save an S3 storage config under [s3:<name>] (secret encrypted at rest)."""
    config = read_config()
    section = f's3:{store.name}'
    if section not in config:
        config.add_section(section)
    config.set(section, 'bucket', store.bucket)
    config.set(section, 'region', store.region)
    config.set(section, 'endpoint_url', store.endpoint_url)
    config.set(section, 'prefix', store.prefix)
    config.set(section, 'path_style', str(store.path_style).lower())
    config.set(section, 'cred_mode', store.cred_mode)
    config.set(section, 'aws_account_alias', store.aws_account_alias)
    config.set(section, 'access_key_id', store.access_key_id)
    config.set(section, 'secret_access_key', encrypt_password(store.secret_access_key))
    write_config(config)
    logger.info(f"Saved S3 storage '{store.name}' (bucket: {store.bucket}, cred_mode: {store.cred_mode})")


def delete_s3_storage_config(name: str) -> None:
    """Delete an S3 storage config."""
    config = read_config()
    section = f's3:{name}'
    if config.has_section(section):
        config.remove_section(section)
        write_config(config)
        logger.info(f"Deleted S3 storage '{name}'")


def get_fileshare_configs() -> Dict[str, FileShareConfig]:
    """Get all WebDAV file share configs from [fileshare:<name>] sections (password decrypted)."""
    config = read_config()
    shares: Dict[str, FileShareConfig] = {}
    for section in config.sections():
        if section.startswith('fileshare:'):
            name = section[len('fileshare:'):]
            shares[name] = FileShareConfig(
                name=name,
                base_url=config.get(section, 'base_url', fallback=''),
                username=config.get(section, 'username', fallback=''),
                password=decrypt_password(config.get(section, 'password', fallback='')),
                verify_ssl=config.getboolean(section, 'verify_ssl', fallback=True),
            )
    return shares


def get_fileshare_config(name: str) -> Optional[FileShareConfig]:
    """Get a specific file share config by name."""
    return get_fileshare_configs().get(name)


def save_fileshare_config(share: FileShareConfig) -> None:
    """Save a WebDAV file share config under [fileshare:<name>] (password encrypted at rest)."""
    config = read_config()
    section = f'fileshare:{share.name}'
    if section not in config:
        config.add_section(section)
    config.set(section, 'base_url', share.base_url)
    config.set(section, 'username', share.username)
    config.set(section, 'password', encrypt_password(share.password))
    config.set(section, 'verify_ssl', str(share.verify_ssl).lower())
    write_config(config)
    logger.info(f"Saved file share '{share.name}' (url: {share.base_url})")


def delete_fileshare_config(name: str) -> None:
    """Delete a file share config."""
    config = read_config()
    section = f'fileshare:{name}'
    if config.has_section(section):
        config.remove_section(section)
        write_config(config)
        logger.info(f"Deleted file share '{name}'")


def get_filebrowser_configs() -> Dict[str, FileBrowserConfig]:
    """Get all filebrowser configs from [filebrowser:<name>] sections (password decrypted)."""
    config = read_config()
    out: Dict[str, FileBrowserConfig] = {}
    for section in config.sections():
        if section.startswith('filebrowser:'):
            name = section[len('filebrowser:'):]
            out[name] = FileBrowserConfig(
                name=name,
                base_url=config.get(section, 'base_url', fallback=''),
                root_path=config.get(section, 'root_path', fallback=''),
                username=config.get(section, 'username', fallback=''),
                password=decrypt_password(config.get(section, 'password', fallback='')),
                verify_ssl=config.getboolean(section, 'verify_ssl', fallback=True),
            )
    return out


def get_filebrowser_config(name: str) -> Optional[FileBrowserConfig]:
    """Get a specific filebrowser config by name."""
    return get_filebrowser_configs().get(name)


def save_filebrowser_config(fb: FileBrowserConfig) -> None:
    """Save a filebrowser config under [filebrowser:<name>] (password encrypted at rest)."""
    config = read_config()
    section = f'filebrowser:{fb.name}'
    if section not in config:
        config.add_section(section)
    config.set(section, 'base_url', fb.base_url)
    config.set(section, 'root_path', fb.root_path)
    config.set(section, 'username', fb.username)
    config.set(section, 'password', encrypt_password(fb.password))
    config.set(section, 'verify_ssl', str(fb.verify_ssl).lower())
    write_config(config)
    logger.info(f"Saved filebrowser '{fb.name}' (url: {fb.base_url})")


def delete_filebrowser_config(name: str) -> None:
    """Delete a filebrowser config."""
    config = read_config()
    section = f'filebrowser:{name}'
    if config.has_section(section):
        config.remove_section(section)
        write_config(config)
        logger.info(f"Deleted filebrowser '{name}'")


# =============================================================================
# Scheduled Backups
# =============================================================================

# Section names / prefixes a schedule name may not collide with. A schedule
# name is used verbatim as the [schedule:<name>] section key, so it must not be
# able to masquerade as (or inject) any other config section.
_RESERVED_PREFIXES = (
    "settings", "auth", "query", "aws:", "s3:", "fileshare:",
    "filebrowser:", "jumphosts", "endpoints", "schedule:",
)

_SCHEDULE_NAME_RE = re.compile(r'^[a-zA-Z0-9_-]{2,50}$')


def validate_schedule_name(name: str) -> None:
    """Validate a schedule name. Raises ValueError if it fails the charset
    (^[a-zA-Z0-9_-]{2,50}$) or collides with a reserved section/prefix.

    Unlike the S3/fileshare save functions (which don't validate), schedule
    names are validated because the name is the section key and an unattended
    job binds to it."""
    if not name or not isinstance(name, str):
        raise ValueError("Schedule name cannot be empty")
    if not _SCHEDULE_NAME_RE.match(name):
        raise ValueError(
            "Schedule name must be 2-50 characters using only letters, "
            "digits, hyphen and underscore"
        )
    lowered = name.lower()
    for reserved in _RESERVED_PREFIXES:
        if reserved.endswith(':'):
            if lowered.startswith(reserved):
                raise ValueError(f"Schedule name may not start with reserved prefix '{reserved}'")
        elif lowered == reserved:
            raise ValueError(f"Schedule name may not be the reserved section name '{reserved}'")


def get_schedules() -> Dict[str, ScheduleConfig]:
    """Get all scheduled backup definitions from [schedule:<name>] sections."""
    config = read_config()
    schedules: Dict[str, ScheduleConfig] = {}
    for section in config.sections():
        if section.startswith('schedule:'):
            name = section[len('schedule:'):]
            schedules[name] = ScheduleConfig(
                name=name,
                cron=config.get(section, 'cron', fallback=''),
                endpoint=config.get(section, 'endpoint', fallback=''),
                database=config.get(section, 'database', fallback=''),
                enabled=config.getboolean(section, 'enabled', fallback=True),
                large_objects=config.getboolean(section, 'large_objects', fallback=True),
                no_owner=config.getboolean(section, 'no_owner', fallback=True),
                no_privileges=config.getboolean(section, 'no_privileges', fallback=True),
                no_tablespaces=config.getboolean(section, 'no_tablespaces', fallback=True),
                no_comments=config.getboolean(section, 'no_comments', fallback=True),
                data_only=config.getboolean(section, 'data_only', fallback=False),
                schema_only=config.getboolean(section, 'schema_only', fallback=False),
                clean=config.getboolean(section, 'clean', fallback=False),
                create=config.getboolean(section, 'create', fallback=False),
                schemas=config.get(section, 'schemas', fallback=''),
                exclude_table=config.get(section, 'exclude_table', fallback=''),
                exclude_table_data=config.get(section, 'exclude_table_data', fallback=''),
                exclude_schema=config.get(section, 'exclude_schema', fallback=''),
                dest_kind=config.get(section, 'dest_kind', fallback='none'),
                dest_target=config.get(section, 'dest_target', fallback=''),
                delete_local_after_copy=config.getboolean(section, 'delete_local_after_copy', fallback=False),
                keep_last_n=config.getint(section, 'keep_last_n', fallback=0),
            )
    return schedules


def get_schedule(name: str) -> Optional[ScheduleConfig]:
    """Get a specific scheduled backup definition by name."""
    return get_schedules().get(name)


def save_schedule(sched: ScheduleConfig) -> None:
    """Save a scheduled backup definition under [schedule:<name>].

    The name is validated (validate_schedule_name); no secrets are stored — a
    schedule references an endpoint and remote target by name only."""
    validate_schedule_name(sched.name)
    config = read_config()
    section = f'schedule:{sched.name}'
    if section not in config:
        config.add_section(section)
    config.set(section, 'cron', sched.cron)
    config.set(section, 'endpoint', sched.endpoint)
    config.set(section, 'database', sched.database)
    config.set(section, 'enabled', str(sched.enabled).lower())
    config.set(section, 'large_objects', str(sched.large_objects).lower())
    config.set(section, 'no_owner', str(sched.no_owner).lower())
    config.set(section, 'no_privileges', str(sched.no_privileges).lower())
    config.set(section, 'no_tablespaces', str(sched.no_tablespaces).lower())
    config.set(section, 'no_comments', str(sched.no_comments).lower())
    config.set(section, 'data_only', str(sched.data_only).lower())
    config.set(section, 'schema_only', str(sched.schema_only).lower())
    config.set(section, 'clean', str(sched.clean).lower())
    config.set(section, 'create', str(sched.create).lower())
    config.set(section, 'schemas', sched.schemas)
    config.set(section, 'exclude_table', sched.exclude_table)
    config.set(section, 'exclude_table_data', sched.exclude_table_data)
    config.set(section, 'exclude_schema', sched.exclude_schema)
    config.set(section, 'dest_kind', sched.dest_kind)
    config.set(section, 'dest_target', sched.dest_target)
    config.set(section, 'delete_local_after_copy', str(sched.delete_local_after_copy).lower())
    config.set(section, 'keep_last_n', str(sched.keep_last_n))
    write_config(config)
    logger.info(f"Saved schedule '{sched.name}' (cron: {sched.cron}, endpoint: {sched.endpoint}, "
                f"database: {sched.database}, enabled: {sched.enabled})")


def delete_schedule(name: str) -> None:
    """Delete a scheduled backup definition."""
    config = read_config()
    section = f'schedule:{name}'
    if config.has_section(section):
        config.remove_section(section)
        write_config(config)
        logger.info(f"Deleted schedule '{name}'")


# =============================================================================
# Jump Hosts
# =============================================================================

def get_jumphosts() -> Dict[str, JumphostConfig]:
    """Get all configured jump hosts. Format: alias = instance_id|aws_account_alias"""
    config = read_config()
    jumphosts = {}

    if 'jumphosts' in config:
        for alias, value in config['jumphosts'].items():
            if not value or value.startswith('#'):
                continue
            parts = value.split('|')
            instance_id = parts[0].strip()
            aws_account_alias = parts[1].strip() if len(parts) >= 2 else ""
            jumphosts[alias] = JumphostConfig(
                alias=alias,
                instance_id=instance_id,
                aws_account_alias=aws_account_alias,
            )

    return jumphosts


def get_jumphost(alias: str) -> Optional[JumphostConfig]:
    """Get a specific jump host by alias."""
    jumphosts = get_jumphosts()
    return jumphosts.get(alias)


def save_jumphost(jumphost: JumphostConfig) -> None:
    """Save or update a jump host configuration."""
    config = read_config()
    if 'jumphosts' not in config:
        config.add_section('jumphosts')
    value = f"{jumphost.instance_id}|{jumphost.aws_account_alias}"
    config.set('jumphosts', jumphost.alias, value)
    write_config(config)
    logger.info(f"Saved jumphost '{jumphost.alias}' -> {jumphost.instance_id} (AWS: {jumphost.aws_account_alias})")


def delete_jumphost(alias: str) -> None:
    """Delete a jump host configuration."""
    config = read_config()
    if 'jumphosts' in config and config.has_option('jumphosts', alias):
        config.remove_option('jumphosts', alias)
        write_config(config)
        logger.info(f"Deleted jumphost '{alias}'")


# =============================================================================
# Database Endpoints
# =============================================================================

def get_database_configs() -> Dict[str, DatabaseConfig]:
    """Get all database configurations with decrypted passwords."""
    config = read_config()
    databases = {}

    if 'endpoints' in config:
        for name, value in config['endpoints'].items():
            if not value or value.startswith('#'):
                continue

            try:
                parts = value.split('|')
                if len(parts) >= 4:
                    password = decrypt_password(parts[3].strip())

                    # Parse SSM fields (6-field format) or default (4-field).
                    # 7th field (optional) = read_only flag, defaults False.
                    use_ssm = False
                    jumphost_alias = ""
                    read_only = False
                    backup_use_replica = False
                    replica_host = ""
                    if len(parts) >= 5:
                        use_ssm = parts[4].strip().lower() == 'true'
                    if len(parts) >= 6:
                        jumphost_alias = parts[5].strip()
                    if len(parts) >= 7:
                        read_only = parts[6].strip().lower() == 'true'
                    # 8th/9th fields (optional): backup_use_replica + replica_host
                    if len(parts) >= 8:
                        backup_use_replica = parts[7].strip().lower() == 'true'
                    if len(parts) >= 9:
                        replica_host = parts[8].strip()

                    databases[name] = DatabaseConfig(
                        name=name,
                        host=parts[0].strip(),
                        port=int(parts[1].strip()),
                        username=parts[2].strip(),
                        password=password,
                        use_ssm=use_ssm,
                        jumphost_alias=jumphost_alias,
                        read_only=read_only,
                        backup_use_replica=backup_use_replica,
                        replica_host=replica_host,
                    )
            except (ValueError, IndexError) as e:
                logger.warning(f"Invalid database config for '{name}': {e}")
                continue

    # Also check environment variables for dynamic config (Kubernetes)
    for key, value in os.environ.items():
        if key.startswith('DB_ENDPOINT_'):
            db_name = key[len('DB_ENDPOINT_'):].lower()
            try:
                endpoint, port = value.split('|')
                username = os.environ.get(f'DB_USERNAME_{db_name.upper()}', '')
                password = os.environ.get(f'DB_PASSWORD_{db_name.upper()}', '')

                if username and password:
                    databases[db_name] = DatabaseConfig(
                        name=db_name,
                        host=endpoint,
                        port=int(port),
                        username=username,
                        password=password,
                    )
            except (ValueError, KeyError):
                continue

    return databases


def get_database_endpoints() -> Dict[str, DatabaseConfig]:
    """Alias for get_database_configs()."""
    return get_database_configs()


def get_database_endpoint(name: str) -> Optional[DatabaseConfig]:
    """Get a specific database endpoint by name."""
    endpoints = get_database_configs()
    return endpoints.get(name)


def save_database_config(db_config: DatabaseConfig) -> None:
    """Save a database configuration with encrypted password."""
    config = read_config()
    if 'endpoints' not in config:
        config.add_section('endpoints')

    encrypted_password = encrypt_password(db_config.password)
    use_ssm_str = 'true' if db_config.use_ssm else 'false'
    read_only_str = 'true' if db_config.read_only else 'false'
    use_replica_str = 'true' if db_config.backup_use_replica else 'false'

    value = (f"{db_config.host}|{db_config.port}|{db_config.username}|{encrypted_password}"
             f"|{use_ssm_str}|{db_config.jumphost_alias}|{read_only_str}"
             f"|{use_replica_str}|{db_config.replica_host}")
    config.set('endpoints', db_config.name, value)
    write_config(config)

    logger.info(f"Saved database config '{db_config.name}' (SSM: {db_config.use_ssm}, "
                f"read_only: {db_config.read_only}, backup_use_replica: {db_config.backup_use_replica})")


def delete_database_config(name: str) -> None:
    """Delete a database configuration."""
    config = read_config()
    if 'endpoints' in config and config.has_option('endpoints', name):
        config.remove_option('endpoints', name)
        write_config(config)


def encrypt_existing_passwords() -> int:
    """Encrypt all existing plain-text passwords. Returns count."""
    config = read_config()
    encrypted_count = 0

    if 'endpoints' not in config:
        return 0

    for name, value in config['endpoints'].items():
        if not value or value.startswith('#'):
            continue

        try:
            parts = value.split('|')
            if len(parts) >= 4:
                password = parts[3].strip()
                if not is_password_encrypted(password):
                    parts[3] = encrypt_password(password)
                    config.set('endpoints', name, '|'.join(parts))
                    encrypted_count += 1
                    logger.info(f"Encrypted password for '{name}'")
        except (ValueError, IndexError):
            continue

    if encrypted_count > 0:
        write_config(config)

    return encrypted_count


# =============================================================================
# Config Export / Import
# =============================================================================

def get_full_config_content() -> str:
    """Get the full config file content for download/export."""
    ensure_config_exists()
    return CONFIG_FILE.read_text()


def migrate_legacy_aws_config() -> bool:
    """Migrate legacy [aws] section to [aws:default]. Returns True if migration occurred."""
    config = read_config()
    has_legacy = 'aws' in config and not any(s.startswith('aws:') for s in config.sections())
    if not has_legacy:
        return False

    alias = 'default'
    new_section = f'aws:{alias}'
    config.add_section(new_section)
    for key, value in config['aws'].items():
        config.set(new_section, key, value)
    config.remove_section('aws')

    # Update jumphosts to reference this account
    if 'jumphosts' in config:
        for jh_alias in list(config['jumphosts'].keys()):
            value = config.get('jumphosts', jh_alias)
            if value and '|' not in value:
                config.set('jumphosts', jh_alias, f"{value}|{alias}")

    write_config(config)
    logger.info("Migrated legacy [aws] section to [aws:default]")
    return True


def _sanitize_imported_schedules() -> int:
    """Force enabled=false on any imported [schedule:*] that is unsafe to run
    unattended: an invalid name, an endpoint that doesn't resolve, or a
    dest_target that doesn't resolve for its dest_kind. Returns the count
    disabled. Operates on the currently written config file."""
    config = read_config()
    endpoints = get_database_configs()
    s3 = get_s3_storage_configs()
    fileshares = get_fileshare_configs()
    filebrowsers = get_filebrowser_configs()

    disabled = 0
    for section in config.sections():
        if not section.startswith('schedule:'):
            continue
        # Already-disabled schedules need no further handling.
        if not config.getboolean(section, 'enabled', fallback=True):
            continue

        name = section[len('schedule:'):]
        invalid = False
        try:
            validate_schedule_name(name)
        except ValueError:
            invalid = True

        if not invalid:
            endpoint = config.get(section, 'endpoint', fallback='')
            if endpoint not in endpoints:
                invalid = True

        if not invalid:
            dest_kind = config.get(section, 'dest_kind', fallback='none')
            dest_target = config.get(section, 'dest_target', fallback='')
            if dest_kind == 's3' and dest_target not in s3:
                invalid = True
            elif dest_kind == 'fileshare' and dest_target not in fileshares:
                invalid = True
            elif dest_kind == 'filebrowser' and dest_target not in filebrowsers:
                invalid = True

        if invalid:
            config.set(section, 'enabled', 'false')
            disabled += 1
            logger.warning(f"Imported schedule '{name}' disabled (invalid name or unresolved reference)")

    if disabled:
        write_config(config)
    return disabled


def import_config_content(content: str) -> Dict:
    """
    Import a config file content. Validates structure before saving.
    Returns dict with success status and details.
    """
    # Validate the content is parseable
    test_config = configparser.ConfigParser(interpolation=None)
    try:
        test_config.read_string(content)
    except configparser.Error as e:
        return {"success": False, "error": f"Invalid INI format: {e}"}

    # Check required sections
    required_sections = ['settings', 'auth']
    missing = [s for s in required_sections if s not in test_config]
    if missing:
        return {"success": False, "error": f"Missing required sections: {', '.join(missing)}"}

    # Reject configs that try to point the tool paths at arbitrary binaries.
    try:
        dump_path = test_config.get('settings', 'pg_dump_path', fallback='/usr/bin/pg_dump')
        restore_path = test_config.get('settings', 'pg_restore_path', fallback='/usr/bin/pg_restore')
        validate_pg_tool_path(dump_path, 'pg_dump')
        validate_pg_tool_path(restore_path, 'pg_restore')
    except ValueError as e:
        return {"success": False, "error": str(e)}

    # Backup current config
    backup_path = CONFIG_FILE.with_suffix('.ini.bak')
    if CONFIG_FILE.exists():
        backup_path.write_text(CONFIG_FILE.read_text())

    # Write new config
    CONFIG_FILE.write_text(content)

    # Trigger migration if imported config has legacy [aws] section
    global _migration_done
    _migration_done = False  # Reset so migration can run on new config

    # Guard imported schedules: any [schedule:*] with an invalid name or an
    # unresolved endpoint/dest_target is imported disabled rather than executed.
    try:
        _sanitize_imported_schedules()
    except Exception as e:
        logger.warning(f"Failed to sanitize imported schedules: {e}")

    # Count what was imported
    endpoint_count = len(dict(test_config['endpoints'])) if 'endpoints' in test_config else 0
    jumphost_count = len(dict(test_config['jumphosts'])) if 'jumphosts' in test_config else 0
    aws_count = sum(1 for s in test_config.sections() if s.startswith('aws:'))
    if aws_count == 0 and 'aws' in test_config:
        aws_count = 1  # legacy format

    return {
        "success": True,
        "message": f"Imported configuration: {endpoint_count} endpoints, {jumphost_count} jumphosts, {aws_count} AWS accounts",
        "backup_path": str(backup_path),
    }


def get_session_timeout() -> int:
    """Get session timeout in minutes."""
    config = read_config()
    return config.getint('auth', 'session_timeout_minutes', fallback=480)
