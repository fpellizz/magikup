"""
Configuration management for PostgreSQL Backup/Restore Application (Full).
Unified single-file configuration with support for direct and SSM tunnel connections.
Includes password encryption for secure storage.
"""

import os
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


APP_ROOT = Path(__file__).parent.parent

@dataclass
class Settings:
    """Application settings."""
    backup_dir: str = str(APP_ROOT / "backups")
    pg_dump_path: str = "/usr/bin/pg_dump"
    pg_restore_path: str = "/usr/bin/pg_restore"
    max_upload_size_gb: int = 5
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
# Format: name = host|port|username|password|use_ssm|jumphost_alias|read_only
# use_ssm: true or false
# jumphost_alias: references a key in [jumphosts] (leave empty if use_ssm=false)
# read_only: true or false (optional, default false). When true the query editor
#            runs read-only and restore/transfer to this endpoint are refused.
# Example (direct):     local-db = 10.0.1.100|5432|postgres|mypassword|false||false
# Example (SSM):        prod-aurora = aurora-cluster.rds.amazonaws.com|5432|admin|ENC:...|true|production-jh|false
# Example (read-only):  prod-ro = reporting.rds.amazonaws.com|5432|readonly|ENC:...|false||true
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
    """Read configuration file."""
    ensure_config_exists()
    config = configparser.ConfigParser()
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
                    if len(parts) >= 5:
                        use_ssm = parts[4].strip().lower() == 'true'
                    if len(parts) >= 6:
                        jumphost_alias = parts[5].strip()
                    if len(parts) >= 7:
                        read_only = parts[6].strip().lower() == 'true'

                    databases[name] = DatabaseConfig(
                        name=name,
                        host=parts[0].strip(),
                        port=int(parts[1].strip()),
                        username=parts[2].strip(),
                        password=password,
                        use_ssm=use_ssm,
                        jumphost_alias=jumphost_alias,
                        read_only=read_only,
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

    value = f"{db_config.host}|{db_config.port}|{db_config.username}|{encrypted_password}|{use_ssm_str}|{db_config.jumphost_alias}|{read_only_str}"
    config.set('endpoints', db_config.name, value)
    write_config(config)

    logger.info(f"Saved database config '{db_config.name}' (SSM: {db_config.use_ssm}, read_only: {db_config.read_only})")


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


def import_config_content(content: str) -> Dict:
    """
    Import a config file content. Validates structure before saving.
    Returns dict with success status and details.
    """
    # Validate the content is parseable
    test_config = configparser.ConfigParser()
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
