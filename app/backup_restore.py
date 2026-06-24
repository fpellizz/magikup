"""
Backup and Restore module for PostgreSQL databases.
Handles pg_dump and pg_restore operations with direct connections.
"""

import os
import re
import subprocess
import asyncio
import fnmatch
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, AsyncGenerator, List, Tuple
from dataclasses import dataclass

from .config import get_settings, validate_pg_tool_path
from .operation_logger import get_logger


@dataclass
class BackupOptions:
    """Options for pg_dump."""
    large_objects: bool = True
    no_owner: bool = True
    no_privileges: bool = True
    no_tablespaces: bool = True
    no_comments: bool = True
    data_only: bool = False
    schema_only: bool = False
    clean: bool = False
    create: bool = False
    exclude_table: Optional[str] = None
    exclude_table_data: Optional[str] = None
    exclude_schema: Optional[str] = None
    schemas: Optional[List[str]] = None  # If set, only backup these schemas


@dataclass
class RestoreOptions:
    """Options for pg_restore."""
    clean: bool = True
    no_owner: bool = True
    no_privileges: bool = True
    role: Optional[str] = None
    exclude_schema: Optional[List[str]] = None  # List of schemas to exclude
    schemas: Optional[List[str]] = None  # If set, only restore these schemas
    data_only: bool = False
    schema_only: bool = False
    no_comments: bool = False
    no_tablespaces: bool = False
    no_publications: bool = False
    no_subscriptions: bool = False
    jobs: Optional[int] = None
    exit_on_error: bool = False
    exclude_tables: Optional[List[str]] = None  # Table name patterns to exclude via TOC filtering
    timescaledb: bool = False  # Run timescaledb_pre_restore() / _post_restore() and add --disable-triggers


def _call_timescaledb_procedure(
    procedure: str,
    database: str,
    host: str,
    port: int,
    username: str,
    password: str,
) -> None:
    """Execute a TimescaleDB restore helper (timescaledb_pre_restore / _post_restore).
    Raises on failure (including when the extension is not installed)."""
    import psycopg2
    conn = psycopg2.connect(
        host=host, port=port, dbname=database,
        user=username, password=password,
        connect_timeout=10,
    )
    conn.autocommit = True
    try:
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT {procedure}();")
    finally:
        conn.close()


def get_backup_dir() -> Path:
    """Get the backup directory, creating it if necessary."""
    settings = get_settings()
    backup_dir = Path(settings.backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    return backup_dir


def list_backup_files() -> List[Dict[str, Any]]:
    """List all backup files in the backup directory."""
    backup_dir = get_backup_dir()
    files = []

    for file in backup_dir.glob("*.backup"):
        stat = file.stat()
        files.append({
            "name": file.name,
            "path": str(file),
            "size": stat.st_size,
            "size_human": _format_size(stat.st_size),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        })

    files.sort(key=lambda x: x["modified"], reverse=True)
    return files


def _format_size(size: int) -> str:
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def get_backup_stats() -> Dict[str, Any]:
    """Get statistics about backup files (count and total size)."""
    backup_dir = get_backup_dir()
    total_size = 0
    count = 0

    for file in backup_dir.glob("*.backup"):
        try:
            total_size += file.stat().st_size
            count += 1
        except OSError:
            pass

    return {
        "count": count,
        "total_size": total_size,
        "total_size_human": _format_size(total_size),
    }


def _validate_identifier(value: str, label: str = "identifier") -> None:
    """Validate a PostgreSQL identifier (database name, schema name, username).
    Raises ValueError if the value contains dangerous characters."""
    if not value:
        raise ValueError(f"{label} cannot be empty")
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', value):
        raise ValueError(f"Invalid {label}: contains disallowed characters")
    if len(value) > 128:
        raise ValueError(f"{label} is too long (max 128 characters)")


def _validate_table_pattern(pattern: str, label: str = "table pattern") -> None:
    """Validate a pg_dump table exclusion pattern.
    Allowed: alphanumeric, underscore, hyphen, dot, asterisk, question mark.
    Raises ValueError if the pattern contains dangerous characters."""
    if not pattern:
        raise ValueError(f"{label} cannot be empty")
    if not re.match(r'^[a-zA-Z0-9_\-\.\*\?]+$', pattern):
        raise ValueError(f"Invalid {label}: contains disallowed characters")
    if len(pattern) > 256:
        raise ValueError(f"{label} is too long (max 256 characters)")


def generate_backup_filename(database: str) -> str:
    """Generate a backup filename with timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{database}_{timestamp}.backup"


def validate_backup_filename(filename: str) -> Tuple[bool, str]:
    """
    Validate backup filename for upload.

    Args:
        filename: The filename to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Reject filenames with path separators or traversal components
    if '/' in filename or '\\' in filename or '..' in filename:
        return False, "Filename must not contain path components"

    # Remove any path components (defense in depth)
    filename = Path(filename).name

    # Check extension
    if not filename.endswith('.backup'):
        return False, "File must have .backup extension"

    # Check for dangerous characters
    # Allow: alphanumeric, underscore, hyphen, dot
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        return False, "Filename contains invalid characters"

    # Optional: Check filename pattern (database_YYYYMMDD_HHMMSS.backup)
    # Commented out to allow arbitrary .backup filenames
    # if not re.match(r'^[a-zA-Z0-9_\-]+_\d{8}_\d{6}\.backup$', filename):
    #     return False, "Filename must follow pattern: database_YYYYMMDD_HHMMSS.backup"

    return True, ""


def sanitize_backup_filename(filename: str) -> str:
    """
    Sanitize uploaded filename by removing path components and dangerous chars.

    Args:
        filename: The filename to sanitize

    Returns:
        Sanitized filename
    """
    # Get base filename only (no directory components)
    safe_name = Path(filename).name

    # Remove any remaining dangerous characters, keep only safe ones
    safe_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', safe_name)

    # Ensure .backup extension
    if not safe_name.endswith('.backup'):
        safe_name += '.backup'

    return safe_name


def check_file_size_limit(size_bytes: int, max_size_gb: int = 5) -> Tuple[bool, str]:
    """
    Check if file size is within limits.

    Args:
        size_bytes: File size in bytes
        max_size_gb: Maximum allowed size in GB

    Returns:
        Tuple of (is_valid, error_message)
    """
    max_bytes = max_size_gb * 1024 * 1024 * 1024

    if size_bytes > max_bytes:
        return False, f"File size {_format_size(size_bytes)} exceeds limit of {max_size_gb}GB"

    return True, ""


def save_uploaded_backup(filename: str, file_data: bytes) -> Dict[str, Any]:
    """
    Save uploaded backup file.

    Args:
        filename: Original filename (will be sanitized)
        file_data: File content as bytes

    Returns:
        Result dictionary with success/error
    """
    # Validate and sanitize filename
    is_valid, error_msg = validate_backup_filename(filename)
    if not is_valid:
        return {"success": False, "error": error_msg}

    safe_filename = sanitize_backup_filename(filename)

    # Check file size
    is_valid, error_msg = check_file_size_limit(len(file_data))
    if not is_valid:
        return {"success": False, "error": error_msg}

    # Get backup directory
    backup_dir = get_backup_dir()
    target_path = backup_dir / safe_filename

    # Check if file already exists
    if target_path.exists():
        return {
            "success": False,
            "error": f"File {safe_filename} already exists"
        }

    # Validate path is within backup directory (security check)
    try:
        target_path.resolve().relative_to(backup_dir.resolve())
    except ValueError:
        return {
            "success": False,
            "error": "Invalid file path"
        }

    # Write file atomically (write to temp, then rename)
    temp_path = target_path.with_suffix('.tmp')
    try:
        # Write to temp file
        temp_path.write_bytes(file_data)

        # Atomic rename
        temp_path.rename(target_path)

        return {
            "success": True,
            "message": f"Uploaded {safe_filename}",
            "filename": safe_filename,
            "size": len(file_data),
            "size_human": _format_size(len(file_data))
        }

    except Exception as e:
        # Clean up temp file if it exists
        if temp_path.exists():
            temp_path.unlink()

        return {
            "success": False,
            "error": f"Failed to save file: {str(e)}"
        }


async def run_backup(
    database: str,
    host: str = "localhost",
    port: int = 5432,
    username: str = "postgres",
    password: str = "",
    output_file: Optional[str] = None,
    options: Optional[BackupOptions] = None,
    operation_id: Optional[str] = None,
    cancel_event: Optional[asyncio.Event] = None,
) -> AsyncGenerator[Dict[str, Any], None]:
    """
    Run pg_dump and yield progress updates.
    Uses direct PostgreSQL connection via PGPASSWORD environment variable.

    Yields dictionaries with:
    - type: "progress", "output", "error", or "complete"
    - message: the message content
    - success: (only for "complete") whether backup succeeded
    """
    if options is None:
        options = BackupOptions()

    # Validate identifiers to prevent command injection
    _validate_identifier(database, "database name")
    _validate_identifier(username, "username")
    _validate_identifier(host, "host")
    if options.schemas:
        for s in options.schemas:
            _validate_identifier(s, "schema name")
    if options.exclude_schema:
        _validate_identifier(options.exclude_schema, "exclude schema name")
    if options.exclude_table:
        _validate_table_pattern(options.exclude_table, "exclude table pattern")
    if options.exclude_table_data:
        _validate_table_pattern(options.exclude_table_data, "exclude table data pattern")

    # Enforce mutual exclusivity
    if options.data_only and options.schema_only:
        raise ValueError("data_only and schema_only are mutually exclusive")

    settings = get_settings()
    backup_dir = get_backup_dir()

    if output_file is None:
        output_file = str(backup_dir / generate_backup_filename(database))

    # Get logger if operation_id is provided
    logger = get_logger() if operation_id else None

    # Defense in depth: refuse to exec a tool path outside the allowlist,
    # even if config.ini was edited out-of-band.
    try:
        validate_pg_tool_path(settings.pg_dump_path, 'pg_dump')
    except ValueError as e:
        error_msg = f"Refusing to run backup: {e}"
        if logger and operation_id:
            logger.log_message(operation_id, error_msg)
            logger.complete_operation(operation_id, status="failed", error=error_msg)
        yield {"type": "complete", "success": False, "message": error_msg}
        return

    cmd = [
        settings.pg_dump_path,
        '--file', output_file,
        '--host', host,
        '--port', str(port),
        '--username', username,
        '--no-password',
        '--format=c',
        '--verbose',
    ]

    # --data-only and --schema-only are mutually exclusive with --section flags
    if options.data_only:
        cmd.append('--data-only')
    elif options.schema_only:
        cmd.append('--schema-only')
    else:
        cmd.extend([
            '--section=pre-data',
            '--section=data',
            '--section=post-data',
        ])

    if options.clean:
        cmd.append('--clean')
    if options.create:
        cmd.append('--create')
    if options.large_objects:
        cmd.append('--large-objects')
    if options.no_owner:
        cmd.append('--no-owner')
    if options.no_privileges:
        cmd.append('--no-privileges')
    if options.no_tablespaces:
        cmd.append('--no-tablespaces')
    if options.no_comments:
        cmd.append('--no-comments')
    if options.exclude_schema and not options.schemas:
        cmd.extend(['--exclude-schema', options.exclude_schema])
    if options.exclude_table:
        cmd.extend(['--exclude-table', options.exclude_table])
    if options.exclude_table_data:
        cmd.extend(['--exclude-table-data', options.exclude_table_data])

    # Schema mode: backup only specific schemas
    if options.schemas:
        for schema in options.schemas:
            cmd.extend(['--schema', schema])

    cmd.extend([
        '--no-publications',
        '--no-subscriptions',
        '--no-security-labels',
        '--no-toast-compression',
        '--no-table-access-method',
        '--no-unlogged-table-data',
    ])

    cmd.append(database)

    # Use PGPASSWORD environment variable for authentication
    env = os.environ.copy()
    env['PGPASSWORD'] = password

    # Build progress message
    if options.schemas:
        schema_list = ', '.join(options.schemas)
        progress_msg = f"Starting backup of schemas [{schema_list}] from {database}..."
    else:
        progress_msg = f"Starting backup of {database}..."

    # Log command (without password)
    if logger and operation_id:
        cmd_display = ' '.join([c for c in cmd if c != password])
        logger.log_message(operation_id, f"Command: {cmd_display}")
        logger.log_message(operation_id, progress_msg)

    yield {
        "type": "progress",
        "message": progress_msg,
        "output_file": output_file,
    }

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            # stdout is unused (progress comes from --verbose on stderr); discard it
            # so a full pipe buffer can never deadlock the process.
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        # Track errors from pg_dump output
        error_count = 0
        last_errors = []

        async def read_stream(stream, stream_type):
            nonlocal error_count, last_errors
            while True:
                line = await stream.readline()
                if not line:
                    break
                decoded = line.decode().strip()
                if decoded:
                    lower = decoded.lower()
                    if 'errore:' in lower or 'error:' in lower:
                        error_count += 1
                        for marker in ['ERROR:  ', 'ERRORE:  ']:
                            idx = decoded.find(marker)
                            if idx != -1:
                                reason = decoded[idx + len(marker):].strip()
                                if reason and reason not in last_errors:
                                    last_errors.append(reason)
                                    if len(last_errors) > 5:
                                        last_errors.pop(0)
                                break

                    # Log to file
                    if logger and operation_id:
                        logger.log_message(operation_id, decoded)

                    yield {
                        "type": stream_type,
                        "message": decoded,
                    }

        cancelled = False
        async for item in read_stream(process.stderr, "output"):
            yield item
            if cancel_event and cancel_event.is_set():
                cancelled = True
                process.terminate()
                break

        await process.wait()

        if cancelled:
            cancel_msg = "Backup cancelled by user"
            if logger and operation_id:
                logger.log_message(operation_id, cancel_msg)
                logger.complete_operation(operation_id, status="cancelled", error=cancel_msg)
            yield {"type": "complete", "success": False, "message": cancel_msg}
        elif process.returncode == 0 and error_count == 0:
            file_size = os.path.getsize(output_file) if os.path.exists(output_file) else 0
            success_msg = "Backup completed successfully"

            if logger and operation_id:
                logger.log_message(operation_id, success_msg)
                logger.log_message(operation_id, f"Output file: {output_file}")
                logger.log_message(operation_id, f"File size: {_format_size(file_size)}")
                logger.complete_operation(operation_id, status="completed")

            yield {
                "type": "complete",
                "success": True,
                "message": success_msg,
                "output_file": output_file,
                "file_size": file_size,
                "file_size_human": _format_size(file_size),
            }
        elif error_count > 0 and process.returncode == 0:
            # pg_dump returned 0 but stderr had errors
            file_size = os.path.getsize(output_file) if os.path.exists(output_file) else 0
            error_summary = "; ".join(last_errors[:3])
            warning_msg = f"Backup completed with {error_count} errors: {error_summary}"

            if logger and operation_id:
                logger.log_message(operation_id, warning_msg)
                logger.complete_operation(operation_id, status="completed")

            yield {
                "type": "complete",
                "success": True,
                "message": warning_msg,
                "output_file": output_file,
                "file_size": file_size,
                "file_size_human": _format_size(file_size),
                "error_count": error_count,
            }
        else:
            error_summary = "; ".join(last_errors[:3]) if last_errors else ""
            error_msg = f"Backup failed (return code {process.returncode})"
            if error_summary:
                error_msg += f": {error_summary}"

            if logger and operation_id:
                logger.log_message(operation_id, error_msg)
                logger.complete_operation(operation_id, status="failed", error=error_msg)

            yield {
                "type": "complete",
                "success": False,
                "message": error_msg,
                "error_count": error_count,
            }

    except FileNotFoundError:
        error_msg = f"pg_dump not found at {settings.pg_dump_path}"

        if logger and operation_id:
            logger.log_message(operation_id, error_msg)
            logger.complete_operation(operation_id, status="failed", error=error_msg)

        yield {
            "type": "complete",
            "success": False,
            "message": error_msg,
        }
    except Exception as e:
        error_msg = f"Backup failed: {str(e)}"

        if logger and operation_id:
            logger.log_message(operation_id, error_msg)
            logger.complete_operation(operation_id, status="failed", error=error_msg)

        yield {
            "type": "complete",
            "success": False,
            "message": error_msg,
        }


async def _get_backup_toc(pg_restore_path: str, backup_file: str) -> str:
    """Run pg_restore --list to get the table of contents of a backup file."""
    process = await asyncio.create_subprocess_exec(
        pg_restore_path, '--list', backup_file,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(f"Failed to list backup contents: {stderr.decode().strip()}")
    return stdout.decode()


def _filter_toc_exclude_tables(toc: str, exclude_tables: List[str]) -> str:
    """Filter a pg_restore TOC by commenting out lines matching excluded table patterns.

    TOC data lines have the format:
        seq_id; oid oid TYPE schema name owner
    or for multi-word types like TABLE DATA:
        seq_id; oid oid TYPE TYPE2 schema name owner

    Args:
        toc: The raw TOC string from pg_restore --list.
        exclude_tables: List of table name patterns (supports * and ? wildcards).

    Returns:
        The filtered TOC string with excluded entries commented out.
    """
    # Object types that are associated with specific tables
    table_related_types = {
        'TABLE', 'TABLE DATA', 'INDEX', 'CONSTRAINT', 'FK CONSTRAINT',
        'TRIGGER', 'RULE', 'POLICY', 'ROW SECURITY',
    }

    filtered_lines = []
    for line in toc.splitlines():
        stripped = line.strip()
        # Keep comment lines and empty lines as-is
        if not stripped or stripped.startswith(';'):
            filtered_lines.append(line)
            continue

        # Parse TOC data line: "seq_id; rest..."
        if ';' not in stripped:
            filtered_lines.append(line)
            continue

        after_semi = stripped.split(';', 1)[1].strip()
        parts = after_semi.split()
        # Minimum: oid oid TYPE schema name owner => 6 parts
        # With multi-word type: oid oid TYPE TYPE2 schema name owner => 7 parts
        if len(parts) < 6:
            filtered_lines.append(line)
            continue

        # Determine object type and name
        # parts[0]=oid, parts[1]=oid, parts[2]=TYPE
        obj_type = parts[2]
        # Check for multi-word types (e.g., "TABLE DATA", "FK CONSTRAINT")
        name_idx = 4  # default: parts[3]=schema, parts[4]=name
        two_word_type = f"{parts[2]} {parts[3]}" if len(parts) >= 7 else ""
        if two_word_type in table_related_types:
            obj_type = two_word_type
            name_idx = 5  # parts[4]=schema, parts[5]=name

        # Only filter table-related objects
        if obj_type not in table_related_types:
            filtered_lines.append(line)
            continue

        obj_name = parts[name_idx] if len(parts) > name_idx else ""

        # Check if the object name matches any exclude pattern
        excluded = False
        for pattern in exclude_tables:
            if fnmatch.fnmatch(obj_name, pattern):
                excluded = True
                break

        if excluded:
            filtered_lines.append('; ' + line)  # Comment out the line
        else:
            filtered_lines.append(line)

    return '\n'.join(filtered_lines)


async def run_restore(
    backup_file: str,
    database: str,
    host: str = "localhost",
    port: int = 5432,
    username: str = "postgres",
    password: str = "",
    options: Optional[RestoreOptions] = None,
    operation_id: Optional[str] = None,
    cancel_event: Optional[asyncio.Event] = None,
) -> AsyncGenerator[Dict[str, Any], None]:
    """
    Run pg_restore and yield progress updates.
    Uses direct PostgreSQL connection via PGPASSWORD environment variable.

    Yields dictionaries with:
    - type: "progress", "output", "error", or "complete"
    - message: the message content
    - success: (only for "complete") whether restore succeeded
    """
    if options is None:
        options = RestoreOptions()

    # Validate identifiers to prevent command injection
    _validate_identifier(database, "database name")
    _validate_identifier(username, "username")
    _validate_identifier(host, "host")
    if options.role:
        _validate_identifier(options.role, "role name")
    if options.schemas:
        for s in options.schemas:
            _validate_identifier(s, "schema name")
    if options.exclude_schema:
        for s in options.exclude_schema:
            _validate_identifier(s, "exclude schema name")
    if options.exclude_tables:
        for t in options.exclude_tables:
            _validate_table_pattern(t)
    if options.jobs is not None and (not isinstance(options.jobs, int) or options.jobs < 1):
        raise ValueError("jobs must be a positive integer")

    settings = get_settings()

    # Get logger if operation_id is provided
    logger = get_logger() if operation_id else None

    # Defense in depth: refuse to exec a tool path outside the allowlist,
    # even if config.ini was edited out-of-band.
    try:
        validate_pg_tool_path(settings.pg_restore_path, 'pg_restore')
    except ValueError as e:
        error_msg = f"Refusing to run restore: {e}"
        if logger and operation_id:
            logger.log_message(operation_id, error_msg)
            logger.complete_operation(operation_id, status="failed", error=error_msg)
        yield {"type": "complete", "success": False, "message": error_msg}
        return

    if not os.path.exists(backup_file):
        error_msg = f"Backup file not found: {backup_file}"

        if logger and operation_id:
            logger.log_message(operation_id, error_msg)
            logger.complete_operation(operation_id, status="failed", error=error_msg)

        yield {
            "type": "complete",
            "success": False,
            "message": error_msg,
        }
        return

    # Handle table exclusion via TOC filtering
    toc_file_path = None
    if options.exclude_tables:
        try:
            toc = await _get_backup_toc(settings.pg_restore_path, backup_file)
            filtered_toc = _filter_toc_exclude_tables(toc, options.exclude_tables)
            # Write filtered TOC to a temp file
            toc_fd, toc_file_path = tempfile.mkstemp(suffix='.list', prefix='pg_restore_toc_')
            with os.fdopen(toc_fd, 'w') as f:
                f.write(filtered_toc)
            if logger and operation_id:
                logger.log_message(operation_id, f"Table exclusion active: filtering {len(options.exclude_tables)} pattern(s)")
        except Exception as e:
            error_msg = f"Failed to prepare table exclusion filter: {str(e)}"
            if logger and operation_id:
                logger.log_message(operation_id, error_msg)
                logger.complete_operation(operation_id, status="failed", error=error_msg)
            yield {
                "type": "complete",
                "success": False,
                "message": error_msg,
            }
            return

    cmd = [
        settings.pg_restore_path,
        '--host', host,
        '--port', str(port),
        '--username', username,
        '--no-password',
        '--dbname', database,
        '--verbose',
    ]

    # Section flags: skip when data_only or schema_only is set
    if options.data_only:
        cmd.append('--data-only')
    elif options.schema_only:
        cmd.append('--schema-only')
    else:
        cmd.extend([
            '--section=pre-data',
            '--section=data',
            '--section=post-data',
        ])

    if options.clean:
        cmd.append('--clean')
        cmd.append('--if-exists')
    if options.no_owner:
        cmd.append('--no-owner')
    if options.no_privileges:
        cmd.append('--no-privileges')
    if options.role:
        cmd.extend(['--role', options.role])
    if options.exit_on_error:
        cmd.append('--exit-on-error')
    if options.jobs and options.jobs > 1:
        cmd.extend(['--jobs', str(options.jobs)])
    if options.no_comments:
        cmd.append('--no-comments')
    if options.no_tablespaces:
        cmd.append('--no-tablespaces')
    if options.no_publications:
        cmd.append('--no-publications')
    if options.no_subscriptions:
        cmd.append('--no-subscriptions')
    if options.timescaledb:
        cmd.append('--disable-triggers')
    if options.exclude_schema and not options.schemas:
        for schema in options.exclude_schema:
            cmd.extend(['--exclude-schema', schema])

    # Schema mode: restore only specific schemas
    if options.schemas:
        for schema in options.schemas:
            cmd.extend(['--schema', schema])

    # Use filtered TOC file if table exclusion is active
    if toc_file_path:
        cmd.extend(['--use-list', toc_file_path])

    cmd.append(backup_file)

    # Use PGPASSWORD environment variable for authentication
    env = os.environ.copy()
    env['PGPASSWORD'] = password

    # Build progress message
    if options.schemas:
        schema_list = ', '.join(options.schemas)
        progress_msg = f"Starting restore of schemas [{schema_list}] to {database}..."
    else:
        progress_msg = f"Starting restore to {database}..."

    # Log command (without password)
    if logger and operation_id:
        cmd_display = ' '.join([c for c in cmd if c != password])
        logger.log_message(operation_id, f"Command: {cmd_display}")
        logger.log_message(operation_id, progress_msg)

    yield {
        "type": "progress",
        "message": progress_msg,
    }

    try:
        # TimescaleDB pre-restore: must run before pg_restore
        if options.timescaledb:
            pre_msg = "Running SELECT timescaledb_pre_restore()..."
            if logger and operation_id:
                logger.log_message(operation_id, pre_msg)
            yield {"type": "progress", "message": pre_msg}
            try:
                await asyncio.to_thread(
                    _call_timescaledb_procedure,
                    "timescaledb_pre_restore", database, host, port, username, password,
                )
                ok_msg = "timescaledb_pre_restore() completed"
                if logger and operation_id:
                    logger.log_message(operation_id, ok_msg)
                yield {"type": "output", "message": ok_msg}
            except Exception as e:
                error_msg = f"timescaledb_pre_restore() failed: {e}"
                if logger and operation_id:
                    logger.log_message(operation_id, error_msg)
                    logger.complete_operation(operation_id, status="failed", error=error_msg)
                yield {"type": "complete", "success": False, "message": error_msg}
                return

        process = await asyncio.create_subprocess_exec(
            *cmd,
            # stdout is unused (progress comes from --verbose on stderr); discard it
            # so a full pipe buffer can never deadlock the process.
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        # Track errors from pg_restore output
        error_count = 0
        warning_count = 0
        last_errors = []  # keep last N distinct error messages

        async def read_stream(stream, stream_type):
            nonlocal error_count, warning_count, last_errors
            while True:
                line = await stream.readline()
                if not line:
                    break
                decoded = line.decode().strip()
                if decoded:
                    # Count real errors vs clean-mode warnings
                    lower = decoded.lower()
                    if 'errore:' in lower or 'error:' in lower:
                        error_count += 1
                        # Extract short error reason
                        for marker in ['ERROR:  ', 'ERRORE:  ']:
                            idx = decoded.find(marker)
                            if idx != -1:
                                reason = decoded[idx + len(marker):].strip()
                                if reason and reason not in last_errors:
                                    last_errors.append(reason)
                                    if len(last_errors) > 5:
                                        last_errors.pop(0)
                                break
                    elif 'avvertimento:' in lower or 'warning:' in lower:
                        warning_count += 1

                    # Log to file
                    if logger and operation_id:
                        logger.log_message(operation_id, decoded)

                    yield {
                        "type": stream_type,
                        "message": decoded,
                    }

        cancelled = False
        async for item in read_stream(process.stderr, "output"):
            yield item
            if cancel_event and cancel_event.is_set():
                cancelled = True
                process.terminate()
                break

        await process.wait()

        # TimescaleDB post-restore: must run after pg_restore (unless cancelled)
        post_error_msg: Optional[str] = None
        if options.timescaledb and not cancelled:
            post_msg = "Running SELECT timescaledb_post_restore()..."
            if logger and operation_id:
                logger.log_message(operation_id, post_msg)
            yield {"type": "progress", "message": post_msg}
            try:
                await asyncio.to_thread(
                    _call_timescaledb_procedure,
                    "timescaledb_post_restore", database, host, port, username, password,
                )
                ok_msg = "timescaledb_post_restore() completed"
                if logger and operation_id:
                    logger.log_message(operation_id, ok_msg)
                yield {"type": "output", "message": ok_msg}
            except Exception as e:
                post_error_msg = f"timescaledb_post_restore() failed: {e}"
                if logger and operation_id:
                    logger.log_message(operation_id, post_error_msg)
                yield {"type": "error", "message": post_error_msg}

        if cancelled:
            cancel_msg = "Restore cancelled by user"
            if logger and operation_id:
                logger.log_message(operation_id, cancel_msg)
                logger.complete_operation(operation_id, status="cancelled", error=cancel_msg)
            yield {"type": "complete", "success": False, "message": cancel_msg}
        elif post_error_msg:
            # pg_restore finished but TimescaleDB post-restore failed: DB is in inconsistent state
            if logger and operation_id:
                logger.complete_operation(operation_id, status="failed", error=post_error_msg)
            yield {"type": "complete", "success": False, "message": post_error_msg}
        elif process.returncode == 0 and error_count == 0:
            success_msg = "Restore completed successfully"

            if logger and operation_id:
                logger.log_message(operation_id, success_msg)
                logger.complete_operation(operation_id, status="completed")

            yield {
                "type": "complete",
                "success": True,
                "message": success_msg,
            }
        elif error_count > 0:
            # Real errors detected in output
            error_summary = "; ".join(last_errors[:3])
            error_msg = f"Restore completed with {error_count} errors: {error_summary}"

            if logger and operation_id:
                logger.log_message(operation_id, error_msg)
                logger.complete_operation(operation_id, status="failed", error=error_msg)

            yield {
                "type": "complete",
                "success": False,
                "message": error_msg,
                "error_count": error_count,
                "warning_count": warning_count,
            }
        elif process.returncode == 1 and options.clean:
            # pg_restore returns 1 with --clean when DROP commands fail
            # (objects don't exist yet). Only warnings, no real errors.
            warning_msg = f"Restore completed successfully ({warning_count} clean-mode warnings)"

            if logger and operation_id:
                logger.log_message(operation_id, warning_msg)
                logger.complete_operation(operation_id, status="completed")

            yield {
                "type": "complete",
                "success": True,
                "message": warning_msg,
                "warning_count": warning_count,
            }
        else:
            error_msg = f"Restore failed (return code {process.returncode})"

            if logger and operation_id:
                logger.log_message(operation_id, error_msg)
                logger.complete_operation(operation_id, status="failed", error=error_msg)

            yield {
                "type": "complete",
                "success": False,
                "message": error_msg,
            }

    except FileNotFoundError:
        error_msg = f"pg_restore not found at {settings.pg_restore_path}"

        if logger and operation_id:
            logger.log_message(operation_id, error_msg)
            logger.complete_operation(operation_id, status="failed", error=error_msg)

        yield {
            "type": "complete",
            "success": False,
            "message": error_msg,
        }
    except Exception as e:
        error_msg = f"Restore failed: {str(e)}"

        if logger and operation_id:
            logger.log_message(operation_id, error_msg)
            logger.complete_operation(operation_id, status="failed", error=error_msg)

        yield {
            "type": "complete",
            "success": False,
            "message": error_msg,
        }
    finally:
        # Clean up temporary TOC file
        if toc_file_path and os.path.exists(toc_file_path):
            try:
                os.unlink(toc_file_path)
            except OSError:
                pass


async def run_transfer(
    source_database: str,
    source_host: str,
    source_port: int,
    source_username: str,
    source_password: str,
    dest_database: str,
    dest_host: str,
    dest_port: int,
    dest_username: str,
    dest_password: str,
    dest_role: Optional[str] = None,
    backup_options: Optional[BackupOptions] = None,
    restore_options: Optional[RestoreOptions] = None,
    operation_id: Optional[str] = None,
    cancel_event: Optional[asyncio.Event] = None,
) -> AsyncGenerator[Dict[str, Any], None]:
    """
    Run a backup followed by restore (transfer between databases).
    Uses direct PostgreSQL connections for both source and destination.

    Yields progress updates for both operations.
    """
    backup_file = str(get_backup_dir() / generate_backup_filename(source_database))

    # Get logger if operation_id is provided
    logger = get_logger() if operation_id else None

    # Build progress message
    if backup_options and backup_options.schemas:
        schema_list = ', '.join(backup_options.schemas)
        progress_msg = f"Starting transfer of schemas [{schema_list}]: {source_database} -> {dest_database}"
    else:
        progress_msg = f"Starting transfer: {source_database} -> {dest_database}"

    if logger and operation_id:
        logger.log_message(operation_id, progress_msg)
        logger.log_message(operation_id, "Phase 1: Backup")

    yield {
        "type": "progress",
        "message": progress_msg,
        "phase": "backup",
    }

    # Note: pass operation_id=None to sub-operations so they don't call
    # complete_operation themselves — the transfer manages the final status.
    backup_success = False
    backup_error = ""
    async for item in run_backup(
        database=source_database,
        host=source_host,
        port=source_port,
        username=source_username,
        password=source_password,
        output_file=backup_file,
        options=backup_options,
        operation_id=None,
        cancel_event=cancel_event,
    ):
        item["phase"] = "backup"
        # Log output to the transfer's log file
        if logger and operation_id and item.get("message"):
            logger.log_message(operation_id, item["message"])
        yield item
        if item.get("type") == "complete":
            backup_success = item.get("success", False)
            if not backup_success:
                backup_error = item.get("message", "")

    if not backup_success:
        is_cancelled = cancel_event and cancel_event.is_set()
        error_msg = f"Transfer cancelled by user" if is_cancelled else (
            f"Transfer failed in backup phase: {backup_error}" if backup_error else "Transfer failed: backup phase failed"
        )
        status = "cancelled" if is_cancelled else "failed"

        if logger and operation_id:
            logger.log_message(operation_id, error_msg)
            logger.complete_operation(operation_id, status=status, error=error_msg)

        yield {
            "type": "complete",
            "success": False,
            "message": error_msg,
            "phase": "transfer",
        }
        return

    restore_msg = "Backup complete, starting restore..."

    if logger and operation_id:
        logger.log_message(operation_id, restore_msg)
        logger.log_message(operation_id, "Phase 2: Restore")

    yield {
        "type": "progress",
        "message": restore_msg,
        "phase": "restore",
    }

    if restore_options is None:
        restore_options = RestoreOptions()
    if dest_role:
        restore_options.role = dest_role

    restore_success = False
    restore_error = ""
    async for item in run_restore(
        backup_file=backup_file,
        database=dest_database,
        host=dest_host,
        port=dest_port,
        username=dest_username,
        password=dest_password,
        options=restore_options,
        operation_id=None,
        cancel_event=cancel_event,
    ):
        item["phase"] = "restore"
        # Log output to the transfer's log file
        if logger and operation_id and item.get("message"):
            logger.log_message(operation_id, item["message"])
        yield item
        if item.get("type") == "complete":
            restore_success = item.get("success", False)
            if not restore_success:
                restore_error = item.get("message", "")

    is_cancelled = cancel_event and cancel_event.is_set()
    if is_cancelled:
        final_msg = "Transfer cancelled by user"
        final_status = "cancelled"
    elif restore_success:
        final_msg = "Transfer completed successfully"
        final_status = "completed"
    else:
        final_msg = f"Transfer failed in restore phase: {restore_error}" if restore_error else "Transfer completed with errors in restore phase"
        final_status = "failed"

    if logger and operation_id:
        logger.log_message(operation_id, final_msg)
        logger.complete_operation(operation_id, status=final_status,
                                  error=final_msg if final_status == "failed" else None)

    # The transfer backup is just an intermediate transport artifact. On success
    # the data now lives in the destination, so remove it to avoid disk growth.
    # On failure/cancel keep it so the operator can inspect or retry.
    removed_intermediate = False
    if final_status == "completed":
        try:
            if os.path.exists(backup_file):
                os.remove(backup_file)
                removed_intermediate = True
                if logger and operation_id:
                    logger.log_message(operation_id, f"Removed intermediate transfer file: {backup_file}")
        except OSError as e:
            if logger and operation_id:
                logger.log_message(operation_id, f"Could not remove intermediate transfer file: {e}")

    yield {
        "type": "complete",
        "success": restore_success,
        "message": final_msg,
        "phase": "transfer",
        "backup_file": None if removed_intermediate else backup_file,
    }


def delete_backup(filename: str) -> Dict[str, Any]:
    """Delete a backup file."""
    backup_dir = get_backup_dir()
    file_path = backup_dir / filename

    if not file_path.exists():
        return {
            "success": False,
            "error": "File not found",
        }

    # Use resolve() for robust path traversal protection
    try:
        file_path.resolve().relative_to(backup_dir.resolve())
    except ValueError:
        return {
            "success": False,
            "error": "Invalid file path",
        }

    try:
        file_path.unlink()
        return {
            "success": True,
            "message": f"Deleted {filename}",
        }
    except Exception as e:
        return {
            "success": False,
            "error": "Failed to delete file",
        }
