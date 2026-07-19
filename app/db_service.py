"""
Database service module for PostgreSQL operations (Direct Connection).
Handles database listing, user listing, connection testing, and query execution.
"""

import json
import logging
import re
import time
import psycopg2
from psycopg2 import sql
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Identifier / privilege validation (security)
# ---------------------------------------------------------------------------
# Strict PostgreSQL identifier: starts with a letter or underscore, then
# letters/digits/underscore/$, max 63 bytes (NAMEDATALEN-1). We reject anything
# else BEFORE building SQL so no unquoted/injection-prone name is ever used, even
# though psycopg2.sql.Identifier already quotes/escapes.
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")

# Fixed allowlist of database-level privileges (these are NOT identifiers and
# must never be passed through sql.Identifier).
_DB_PRIVILEGES = {"CONNECT", "CREATE", "TEMP", "TEMPORARY", "ALL"}


def _validate_ident(name: str, what: str = "identifier") -> str:
    """Validate a PostgreSQL identifier (db/role/template name).

    Raises ValueError on anything that is not a plain identifier <=63 chars.
    Returns the name unchanged when valid so callers can inline the check.
    """
    if not isinstance(name, str) or not name:
        raise ValueError(f"Invalid {what}: must be a non-empty string")
    if len(name) > 63:
        raise ValueError(f"Invalid {what}: must be at most 63 characters")
    if not _IDENT_RE.match(name):
        raise ValueError(
            f"Invalid {what} '{name}': only letters, digits, underscore and $ "
            f"are allowed, and it must not start with a digit"
        )
    return name


def _validate_privileges(privileges: List[str]) -> List[str]:
    """Validate database privileges against the fixed allowlist.

    Returns the upper-cased privilege list. Raises ValueError on any unknown
    privilege (privileges are keywords, never identifiers)."""
    if not privileges:
        raise ValueError("At least one privilege is required")
    validated = []
    for priv in privileges:
        if not isinstance(priv, str):
            raise ValueError("Invalid privilege: must be a string")
        up = priv.strip().upper()
        if up not in _DB_PRIVILEGES:
            raise ValueError(
                f"Invalid privilege '{priv}': allowed values are "
                f"{', '.join(sorted(_DB_PRIVILEGES))}"
            )
        validated.append(up)
    return validated


def get_connection(
    host: str = "localhost",
    port: int = 5432,
    database: str = "postgres",
    username: str = "postgres",
    password: str = "",
    read_only: bool = False,
    sslmode: Optional[str] = None,
) -> psycopg2.extensions.connection:
    """Create a database connection.

    When read_only=True the connection starts every transaction read-only
    (default_transaction_read_only), so any write statement is rejected by
    PostgreSQL itself — used for endpoints flagged read-only.
    ``sslmode`` (libpq) is forwarded when set — needed for managed Postgres such
    as Supabase (require/verify-full).
    """
    options = "-c default_transaction_read_only=on" if read_only else ""
    return psycopg2.connect(
        host=host,
        port=port,
        dbname=database,
        user=username,
        password=password,
        connect_timeout=10,
        options=options,
        **({"sslmode": sslmode} if sslmode else {}),
    )


def test_connection(
    host: str = "localhost",
    port: int = 5432,
    database: str = "postgres",
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
) -> Dict[str, Any]:
    """Test database connection and return status."""
    try:
        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return {
            "success": True,
            "version": version,
        }
    except psycopg2.OperationalError as e:
        return {
            "success": False,
            "error": str(e),
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}",
        }


def list_databases(
    host: str = "localhost",
    port: int = 5432,
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
) -> Dict[str, Any]:
    """List all databases in the PostgreSQL instance."""
    logger.info(f"Listing databases on {host}:{port} as {username}")
    try:
        conn = get_connection(host, port, "postgres", username, password, sslmode=sslmode)
        cursor = conn.cursor()

        # List ALL non-template databases (v4.2.0): the CONNECT filter is
        # intentionally removed so users can see every database on the server.
        # Size is computed only when the current user CAN connect, otherwise
        # pg_database_size() would raise "permission denied" — so it is wrapped
        # in a CASE guarded by has_database_privilege(...,'CONNECT') and NULL
        # is returned for databases the user cannot connect to. A boolean
        # can_connect is added to each row for the UI.
        cursor.execute("""
            SELECT
                d.datname as name,
                pg_catalog.pg_get_userbyid(d.datdba) as owner,
                pg_catalog.pg_encoding_to_char(d.encoding) as encoding,
                CASE
                    WHEN has_database_privilege(current_user, d.datname, 'CONNECT')
                    THEN pg_size_pretty(pg_database_size(d.datname))
                    ELSE NULL
                END as size,
                has_database_privilege(current_user, d.datname, 'CONNECT') as can_connect
            FROM pg_catalog.pg_database d
            WHERE d.datname NOT IN ('template0', 'template1', 'rdsadmin')
            AND d.datistemplate = false
            ORDER BY d.datname;
        """)

        databases = []
        for row in cursor.fetchall():
            databases.append({
                "name": row[0],
                "owner": row[1],
                "encoding": row[2],
                "size": row[3],
                "can_connect": row[4],
            })

        cursor.close()
        conn.close()
        logger.info(f"Found {len(databases)} databases on {host}:{port}")
        return {
            "success": True,
            "databases": databases,
        }
    except psycopg2.OperationalError as e:
        logger.error(f"Connection error listing databases on {host}:{port}: {e}")
        return {
            "success": False,
            "error": f"Connection failed: {str(e)}",
            "databases": [],
        }
    except Exception as e:
        logger.exception(f"Unexpected error listing databases on {host}:{port}: {e}")
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}",
            "databases": [],
        }


def list_users(
    host: str = "localhost",
    port: int = 5432,
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    database: str = "postgres",
) -> Dict[str, Any]:
    """List all users/roles in the PostgreSQL instance."""
    logger.info(f"Listing users on {host}:{port} as {username}")
    try:
        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                r.rolname as name,
                r.rolsuper as is_superuser,
                r.rolinherit as inherit,
                r.rolcreaterole as can_create_role,
                r.rolcreatedb as can_create_db,
                r.rolcanlogin as can_login
            FROM pg_catalog.pg_roles r
            WHERE r.rolname NOT LIKE 'pg_%'
            AND r.rolname NOT IN ('rdsadmin', 'rds_superuser', 'rds_replication', 'rds_password')
            ORDER BY r.rolname;
        """)

        users = []
        for row in cursor.fetchall():
            users.append({
                "name": row[0],
                "is_superuser": row[1],
                "inherit": row[2],
                "can_create_role": row[3],
                "can_create_db": row[4],
                "can_login": row[5],
            })

        cursor.close()
        conn.close()
        logger.info(f"Found {len(users)} users on {host}:{port}")
        return {
            "success": True,
            "users": users,
        }
    except psycopg2.OperationalError as e:
        logger.error(f"Connection error listing users on {host}:{port}: {e}")
        return {
            "success": False,
            "error": f"Connection failed: {str(e)}",
            "users": [],
        }
    except Exception as e:
        logger.exception(f"Unexpected error listing users on {host}:{port}: {e}")
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}",
            "users": [],
        }


def list_schemas(
    host: str = "localhost",
    port: int = 5432,
    database: str = "postgres",
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List all schemas in a database."""
    try:
        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                n.nspname as name,
                pg_catalog.pg_get_userbyid(n.nspowner) as owner
            FROM pg_catalog.pg_namespace n
            WHERE n.nspname NOT LIKE 'pg_%'
            AND n.nspname != 'information_schema'
            ORDER BY n.nspname;
        """)

        schemas = []
        for row in cursor.fetchall():
            schemas.append({
                "name": row[0],
                "owner": row[1],
            })

        cursor.close()
        conn.close()
        return schemas
    except Exception as e:
        return []


def database_exists(
    database: str,
    host: str = "localhost",
    port: int = 5432,
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
) -> bool:
    """Check if a database exists."""
    try:
        conn = get_connection(host, port, "postgres", username, password, sslmode=sslmode)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s",
            (database,)
        )
        result = cursor.fetchone() is not None

        cursor.close()
        conn.close()
        return result
    except Exception:
        return False


def get_database_size(
    database: str,
    host: str = "localhost",
    port: int = 5432,
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
) -> Optional[str]:
    """Get the size of a database."""
    try:
        conn = get_connection(host, port, "postgres", username, password, sslmode=sslmode)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT pg_size_pretty(pg_database_size(%s))",
            (database,)
        )
        result = cursor.fetchone()

        cursor.close()
        conn.close()
        return result[0] if result else None
    except Exception:
        return None


# =============================================================================
# DB / role management (v4.2.0)
# =============================================================================
# All functions connect via get_connection to the given `database` (the DB used
# to ISSUE the statement, default 'postgres'). The connected role's own
# privileges are the ultimate authority: if it lacks CREATEDB/CREATEROLE the DB
# rejects the statement and we surface the message. Identifier validation is
# done up-front so callers can also validate BEFORE opening a connection.
# Passwords are never logged.


def get_role_capabilities(
    host: str = "localhost",
    port: int = 5432,
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    database: str = "postgres",
) -> Dict[str, Any]:
    """Return the capabilities of the currently connected role.

    {"current_user", "is_superuser", "can_create_db", "can_create_role"}.
    """
    logger.info(f"Getting role capabilities on {host}:{port} as {username}")
    conn = None
    try:
        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT current_user, rolsuper, rolcreatedb, rolcreaterole
            FROM pg_catalog.pg_roles
            WHERE rolname = current_user;
        """)
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if not row:
            return {
                "success": False,
                "error": "Could not determine role capabilities",
            }
        return {
            "success": True,
            "current_user": row[0],
            "is_superuser": bool(row[1]),
            "can_create_db": bool(row[2]),
            "can_create_role": bool(row[3]),
        }
    except psycopg2.OperationalError as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        logger.error(f"Connection error getting capabilities on {host}:{port}: {e}")
        return {"success": False, "error": f"Connection failed: {str(e)}"}
    except Exception as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        logger.exception(f"Unexpected error getting capabilities on {host}:{port}: {e}")
        return {"success": False, "error": f"Unexpected error: {str(e)}"}


def list_roles(
    host: str = "localhost",
    port: int = 5432,
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    database: str = "postgres",
) -> Dict[str, Any]:
    """List roles (excluding internal pg_* roles) with their attributes."""
    logger.info(f"Listing roles on {host}:{port} as {username}")
    conn = None
    try:
        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                r.rolname,
                r.rolsuper,
                r.rolcreatedb,
                r.rolcreaterole,
                r.rolcanlogin,
                r.rolvaliduntil
            FROM pg_catalog.pg_roles r
            WHERE r.rolname NOT LIKE 'pg\\_%'
            ORDER BY r.rolname;
        """)
        roles = []
        for row in cursor.fetchall():
            roles.append({
                "name": row[0],
                "is_superuser": bool(row[1]),
                "can_create_db": bool(row[2]),
                "can_create_role": bool(row[3]),
                "can_login": bool(row[4]),
                "valid_until": row[5].isoformat() if row[5] else None,
            })
        cursor.close()
        conn.close()
        logger.info(f"Found {len(roles)} roles on {host}:{port}")
        return {"success": True, "roles": roles}
    except psycopg2.OperationalError as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        logger.error(f"Connection error listing roles on {host}:{port}: {e}")
        return {"success": False, "error": f"Connection failed: {str(e)}", "roles": []}
    except Exception as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        logger.exception(f"Unexpected error listing roles on {host}:{port}: {e}")
        return {"success": False, "error": f"Unexpected error: {str(e)}", "roles": []}


def create_database(
    host: str = "localhost",
    port: int = 5432,
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    database: str = "postgres",
    name: str = "",
    owner: Optional[str] = None,
    encoding: Optional[str] = None,
    template: Optional[str] = None,
) -> Dict[str, Any]:
    """CREATE DATABASE. Runs on a dedicated autocommit connection because
    CREATE DATABASE cannot run inside a transaction block."""
    # Validate identifiers BEFORE opening any connection.
    _validate_ident(name, "database name")
    if owner:
        _validate_ident(owner, "owner")
    if template:
        _validate_ident(template, "template")

    logger.info(f"Creating database '{name}' on {host}:{port} as {username}")
    conn = None
    try:
        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        conn.autocommit = True  # CREATE DATABASE cannot run in a transaction
        cursor = conn.cursor()

        stmt = sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name))
        opts = []
        if owner:
            opts.append(sql.SQL("OWNER {}").format(sql.Identifier(owner)))
        if template:
            opts.append(sql.SQL("TEMPLATE {}").format(sql.Identifier(template)))
        if encoding:
            opts.append(sql.SQL("ENCODING {}").format(sql.Literal(encoding)))
        if opts:
            stmt = sql.SQL("{} WITH {}").format(stmt, sql.SQL(" ").join(opts))

        cursor.execute(stmt)
        cursor.close()
        conn.close()
        return {"success": True, "message": f"Database '{name}' created"}
    except psycopg2.Error as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        return {"success": False, "error": str(e).strip()}
    except Exception as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        logger.exception(f"Unexpected error creating database on {host}:{port}: {e}")
        return {"success": False, "error": f"Unexpected error: {str(e)}"}


def create_role(
    host: str = "localhost",
    port: int = 5432,
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    database: str = "postgres",
    name: str = "",
    role_password: str = "",
    login: bool = True,
    createdb: bool = False,
    createrole: bool = False,
    superuser: bool = False,
    valid_until: Optional[str] = None,
) -> Dict[str, Any]:
    """CREATE ROLE with attribute keywords from a fixed allowlist and the
    password/VALID UNTIL passed as SQL literals. `name` is validated up-front."""
    _validate_ident(name, "role name")

    logger.info(f"Creating role '{name}' on {host}:{port} as {username}")  # never log password
    conn = None
    try:
        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()

        # Attribute keywords come from a fixed allowlist (never user text).
        flags = [
            sql.SQL("LOGIN" if login else "NOLOGIN"),
            sql.SQL("CREATEDB" if createdb else "NOCREATEDB"),
            sql.SQL("CREATEROLE" if createrole else "NOCREATEROLE"),
            sql.SQL("SUPERUSER" if superuser else "NOSUPERUSER"),
        ]
        parts = [sql.SQL("CREATE ROLE {} WITH").format(sql.Identifier(name)),
                 sql.SQL(" ").join(flags)]
        if role_password:
            parts.append(sql.SQL("PASSWORD {}").format(sql.Literal(role_password)))
        if valid_until:
            parts.append(sql.SQL("VALID UNTIL {}").format(sql.Literal(valid_until)))

        cursor.execute(sql.SQL(" ").join(parts))
        conn.commit()
        cursor.close()
        conn.close()
        return {"success": True, "message": f"Role '{name}' created"}
    except psycopg2.Error as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        return {"success": False, "error": str(e).strip()}
    except Exception as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        logger.exception(f"Unexpected error creating role on {host}:{port}: {e}")
        return {"success": False, "error": f"Unexpected error: {str(e)}"}


def alter_role(
    host: str = "localhost",
    port: int = 5432,
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    database: str = "postgres",
    name: str = "",
    login: Optional[bool] = None,
    createdb: Optional[bool] = None,
    createrole: Optional[bool] = None,
    superuser: Optional[bool] = None,
    role_password: Optional[str] = None,
    valid_until: Optional[str] = None,
) -> Dict[str, Any]:
    """ALTER ROLE. Only the attributes explicitly provided (not None) are
    included. `name` is validated up-front."""
    _validate_ident(name, "role name")

    logger.info(f"Altering role '{name}' on {host}:{port} as {username}")  # never log password
    conn = None
    try:
        parts = []
        if login is not None:
            parts.append(sql.SQL("LOGIN" if login else "NOLOGIN"))
        if createdb is not None:
            parts.append(sql.SQL("CREATEDB" if createdb else "NOCREATEDB"))
        if createrole is not None:
            parts.append(sql.SQL("CREATEROLE" if createrole else "NOCREATEROLE"))
        if superuser is not None:
            parts.append(sql.SQL("SUPERUSER" if superuser else "NOSUPERUSER"))
        if role_password is not None:
            parts.append(sql.SQL("PASSWORD {}").format(sql.Literal(role_password)))
        if valid_until is not None:
            parts.append(sql.SQL("VALID UNTIL {}").format(sql.Literal(valid_until)))

        if not parts:
            return {"success": False, "error": "No attributes to change"}

        stmt = sql.SQL("ALTER ROLE {} WITH {}").format(
            sql.Identifier(name), sql.SQL(" ").join(parts)
        )

        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()
        cursor.execute(stmt)
        conn.commit()
        cursor.close()
        conn.close()
        return {"success": True, "message": f"Role '{name}' updated"}
    except psycopg2.Error as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        return {"success": False, "error": str(e).strip()}
    except Exception as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        logger.exception(f"Unexpected error altering role on {host}:{port}: {e}")
        return {"success": False, "error": f"Unexpected error: {str(e)}"}


def grant_role_membership(
    host: str = "localhost",
    port: int = 5432,
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    database: str = "postgres",
    role: str = "",
    member: str = "",
    grant: bool = True,
) -> Dict[str, Any]:
    """GRANT <role> TO <member> / REVOKE <role> FROM <member>."""
    _validate_ident(role, "role")
    _validate_ident(member, "member")

    logger.info(
        f"{'Granting' if grant else 'Revoking'} membership of '{role}' "
        f"{'to' if grant else 'from'} '{member}' on {host}:{port} as {username}"
    )
    conn = None
    try:
        if grant:
            stmt = sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(role), sql.Identifier(member)
            )
        else:
            stmt = sql.SQL("REVOKE {} FROM {}").format(
                sql.Identifier(role), sql.Identifier(member)
            )

        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()
        cursor.execute(stmt)
        conn.commit()
        cursor.close()
        conn.close()
        verb = "granted to" if grant else "revoked from"
        return {"success": True, "message": f"Role '{role}' {verb} '{member}'"}
    except psycopg2.Error as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        return {"success": False, "error": str(e).strip()}
    except Exception as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        logger.exception(f"Unexpected error changing membership on {host}:{port}: {e}")
        return {"success": False, "error": f"Unexpected error: {str(e)}"}


def grant_database_privileges(
    host: str = "localhost",
    port: int = 5432,
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    database: str = "postgres",
    target_database: str = "",
    role: str = "",
    privileges: Optional[List[str]] = None,
    grant: bool = True,
) -> Dict[str, Any]:
    """GRANT/REVOKE database-level privileges (from the fixed allowlist) on
    target_database to/from role. `database` is the DB used to issue the
    statement; `target_database` is the DB the privileges apply to."""
    _validate_ident(target_database, "target database")
    _validate_ident(role, "role")
    validated_privs = _validate_privileges(privileges or [])

    logger.info(
        f"{'Granting' if grant else 'Revoking'} {','.join(validated_privs)} on "
        f"database '{target_database}' {'to' if grant else 'from'} '{role}' "
        f"on {host}:{port} as {username}"
    )
    conn = None
    try:
        # Privileges are keywords from the allowlist, joined as raw SQL — never
        # identifiers, never user text.
        priv_sql = sql.SQL(", ").join(sql.SQL(p) for p in validated_privs)
        if grant:
            stmt = sql.SQL("GRANT {} ON DATABASE {} TO {}").format(
                priv_sql, sql.Identifier(target_database), sql.Identifier(role)
            )
        else:
            stmt = sql.SQL("REVOKE {} ON DATABASE {} FROM {}").format(
                priv_sql, sql.Identifier(target_database), sql.Identifier(role)
            )

        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()
        cursor.execute(stmt)
        conn.commit()
        cursor.close()
        conn.close()
        verb = "granted to" if grant else "revoked from"
        return {
            "success": True,
            "message": f"{', '.join(validated_privs)} on '{target_database}' {verb} '{role}'",
        }
    except psycopg2.Error as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        return {"success": False, "error": str(e).strip()}
    except Exception as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        logger.exception(f"Unexpected error changing db privileges on {host}:{port}: {e}")
        return {"success": False, "error": f"Unexpected error: {str(e)}"}


# =============================================================================
# Query execution
# =============================================================================


def execute_query(
    query: str,
    host: str = "localhost",
    port: int = 5432,
    database: str = "postgres",
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    timeout_seconds: int = 30,
    row_limit: int = 1000,
    role: str = None,
    autocommit: bool = False,
    read_only: bool = False,
) -> Dict[str, Any]:
    """Execute an arbitrary SQL query and return results.

    If read_only is True, the connection rejects any write statement at the
    PostgreSQL level (used for endpoints flagged read-only)."""
    conn = None
    try:
        conn = get_connection(host, port, database, username, password, read_only=read_only, sslmode=sslmode)
        conn.autocommit = autocommit
        cursor = conn.cursor()

        if role:
            cursor.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))

        cursor.execute(f"SET statement_timeout = '{timeout_seconds * 1000}'")

        start_time = time.time()
        cursor.execute(query)
        execution_time_ms = round((time.time() - start_time) * 1000, 2)

        result_sets = []

        if cursor.description:
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchmany(row_limit)
            total_rows = cursor.rowcount

            serialized_rows = []
            for row in rows:
                serialized_row = []
                for val in row:
                    if val is None:
                        serialized_row.append(None)
                    elif isinstance(val, (bytes, bytearray, memoryview)):
                        serialized_row.append(f"<binary {len(val)} bytes>")
                    elif isinstance(val, (dict, list)):
                        serialized_row.append(json.dumps(val, default=str))
                    else:
                        serialized_row.append(str(val))
                serialized_rows.append(serialized_row)

            truncated = len(rows) >= row_limit and total_rows != row_limit

            result_sets.append({
                "columns": columns,
                "rows": serialized_rows,
                "row_count": len(serialized_rows),
                "total_rows": total_rows if total_rows >= 0 else len(serialized_rows),
                "truncated": truncated,
            })
        else:
            result_sets.append({
                "columns": [],
                "rows": [],
                "row_count": 0,
                "total_rows": 0,
                "affected_rows": cursor.rowcount,
                "truncated": False,
            })

        if not autocommit:
            conn.commit()
        cursor.close()
        conn.close()

        return {
            "success": True,
            "result_sets": result_sets,
            "execution_time_ms": execution_time_ms,
        }

    except psycopg2.extensions.QueryCanceledError:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        return {
            "success": False,
            "error": f"Query timed out after {timeout_seconds} seconds",
            "result_sets": [],
            "execution_time_ms": timeout_seconds * 1000,
        }
    except psycopg2.Error as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        return {
            "success": False,
            "error": str(e).strip(),
            "result_sets": [],
            "execution_time_ms": 0,
        }
    except Exception as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        logger.exception(f"Unexpected error executing query on {host}:{port}/{database}: {e}")
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}",
            "result_sets": [],
            "execution_time_ms": 0,
        }


# =============================================================================
# Object browser functions
# =============================================================================


def list_tables(
    host: str = "localhost",
    port: int = 5432,
    database: str = "postgres",
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    schema: str = "public",
) -> List[Dict[str, Any]]:
    """List all tables in a schema with basic info."""
    try:
        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                t.table_name,
                pg_catalog.pg_get_userbyid(c.relowner) as owner,
                pg_size_pretty(pg_total_relation_size(c.oid)) as size,
                c.reltuples::bigint as estimated_rows
            FROM information_schema.tables t
            JOIN pg_catalog.pg_class c ON c.relname = t.table_name
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                AND n.nspname = t.table_schema
            WHERE t.table_schema = %s
            AND t.table_type = 'BASE TABLE'
            ORDER BY t.table_name;
        """, (schema,))

        tables = []
        for row in cursor.fetchall():
            tables.append({
                "name": row[0],
                "owner": row[1],
                "size": row[2],
                "estimated_rows": row[3],
            })
        cursor.close()
        conn.close()
        return tables
    except Exception as e:
        logger.error(f"Error listing tables in {schema}: {e}")
        return []


def list_table_columns(
    host: str = "localhost",
    port: int = 5432,
    database: str = "postgres",
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    schema: str = "public",
    table: str = "",
) -> List[Dict[str, Any]]:
    """List all columns for a specific table."""
    try:
        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                c.column_name,
                c.data_type,
                c.is_nullable,
                c.column_default,
                c.character_maximum_length,
                c.ordinal_position
            FROM information_schema.columns c
            WHERE c.table_schema = %s
            AND c.table_name = %s
            ORDER BY c.ordinal_position;
        """, (schema, table))

        columns = []
        for row in cursor.fetchall():
            columns.append({
                "name": row[0],
                "data_type": row[1],
                "nullable": row[2] == "YES",
                "default": row[3],
                "max_length": row[4],
                "position": row[5],
            })
        cursor.close()
        conn.close()
        return columns
    except Exception as e:
        logger.error(f"Error listing columns for {schema}.{table}: {e}")
        return []


def list_views(
    host: str = "localhost",
    port: int = 5432,
    database: str = "postgres",
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    schema: str = "public",
) -> List[Dict[str, Any]]:
    """List all views in a schema."""
    try:
        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                v.table_name,
                pg_catalog.pg_get_userbyid(c.relowner) as owner,
                CASE WHEN v.is_updatable = 'YES' THEN true ELSE false END as is_updatable
            FROM information_schema.views v
            JOIN pg_catalog.pg_class c ON c.relname = v.table_name
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                AND n.nspname = v.table_schema
            WHERE v.table_schema = %s
            ORDER BY v.table_name;
        """, (schema,))

        views = []
        for row in cursor.fetchall():
            views.append({
                "name": row[0],
                "owner": row[1],
                "is_updatable": row[2],
            })
        cursor.close()
        conn.close()
        return views
    except Exception as e:
        logger.error(f"Error listing views in {schema}: {e}")
        return []


def list_functions(
    host: str = "localhost",
    port: int = 5432,
    database: str = "postgres",
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    schema: str = "public",
) -> List[Dict[str, Any]]:
    """List all functions/procedures in a schema."""
    try:
        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                p.proname as name,
                pg_catalog.pg_get_userbyid(p.proowner) as owner,
                pg_catalog.pg_get_function_result(p.oid) as return_type,
                pg_catalog.pg_get_function_arguments(p.oid) as arguments,
                CASE p.prokind
                    WHEN 'f' THEN 'function'
                    WHEN 'p' THEN 'procedure'
                    WHEN 'a' THEN 'aggregate'
                    WHEN 'w' THEN 'window'
                END as kind
            FROM pg_catalog.pg_proc p
            JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = %s
            AND p.prokind IN ('f', 'p')
            ORDER BY p.proname;
        """, (schema,))

        functions = []
        for row in cursor.fetchall():
            functions.append({
                "name": row[0],
                "owner": row[1],
                "return_type": row[2],
                "arguments": row[3],
                "kind": row[4],
            })
        cursor.close()
        conn.close()
        return functions
    except Exception as e:
        logger.error(f"Error listing functions in {schema}: {e}")
        return []


def list_indexes(
    host: str = "localhost",
    port: int = 5432,
    database: str = "postgres",
    username: str = "postgres",
    password: str = "",
    sslmode: Optional[str] = None,
    schema: str = "public",
    table: str = None,
) -> List[Dict[str, Any]]:
    """List indexes in a schema, optionally filtered by table."""
    try:
        conn = get_connection(host, port, database, username, password, sslmode=sslmode)
        cursor = conn.cursor()

        q = """
            SELECT
                i.indexname as name,
                i.tablename as table_name,
                pg_size_pretty(pg_relation_size(c.oid)) as size,
                ix.indisunique as is_unique,
                ix.indisprimary as is_primary,
                i.indexdef as definition
            FROM pg_indexes i
            JOIN pg_catalog.pg_class c ON c.relname = i.indexname
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                AND n.nspname = i.schemaname
            JOIN pg_catalog.pg_index ix ON ix.indexrelid = c.oid
            WHERE i.schemaname = %s
        """
        params = [schema]

        if table:
            q += " AND i.tablename = %s"
            params.append(table)

        q += " ORDER BY i.tablename, i.indexname;"

        cursor.execute(q, params)

        indexes = []
        for row in cursor.fetchall():
            indexes.append({
                "name": row[0],
                "table_name": row[1],
                "size": row[2],
                "is_unique": row[3],
                "is_primary": row[4],
                "definition": row[5],
            })
        cursor.close()
        conn.close()
        return indexes
    except Exception as e:
        logger.error(f"Error listing indexes in {schema}: {e}")
        return []
