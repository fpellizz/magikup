"""
Database service module for PostgreSQL operations (Direct Connection).
Handles database listing, user listing, connection testing, and query execution.
"""

import json
import logging
import time
import psycopg2
from psycopg2 import sql
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


def get_connection(
    host: str = "localhost",
    port: int = 5432,
    database: str = "postgres",
    username: str = "postgres",
    password: str = "",
    read_only: bool = False,
) -> psycopg2.extensions.connection:
    """Create a database connection.

    When read_only=True the connection starts every transaction read-only
    (default_transaction_read_only), so any write statement is rejected by
    PostgreSQL itself — used for endpoints flagged read-only.
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
    )


def test_connection(
    host: str = "localhost",
    port: int = 5432,
    database: str = "postgres",
    username: str = "postgres",
    password: str = "",
) -> Dict[str, Any]:
    """Test database connection and return status."""
    try:
        conn = get_connection(host, port, database, username, password)
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
) -> Dict[str, Any]:
    """List all databases in the PostgreSQL instance."""
    logger.info(f"Listing databases on {host}:{port} as {username}")
    try:
        conn = get_connection(host, port, "postgres", username, password)
        cursor = conn.cursor()

        # Only list databases the current user has CONNECT privilege on
        # This avoids permission denied errors when calling pg_database_size()
        cursor.execute("""
            SELECT
                d.datname as name,
                pg_catalog.pg_get_userbyid(d.datdba) as owner,
                pg_catalog.pg_encoding_to_char(d.encoding) as encoding,
                pg_size_pretty(pg_database_size(d.datname)) as size
            FROM pg_catalog.pg_database d
            WHERE d.datname NOT IN ('template0', 'template1', 'rdsadmin')
            AND d.datistemplate = false
            AND has_database_privilege(current_user, d.datname, 'CONNECT')
            ORDER BY d.datname;
        """)

        databases = []
        for row in cursor.fetchall():
            databases.append({
                "name": row[0],
                "owner": row[1],
                "encoding": row[2],
                "size": row[3],
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
    database: str = "postgres",
) -> Dict[str, Any]:
    """List all users/roles in the PostgreSQL instance."""
    logger.info(f"Listing users on {host}:{port} as {username}")
    try:
        conn = get_connection(host, port, database, username, password)
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
) -> List[Dict[str, Any]]:
    """List all schemas in a database."""
    try:
        conn = get_connection(host, port, database, username, password)
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
) -> bool:
    """Check if a database exists."""
    try:
        conn = get_connection(host, port, "postgres", username, password)
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
) -> Optional[str]:
    """Get the size of a database."""
    try:
        conn = get_connection(host, port, "postgres", username, password)
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
# Query execution
# =============================================================================


def execute_query(
    query: str,
    host: str = "localhost",
    port: int = 5432,
    database: str = "postgres",
    username: str = "postgres",
    password: str = "",
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
        conn = get_connection(host, port, database, username, password, read_only=read_only)
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
    schema: str = "public",
) -> List[Dict[str, Any]]:
    """List all tables in a schema with basic info."""
    try:
        conn = get_connection(host, port, database, username, password)
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
    schema: str = "public",
    table: str = "",
) -> List[Dict[str, Any]]:
    """List all columns for a specific table."""
    try:
        conn = get_connection(host, port, database, username, password)
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
    schema: str = "public",
) -> List[Dict[str, Any]]:
    """List all views in a schema."""
    try:
        conn = get_connection(host, port, database, username, password)
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
    schema: str = "public",
) -> List[Dict[str, Any]]:
    """List all functions/procedures in a schema."""
    try:
        conn = get_connection(host, port, database, username, password)
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
    schema: str = "public",
    table: str = None,
) -> List[Dict[str, Any]]:
    """List indexes in a schema, optionally filtered by table."""
    try:
        conn = get_connection(host, port, database, username, password)
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
