"""
Backup privilege preflight.

Before a backup runs, checks whether the connected role can actually lock and
read every object pg_dump is going to touch, so a missing GRANT is reported up
front (with a copyable fix script) instead of failing halfway through a dump.

The check mirrors pg_dump's object selection (schema filter, --exclude-table /
--exclude-table-data patterns, extension members, owned sequences, inheritance
lock recursion) with a handful of catalog queries — no per-object round trips —
so it stays fast on databases with tens of thousands of relations.

Privilege facts encoded here (PostgreSQL 12..17 servers, pg_dump 14..17):
- pg_dump runs ``LOCK TABLE ... IN ACCESS SHARE MODE`` (without ONLY) on every
  dumped plain or partitioned table, in every mode (schema-only too). LOCK
  recurses into *all* inheritance/partition descendants — whatever their
  relkind (foreign partitions too), schema or dump selection. Only PG 12
  checks the privilege on each descendant (LockTableRecurse ->
  LockTableAclCheck); from PG 13 the recursion locks by OID without any ACL
  check, so an unreadable child only fails when it is dumped itself.
  ACCESS SHARE is allowed by: SELECT (PG <= 15); SELECT, INSERT, UPDATE, DELETE
  or TRUNCATE (PG 16); the same plus MAINTAIN (PG 17+). Owners and superusers
  always pass. Resolving the qualified name needs USAGE on the schema (the
  recursion works by OID and does not).
- Extension member tables are not locked by current pg_dump releases (ACL
  component only, since 16.2/15.6/14.11/13.14/12.18 — commit "Don't try to
  dump RLS policies or security labels for extension objects"). Older minor
  releases also dumped their POLICY component without --schema and locked
  them; --exclude-table / --exclude-schema cannot remove them (extension
  membership overrides every selection switch), so they are reported as
  non-blocking warnings.
- Table data (COPY with an explicit column list) needs SELECT on the table or
  on every copied column; pg_dump sets row_security=off, so a table with RLS
  enabled errors out unless the role is superuser / BYPASSRLS, or is the owner
  (has the owner's privileges) and the table is not FORCE RLS.
- Sequence data is read with ``SELECT last_value, is_called FROM seq``: needs
  SELECT on the sequence (USAGE is not enough). Owned/identity sequences follow
  their table, so ``--exclude-table`` on the sequence does not drop them; their
  data is skipped with ``--exclude-table-data``. Extension configuration tables
  *and sequences* get their data dumped; with --schema-only the config
  sequences are still read.
- Large objects are read with lo_open(INV_READ): SELECT on the LO (or owner),
  unless the server runs with lo_compat_privileges=on.
  has_largeobject_privilege() only exists from PG 18, so older servers are
  checked through pg_largeobject_metadata.lomacl.

The fix SQL is only ever shown to the user — MagikUp never executes it. Every
identifier in it is emitted through ``_qi``, which never produces a line break
or other control/format character (those are written as U&"" escapes), so a
crafted object name cannot break out of a quoted identifier or a ``--`` comment.
"""

import logging
import re
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from app import db_service

logger = logging.getLogger(__name__)

ISSUE_KINDS = (
    "database_connect",
    "schema_usage",
    "table_lock",
    "table_select",
    "sequence_select",
    "rls",
    "large_object",
)
_KIND_ORDER = {k: i for i, k in enumerate(ISSUE_KINDS)}

STATEMENT_TIMEOUT_MS = 60000
_FIRST_USER_OID = 16384          # FirstNormalObjectId: built-in extensions (plpgsql) sit below
_GRANT_CHUNK = 10                # object names per GRANT statement in fix_sql
_LO_SAMPLE = 20                  # large objects listed individually in fix_sql
_FIX_LIST_PREVIEW = 20           # tables listed in fix_sql comments (RLS)
_BLOCKED_PREVIEW = 5             # unlockable descendants named in a table_lock message
# Above this many exact-match exclusion patterns the partial backup is refused:
# pg_dump runs one catalog query per pattern and every pattern is an argv entry.
MAX_EXCLUSION_PATTERNS = 500

_PG13 = 130000
_PG14 = 140000
_PG16 = 160000
_PG17 = 170000
_PG18 = 180000

_SQLSTATE_INSUFFICIENT_PRIVILEGE = "42501"


class _PatternError(ValueError):
    """A user pattern pg_dump itself would reject."""


# ---------------------------------------------------------------------------
# Quoting / sanitising helpers
# ---------------------------------------------------------------------------

# Control (Cc: includes \r \n \x85), format (Cf: bidi overrides, ZWJ, ...) and
# line/paragraph separators (Zl/Zp): never emitted verbatim into fix SQL.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})


def _unsafe_char(ch: str) -> bool:
    return unicodedata.category(ch) in _UNSAFE_CATEGORIES


def _clean(text: Any) -> str:
    """Single-line, printable rendering of arbitrary text (for comments/logs)."""
    return "".join("?" if _unsafe_char(ch) else ch for ch in str(text))


def _qi(name: str) -> str:
    """Quote an SQL identifier for the fix script.

    Always quoted with inner double quotes doubled. If the name contains any
    control/format/separator character it is written as a Unicode-escaped
    identifier (``U&"a\\000Ab"``), so the result is always a single printable
    line and safe inside ``--`` comments too. U&"" identifiers do not depend on
    standard_conforming_strings and exist on every supported server.
    """
    s = str(name)
    if not any(_unsafe_char(ch) for ch in s):
        return '"' + s.replace('"', '""') + '"'
    out: List[str] = []
    for ch in s:
        if ch == '"':
            out.append('""')
        elif ch == "\\":
            out.append("\\\\")
        elif _unsafe_char(ch):
            cp = ord(ch)
            out.append("\\%04X" % cp if cp <= 0xFFFF else "\\+%06X" % cp)
        else:
            out.append(ch)
    return 'U&"' + "".join(out) + '"'


def _qn(schema: str, name: str) -> str:
    return f"{_qi(schema)}.{_qi(name)}"


def _pq(name: str) -> str:
    """pg_dump pattern quoting (argv, not SQL): literal inside double quotes."""
    return '"' + str(name).replace('"', '""') + '"'


def quote_dump_pattern(schema: str, name: Optional[str] = None) -> str:
    """Exact-match pg_dump pattern for a schema or a schema-qualified relation.

    Inside double quotes pg_dump treats ``* ? .`` and regex metacharacters
    literally and keeps the case, so the result matches exactly one object.
    """
    if name is None:
        return _pq(schema)
    return f"{_pq(schema)}.{_pq(name)}"


# ---------------------------------------------------------------------------
# pg_dump pattern emulation
# ---------------------------------------------------------------------------

def _pattern_split(pattern: str) -> List[Tuple[str, str]]:
    """Split a pg_dump name pattern into (regex, literal) per dotted part.

    Mirrors patternToSQLRegex: outside double quotes letters fold to lower
    case, ``*`` -> ``.*``, ``?`` -> ``.``, ``.`` separates parts; inside
    quotes everything is literal and ``""`` is a literal quote. The literal
    form (wildcards kept as typed) is what pg_dump compares the database
    part of a qualified pattern against.
    """
    rx: List[List[str]] = [[]]
    lit: List[List[str]] = [[]]
    inquotes = False
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == '"':
            if inquotes and i + 1 < n and pattern[i + 1] == '"':
                rx[-1].append(re.escape('"'))
                lit[-1].append('"')
                i += 2
                continue
            inquotes = not inquotes
        elif inquotes:
            rx[-1].append(re.escape(ch))
            lit[-1].append(ch)
        elif ch == ".":
            rx.append([])
            lit.append([])
        elif ch == "*":
            rx[-1].append(".*")
            lit[-1].append(ch)
        elif ch == "?":
            rx[-1].append(".")
            lit[-1].append(ch)
        else:
            rx[-1].append(re.escape(ch.lower()))
            lit[-1].append(ch.lower())
        i += 1
    return [("".join(r), "".join(l)) for r, l in zip(rx, lit)]


def _compile(regex: str) -> Optional["re.Pattern[str]"]:
    # An empty part imposes no condition (as in processSQLNamePattern).
    return re.compile(regex, re.DOTALL) if regex else None


def _full(rx: Optional["re.Pattern[str]"], value: str) -> bool:
    return rx is None or rx.fullmatch(value) is not None


def _check_db_part(literal: str, database: str, pattern: str) -> None:
    # pg_dump 14+ prohibit_crossdb_refs(): strcmp against the current database.
    if literal != database:
        raise _PatternError(
            f"cross-database references are not implemented: {_clean(pattern)}")


class _SchemaPattern:
    """A --schema / --exclude-schema pattern: ``schema`` or ``db.schema``.

    Like pg_dump 14+, more than one dot or a database part that is not the
    current database is an error (raised as _PatternError).
    """

    def __init__(self, pattern: str, database: str):
        parts = _pattern_split(pattern)
        if len(parts) > 2:
            raise _PatternError(
                f"improper qualified name (too many dotted names): {_clean(pattern)}")
        if len(parts) == 2:
            _check_db_part(parts[0][1], database, pattern)
            parts = parts[1:]
        self.rx = _compile(parts[0][0])

    def matches(self, nspname: str) -> bool:
        return _full(self.rx, nspname)


class _RelPattern:
    """A --exclude-table / --exclude-table-data pattern.

    ``name`` (only relations visible in search_path), ``schema.name`` or
    ``db.schema.name``. More dots, or a database part that is not the
    current database, is an error in pg_dump 14+ (raised as _PatternError).
    """

    def __init__(self, pattern: str, database: str):
        parts = _pattern_split(pattern)
        if len(parts) > 3:
            raise _PatternError(
                f"improper relation name (too many dotted names): {_clean(pattern)}")
        if len(parts) == 3:
            _check_db_part(parts[0][1], database, pattern)
            parts = parts[1:]
        if len(parts) == 2:
            self.schema_rx = _compile(parts[0][0])
            self.qualified = bool(parts[0][0])
            self.name_rx = _compile(parts[1][0])
        else:
            self.schema_rx = None
            self.qualified = False
            self.name_rx = _compile(parts[0][0])

    @property
    def needs_visibility(self) -> bool:
        return not self.qualified

    def matches(self, nspname: str, relname: str, visible: Optional[bool]) -> bool:
        if self.qualified:
            if not _full(self.schema_rx, nspname):
                return False
        elif not visible:
            return False
        return _full(self.name_rx, relname)


# ---------------------------------------------------------------------------
# Catalog queries (each tagged so tests can route them)
# ---------------------------------------------------------------------------

_SQL_ROLE = """/* magikup:role */
SELECT current_user AS role_name,
       pg_catalog.current_database() AS database,
       r.rolsuper AS is_superuser,
       r.rolbypassrls AS bypass_rls,
       pg_catalog.current_setting('server_version_num')::int AS server_version_num,
       pg_catalog.has_database_privilege(pg_catalog.current_database(), 'CONNECT') AS can_connect,
       pg_catalog.current_setting('lo_compat_privileges') AS lo_compat_privileges
FROM pg_catalog.pg_roles r
WHERE r.rolname = current_user
"""

_SYSTEM_SCHEMA_FILTER = "n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'"

_SQL_SCHEMAS = f"""/* magikup:schemas */
SELECT n.nspname AS nspname,
       pg_catalog.pg_get_userbyid(n.nspowner) AS owner,
       pg_catalog.has_schema_privilege(n.oid, 'USAGE') AS can_usage
FROM pg_catalog.pg_namespace n
WHERE {_SYSTEM_SCHEMA_FILTER}
"""

# Only plain tables, partitioned tables and sequences: views, matviews and
# foreign tables are never locked nor read by pg_dump (matview data is a
# REFRESH at restore time, foreign data needs --include-foreign-data).
# Foreign/other descendants reached by LOCK recursion come from _SQL_INHERITS.
#
# can_select: COPY uses an explicit column list (non-dropped, non-generated
# columns), so column-level SELECT on all of them is enough for plain tables.
_SQL_RELATIONS = f"""/* magikup:relations */
SELECT c.oid AS oid,
       n.nspname AS nspname,
       c.relname AS relname,
       c.relkind AS relkind,
       c.relpersistence AS relpersistence,
       pg_catalog.pg_get_userbyid(c.relowner) AS owner,
       c.relrowsecurity AS rowsecurity,
       c.relforcerowsecurity AS forcerowsecurity,
       c.relhassubclass AS has_children,
       pg_catalog.pg_has_role(c.relowner, 'USAGE') AS is_owner,
       CASE WHEN pg_catalog.has_table_privilege(c.oid, 'SELECT') THEN true
            WHEN c.relkind = 'r' THEN COALESCE((
                SELECT pg_catalog.bool_and(pg_catalog.has_column_privilege(c.oid, a.attnum, 'SELECT'))
                FROM pg_catalog.pg_attribute a
                WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
                  AND a.attgenerated = ''), false)
            ELSE false
       END AS can_select,
       CASE WHEN c.relkind IN ('r', 'p')
            THEN pg_catalog.has_table_privilege(c.oid, %(lock_privs)s)
       END AS can_lock,
       EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
               WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
                 AND d.objid = c.oid AND d.objsubid = 0 AND d.deptype = 'e') AS ext_member,
       EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
               WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
                 AND d.objid = c.oid AND d.objsubid = 0 AND d.deptype = 'e'
                 AND d.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass
                 AND d.refobjid >= {_FIRST_USER_OID}::pg_catalog.oid) AS ext_user_member,
       EXISTS (SELECT 1 FROM pg_catalog.pg_extension e
               WHERE e.oid >= {_FIRST_USER_OID}::pg_catalog.oid
                 AND c.oid = ANY (e.extconfig)) AS ext_config,
       CASE WHEN c.relkind IN ('r', 'p')
            THEN EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid)
       END AS has_policies,
       CASE WHEN %(need_vis)s THEN pg_catalog.pg_table_is_visible(c.oid) END AS visible,
       own.refobjid AS owned_by,
       own.deptype AS owned_deptype
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN LATERAL (
    SELECT d.refobjid, d.deptype
    FROM pg_catalog.pg_depend d
    WHERE c.relkind = 'S'
      AND d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
      AND d.objid = c.oid AND d.objsubid = 0
      AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
      AND d.refobjsubid > 0
      AND d.deptype IN ('a', 'i')
    LIMIT 1
) own ON true
WHERE c.relkind IN ('r', 'p', 'S') AND {_SYSTEM_SCHEMA_FILTER}
"""

# Every inheritance edge with the lock privilege of the child, regardless of
# the child's relkind/schema: LOCK TABLE recursion checks them all.
_SQL_INHERITS = """/* magikup:inherits */
SELECT i.inhrelid AS child,
       i.inhparent AS parent,
       n.nspname AS nspname,
       c.relname AS relname,
       c.relkind AS relkind,
       pg_catalog.pg_get_userbyid(c.relowner) AS owner,
       pg_catalog.has_table_privilege(c.oid, %(lock_privs)s) AS can_lock
FROM pg_catalog.pg_inherits i
JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
"""

# Readability of a large object for the current role on PG < 18 (no
# has_largeobject_privilege): NULL ACL = owner only; otherwise an ACL entry
# granting SELECT to PUBLIC or to a role whose privileges we have.
_LO_READABLE_LEGACY = (
    "((m.lomacl IS NULL AND pg_catalog.pg_has_role(m.lomowner, 'USAGE')) OR EXISTS ("
    "SELECT 1 FROM pg_catalog.aclexplode(m.lomacl) a WHERE a.privilege_type = 'SELECT' "
    "AND CASE WHEN a.grantee = 0 THEN true ELSE pg_catalog.pg_has_role(a.grantee, 'USAGE') END))"
)
_LO_READABLE_PG18 = "pg_catalog.has_largeobject_privilege(m.oid, 'SELECT')"

_SQL_LO_COUNT = (
    "/* magikup:lo_count */\n"
    "SELECT count(*) AS total FROM pg_catalog.pg_largeobject_metadata\n"
)


def _lo_sample_sql(readable: str) -> str:
    """Up to _LO_SAMPLE + 1 unreadable LOs: stops at the first rows found, so
    the ACL expression is evaluated at most once per large object."""
    return (
        "/* magikup:lo_sample */\n"
        "SELECT m.oid AS oid, pg_catalog.pg_get_userbyid(m.lomowner) AS owner\n"
        "FROM pg_catalog.pg_largeobject_metadata m\n"
        f"WHERE NOT {readable}\n"
        f"LIMIT {_LO_SAMPLE + 1}\n"
    )


def _lock_privileges(server_version_num: int) -> str:
    """Privileges any of which lets LOCK TABLE ... IN ACCESS SHARE MODE pass."""
    if server_version_num >= _PG17:
        return "SELECT, INSERT, UPDATE, DELETE, TRUNCATE, MAINTAIN"
    if server_version_num >= _PG16:
        return "SELECT, INSERT, UPDATE, DELETE, TRUNCATE"
    return "SELECT"


def _fetch(cur, sql: str, params: Optional[dict] = None) -> List[Dict[str, Any]]:
    cur.execute(sql, params) if params is not None else cur.execute(sql)
    cols = [d[0] for d in (cur.description or [])]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------

def _empty_summary() -> Dict[str, Any]:
    return {
        "issues_total": 0, "errors": 0, "warnings": 0,
        "by_kind": {k: 0 for k in ISSUE_KINDS},
        "by_schema": [],
    }


def _base_result(username: str) -> Dict[str, Any]:
    return {
        "success": True,
        "error": None,
        "ok": True,
        "current_user": username,
        "is_superuser": False,
        "bypass_rls": False,
        "server_version_num": None,
        "summary": _empty_summary(),
        "issues": [],
        "truncated": False,
        "exclusions": {"schemas": [], "tables": [], "large_objects": False, "table_data": []},
        "can_exclude": False,
        # Extra (beyond the base contract): why can_exclude is False, when
        # there is something to exclude; None otherwise.
        "can_exclude_reason": None,
        "fix_sql": "",
    }


def _error_result(username: str, message: str) -> Dict[str, Any]:
    res = _base_result(username)
    res.update({"success": False, "error": message, "ok": False})
    return res


def _safe_error(exc: BaseException, password: Optional[str]) -> str:
    msg = " ".join(str(exc).split()) or exc.__class__.__name__
    if password and len(password) >= 3:
        msg = msg.replace(password, "***")
    return msg[:500]


def _issue(kind: str, schema: Optional[str], obj: str, object_type: str,
           owner: Optional[str], message: str, severity: str = "error") -> Dict[str, Any]:
    return {
        "kind": kind, "severity": severity, "schema": schema, "object": obj,
        "object_type": object_type, "owner": owner, "message": message,
    }


def _finalize(res: Dict[str, Any], issues: List[Dict[str, Any]], max_issues: int) -> None:
    issues.sort(key=lambda i: (i.get("schema") or "", _KIND_ORDER.get(i["kind"], 99),
                               i.get("object") or ""))
    summary = _empty_summary()
    by_schema: Dict[str, int] = {}
    for i in issues:
        summary["issues_total"] += 1
        if i["severity"] == "error":
            summary["errors"] += 1
        else:
            summary["warnings"] += 1
        summary["by_kind"][i["kind"]] = summary["by_kind"].get(i["kind"], 0) + 1
        if i.get("schema"):
            by_schema[i["schema"]] = by_schema.get(i["schema"], 0) + 1
    summary["by_schema"] = [
        {"schema": s, "count": c}
        for s, c in sorted(by_schema.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    cap = max(0, int(max_issues))
    res["summary"] = summary
    res["issues"] = issues[:cap]
    res["truncated"] = len(issues) > cap
    res["ok"] = summary["errors"] == 0


def _is_connect_denied(exc: BaseException, msg: str) -> bool:
    # SQLSTATE 42501 (insufficient_privilege) when the driver exposes it;
    # psycopg2 usually does not for connection-time errors, hence the
    # (English-locale) message fallback.
    if getattr(exc, "pgcode", None) == _SQLSTATE_INSUFFICIENT_PRIVILEGE:
        return True
    return "permission denied for database" in msg.lower()


def _connect_denied_result(username: str, database: str, detail: str) -> Dict[str, Any]:
    res = _base_result(username)
    issue = _issue("database_connect", None, database, "database", None,
                   "No CONNECT privilege on the database: pg_dump cannot connect")
    _finalize(res, [issue], 1)
    res["fix_sql"] = _join_fix(_fix_header(username) + [
        f"GRANT CONNECT ON DATABASE {_qi(database)} TO {_qi(username)};"])
    res["can_exclude"] = False
    res["can_exclude_reason"] = "No CONNECT privilege on the database: nothing can be backed up"
    logger.warning("Backup privilege check: role %r has no CONNECT on database %r (%s)",
                   username, database, detail)
    return res


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def check_backup_privileges(
    host: str, port: int, database: str, username: str, password: str,
    sslmode: Optional[str] = None, *,
    schemas: Optional[List[str]] = None,
    exclude_schema: Optional[str] = None,
    exclude_table: Optional[str] = None,
    exclude_table_data: Optional[str] = None,
    data_only: bool = False,
    schema_only: bool = False,
    large_objects: bool = True,
    max_issues: int = 500,
) -> Dict[str, Any]:
    """Check that ``username`` can lock/read everything pg_dump would dump.

    Read-only, never raises: ``success`` is False (with ``error``) when the
    check itself could not run. See the module docstring for the rules.
    """
    if data_only and schema_only:
        return _error_result(username, "data_only and schema_only are mutually exclusive")

    conn = None
    try:
        try:
            conn = db_service.get_connection(host, port, database, username, password,
                                             sslmode=sslmode)
        except Exception as exc:  # connection-level failure
            msg = _safe_error(exc, password)
            if _is_connect_denied(exc, msg):
                return _connect_denied_result(username, database, msg)
            logger.warning("Backup privilege check: cannot connect to %s:%s/%s as %s: %s",
                           host, port, database, username, msg)
            return _error_result(username, f"Connection failed: {msg}")

        cur = conn.cursor()
        # Read-only transaction with a bounded runtime; must be the first statement.
        cur.execute("SET TRANSACTION READ ONLY")
        cur.execute("SELECT pg_catalog.set_config('statement_timeout', %s, true)",
                    (str(STATEMENT_TIMEOUT_MS),))

        result = _run_checks(
            cur, username,
            schemas=[s for s in (schemas or []) if s] or None,
            exclude_schema=exclude_schema or None,
            exclude_table=exclude_table or None,
            exclude_table_data=exclude_table_data or None,
            need_data=not schema_only,
            large_objects=large_objects,
            max_issues=max_issues,
        )
        logger.info(
            "Backup privilege check on %s as %s: ok=%s issues=%s",
            database, result.get("current_user"), result.get("ok"),
            result.get("summary", {}).get("issues_total"),
        )
        return result
    except _PatternError as exc:
        # pg_dump itself would refuse the pattern: report it, do not guess.
        return _error_result(username, f"Invalid name pattern (pg_dump would reject it): {exc}")
    except Exception as exc:
        msg = _safe_error(exc, password)
        logger.warning("Backup privilege check failed on %s:%s/%s as %s: %s",
                       host, port, database, username, msg)
        return _error_result(username, f"Privilege check failed: {msg}")
    finally:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def _run_checks(cur, username: str, *, schemas: Optional[List[str]],
                exclude_schema: Optional[str], exclude_table: Optional[str],
                exclude_table_data: Optional[str], need_data: bool,
                large_objects: bool, max_issues: int) -> Dict[str, Any]:
    role_rows = _fetch(cur, _SQL_ROLE)
    if not role_rows:
        raise RuntimeError("current role not found in pg_roles")
    role = role_rows[0]
    role_name = role["role_name"] or username
    dbname = role["database"]
    version = int(role["server_version_num"] or 0)

    res = _base_result(role_name)
    res["is_superuser"] = bool(role["is_superuser"])
    res["bypass_rls"] = bool(role["bypass_rls"]) or res["is_superuser"]
    res["server_version_num"] = version

    # Patterns are validated even for superusers: pg_dump rejects them too.
    schema_pats = [_SchemaPattern(p, dbname) for p in schemas] if schemas else None
    xs_pat = _SchemaPattern(exclude_schema, dbname) if exclude_schema and not schemas else None
    excl_t = _RelPattern(exclude_table, dbname) if exclude_table else None
    excl_d = _RelPattern(exclude_table_data, dbname) if exclude_table_data else None

    if res["is_superuser"]:
        return res  # superusers bypass every privilege and RLS check

    issues: List[Dict[str, Any]] = []
    if role.get("can_connect") is False:
        issues.append(_issue("database_connect", None, dbname, "database", None,
                             "No CONNECT privilege on the database: pg_dump cannot connect"))

    # -- schema selection (selectDumpableNamespace) --
    schema_rows = {r["nspname"]: r for r in _fetch(cur, _SQL_SCHEMAS)}
    if schema_pats:
        selected = {n for n in schema_rows if any(p.matches(n) for p in schema_pats)}
        # pg_dump: "no matching schemas were found" when no --schema pattern
        # matches anything (unquoted names fold to lower case). System schemas
        # are not in schema_rows, so the common ones are tested by name.
        if not selected and not any(p.matches(n) for p in schema_pats
                                    for n in ("information_schema", "pg_catalog", "pg_toast")):
            raise _PatternError("no matching schemas were found")
    else:
        selected = set(schema_rows)
        if xs_pat:
            selected = {n for n in selected if not xs_pat.matches(n)}
    # Without --schema pg_dump runs with include_everything: extensions (and
    # so their member tables' POLICY component) are dumped.
    include_everything = not schema_pats

    need_vis = any(p is not None and p.needs_visibility for p in (excl_t, excl_d))
    lock_privs = _lock_privileges(version)

    rels = {r["oid"]: r for r in _fetch(cur, _SQL_RELATIONS, {
        "lock_privs": lock_privs, "need_vis": need_vis})}

    # -- relation selection (selectDumpableTable / getOwnedSeqs / extension config) --
    for r in rels.values():
        r["user_excluded"] = bool(excl_t and excl_t.matches(r["nspname"], r["relname"], r["visible"]))
        r["data_excluded"] = bool(excl_d and excl_d.matches(r["nspname"], r["relname"], r["visible"]))
        r["selected"] = (r["nspname"] in selected and not r["user_excluded"]
                         and not r["ext_member"])
        r["dumped"] = False
        r["ext_data"] = False

    def ext_config_data(r: Dict[str, Any]) -> bool:
        # processExtensionTables: config table/sequence data is dumped when
        # its schema is selected and no exclusion switch names it. With
        # --schema-only the config *sequence* value is still read (dumpSequenceData
        # queries it eagerly) while the config table COPY is skipped
        # (verified with pg_dump 15-17).
        return bool(r["ext_member"] and r["ext_config"]
                    and (need_data or r["relkind"] == "S")
                    and r["nspname"] in selected and not r["user_excluded"]
                    and not r["data_excluded"] and r["relpersistence"] != "u")

    lock_needed: List[Dict[str, Any]] = []       # dumped r/p: locked, excludable
    ext_lock: List[Dict[str, Any]] = []          # extension member r/p: may be locked, not excludable
    data_needed: List[Dict[str, Any]] = []       # plain tables whose rows are COPYed
    seq_needed: List[Dict[str, Any]] = []        # sequences whose value is SELECTed

    for r in rels.values():
        kind = r["relkind"]
        if kind not in ("r", "p"):
            continue
        if r["selected"]:
            r["dumped"] = True
            lock_needed.append(r)
            if (need_data and kind == "r" and r["relpersistence"] != "u"
                    and not r["data_excluded"]):
                data_needed.append(r)
        else:
            if kind == "r" and ext_config_data(r):
                r["ext_data"] = True
                data_needed.append(r)
            if r["ext_member"] and r.get("ext_user_member") and include_everything:
                ext_lock.append(r)

    for r in rels.values():
        if r["relkind"] != "S":
            continue
        owner_tab = rels.get(r["owned_by"]) if r.get("owned_by") is not None else None
        tab_dumped = bool(owner_tab and owner_tab.get("dumped"))
        r["owner_table"] = owner_tab
        if r.get("owned_deptype") == "i":
            dumped = tab_dumped
        else:
            dumped = r["selected"] or tab_dumped
        r["dumped"] = dumped
        if dumped:
            if need_data and r["relpersistence"] != "u" and not r["data_excluded"]:
                seq_needed.append(r)
        elif ext_config_data(r):
            r["ext_data"] = True
            seq_needed.append(r)

    # -- schema USAGE --
    needs_usage: Set[str] = {r["nspname"] for r in lock_needed + data_needed + seq_needed}
    usage_fail = sorted(s for s in needs_usage
                        if schema_rows.get(s, {}).get("can_usage") is False)
    usage_fail_set = set(usage_fail)
    for s in usage_fail:
        issues.append(_issue("schema_usage", s, s, "schema", schema_rows[s].get("owner"),
                             "No USAGE privilege on schema: pg_dump cannot lock or read its objects"))

    # -- LOCK TABLE (with recursion into every descendant) --
    lock_roots = lock_needed + ext_lock
    children_of: Dict[int, List[int]] = {}
    parents_of: Dict[int, List[int]] = {}
    child_info: Dict[int, Dict[str, Any]] = {}
    if any(r.get("has_children") for r in lock_roots):
        for row in _fetch(cur, _SQL_INHERITS, {"lock_privs": lock_privs}):
            children_of.setdefault(row["parent"], []).append(row["child"])
            parents_of.setdefault(row["child"], []).append(row["parent"])
            child_info[row["child"]] = row

    def can_lock(oid: int) -> Optional[bool]:
        if oid in rels and rels[oid]["relkind"] in ("r", "p"):
            return rels[oid]["can_lock"]
        info = child_info.get(oid)
        return info.get("can_lock") if info else None

    def label(oid: int) -> str:
        r = rels.get(oid) or child_info.get(oid) or {}
        return f'{r.get("nspname")}.{r.get("relname")}'

    root_ids = {r["oid"] for r in lock_roots}
    # blocked[ancestor] = [count, preview names] of unlockable descendants
    blocked: Dict[int, List[Any]] = {}
    extra_fix: Dict[int, Dict[str, Any]] = {}    # unlockable, not dumped, under a lock root
    # Only PG 12 checks privileges on the descendants reached by recursion.
    failing_desc = sorted((o for o, info in child_info.items() if info.get("can_lock") is False),
                          key=label) if version < _PG13 else []
    for f in failing_desc:
        hit = False
        for anc in _ancestors(f, parents_of):
            if anc not in root_ids:
                continue
            hit = True
            entry = blocked.setdefault(anc, [0, []])
            entry[0] += 1
            if len(entry[1]) < _BLOCKED_PREVIEW:
                entry[1].append(label(f))
        if hit and not (f in rels and rels[f].get("dumped")):
            info = child_info[f]
            extra_fix[f] = {"oid": f, "nspname": info["nspname"], "relname": info["relname"],
                            "relkind": info.get("relkind"), "owner": info.get("owner"),
                            "ext_member": f in rels and rels[f].get("ext_member")}

    direct_lock_fail = [r for r in lock_needed if r["can_lock"] is False]
    lock_fail_ids = {r["oid"] for r in direct_lock_fail}
    blocked_only = [r for r in lock_needed if r["oid"] in blocked and r["oid"] not in lock_fail_ids]
    # Tables that must leave the dump: unlockable ones, ancestors that recurse
    # into an unlockable descendant, and all dumped descendants of those (a
    # partition/child cannot be restored without its parent). Siblings through
    # multiple inheritance are not pulled in: only descendants are.
    lock_family = _descendants_closure(lock_fail_ids | {r["oid"] for r in blocked_only},
                                       children_of)
    lock_excluded = {o for o in lock_family
                     if o in rels and rels[o].get("dumped") and rels[o]["relkind"] in ("r", "p")}

    # -- data / sequence / RLS --
    select_fail = [r for r in data_needed if r["can_select"] is False]
    select_fail_ids = {r["oid"] for r in select_fail}
    seq_fail = [r for r in seq_needed if r["can_select"] is False]
    rls_fail = [r for r in data_needed
                if r["rowsecurity"] and not res["bypass_rls"]
                and not (r["is_owner"] and not r["forcerowsecurity"])]
    rls_fail_ids = {r["oid"] for r in rls_fail}

    lock_hint = lock_privs.replace(", ", "/")
    fix_tables: List[Dict[str, Any]] = []        # root causes fixed by GRANT SELECT
    for r in select_fail:
        msg = "No SELECT privilege: pg_dump cannot read the table data"
        if r["oid"] in lock_fail_ids:
            msg += " (nor lock it)"
        issues.append(_issue("table_select", r["nspname"], r["relname"], _type_of(r),
                             r["owner"], msg))
        fix_tables.append(r)
    for r in direct_lock_fail:
        if r["oid"] in select_fail_ids:
            continue
        issues.append(_issue(
            "table_lock", r["nspname"], r["relname"], _type_of(r), r["owner"],
            f"Cannot LOCK TABLE ... IN ACCESS SHARE MODE (needs {lock_hint})"))
        fix_tables.append(r)
    for r in blocked_only:
        count, names = blocked[r["oid"]]
        shown = ", ".join(names) + (f" (+{count - len(names)} more)" if count > len(names) else "")
        issues.append(_issue(
            "table_lock", r["nspname"], r["relname"], _type_of(r), r["owner"],
            f"LOCK TABLE recurses into descendant tables that cannot be locked: {shown}"))
    fix_tables.extend(extra_fix[o] for o in sorted(extra_fix, key=label))

    # Extension member tables (no --schema): not removable by any exclusion.
    ext_usage_fix: Set[str] = set()
    for r in ext_lock:
        no_usage = schema_rows.get(r["nspname"], {}).get("can_usage") is False
        own_fail = r["can_lock"] is False
        desc = blocked.get(r["oid"])
        if not (no_usage or own_fail or desc):
            continue
        # Current pg_dump minor releases dump only the ACL of extension members
        # and never lock them (verified with pg_dump 15-17 against PG 12-17,
        # RLS/policies included); older minors (before 16.2/15.6/14.11) did.
        # Hence a non-blocking warning.
        reasons = []
        if no_usage:
            reasons.append("no USAGE on its schema")
            ext_usage_fix.add(r["nspname"])
        if own_fail:
            reasons.append(f"cannot lock it (needs {lock_hint})")
        if desc:
            reasons.append(f"{desc[0]} descendant table(s) cannot be locked: " + ", ".join(desc[1]))
        msg = ("Extension member table that older pg_dump minor releases (before "
               "16.2/15.6/14.11) lock when the whole database is dumped: "
               + "; ".join(reasons) + ". Current releases do not lock it; with an "
               "older pg_dump grant the privilege (it cannot be excluded)")
        issues.append(_issue("table_lock", r["nspname"], r["relname"], _type_of(r), r["owner"],
                             msg, severity="warning"))
        if own_fail:
            fix_tables.append(dict(r, ext_member=True))

    for r in seq_fail:
        issues.append(_issue("sequence_select", r["nspname"], r["relname"], "sequence",
                             r["owner"],
                             "No SELECT privilege on sequence: pg_dump cannot read its current value"))
    for r in rls_fail:
        issues.append(_issue(
            "rls", r["nspname"], r["relname"], _type_of(r), r["owner"],
            "Row-level security is enabled and the role cannot bypass it: "
            "pg_dump (row_security=off) fails on this table"))

    # -- large objects --
    lo_dumped = need_data and (large_objects or not schemas)
    lo_issue = None
    lo_info: Dict[str, Any] = {"total": 0, "unreadable": 0, "sample": []}
    if lo_dumped and str(role.get("lo_compat_privileges") or "").lower() not in ("on", "true", "1"):
        readable = _LO_READABLE_PG18 if version >= _PG18 else _LO_READABLE_LEGACY
        lo_info["total"] = int((_fetch(cur, _SQL_LO_COUNT) or [{}])[0].get("total") or 0)
        sample = _fetch(cur, _lo_sample_sql(readable)) if lo_info["total"] else []
        if sample:
            sample.sort(key=lambda s: int(s["oid"]))
            exact = len(sample) <= _LO_SAMPLE
            lo_info["sample"] = sample[:_LO_SAMPLE]
            lo_info["unreadable"] = len(sample) if exact else None
            n_txt = str(len(sample)) if exact else f"More than {_LO_SAMPLE}"
            owners = sorted({s["owner"] for s in lo_info["sample"] if s.get("owner")})
            lo_issue = _issue(
                "large_object", None,
                f"{len(sample)} large object(s)" if exact else f">{_LO_SAMPLE} large object(s)",
                "large object", ", ".join(owners) or None,
                f"{n_txt} of {lo_info['total']} large object(s) are not readable "
                "(no SELECT privilege): pg_dump cannot read them")
            issues.append(lo_issue)

    # -- exclusions --
    plan = _ExclusionPlan(rels, selected, usage_fail_set, lock_excluded, children_of,
                          data_needed, seq_needed, select_fail_ids | rls_fail_ids,
                          child_info)
    excl_schemas = set(usage_fail_set & selected)
    excl_tables, excl_data = plan.build(excl_schemas)
    collapsed: List[str] = []
    lo_excl = 1 if lo_issue is not None else 0
    if len(excl_schemas) + len(excl_tables) + len(excl_data) + lo_excl > MAX_EXCLUSION_PATTERNS:
        collapsed = plan.collapsible(excl_schemas, excl_tables, excl_data)
        if collapsed:
            excl_schemas |= set(collapsed)
            excl_tables, excl_data = plan.build(excl_schemas)
    n_patterns = len(excl_schemas) + len(excl_tables) + len(excl_data)

    res["exclusions"] = {
        "schemas": sorted(excl_schemas),
        "tables": [list(t) for t in sorted(excl_tables)],
        "large_objects": lo_issue is not None,
        # Extra (beyond the base contract): data-only exclusions, passed as
        # --exclude-table-data (owned sequences, unreadable data of tables
        # that can still be locked, RLS tables, extension config data).
        "table_data": [list(t) for t in sorted(excl_data)],
    }
    if collapsed:
        res["exclusions"]["collapsed_schemas"] = sorted(collapsed)

    has_excl = bool(excl_schemas or excl_tables or excl_data or lo_issue is not None)
    connect_issue = any(i["kind"] == "database_connect" for i in issues)
    reason: Optional[str] = None
    if connect_issue:
        reason = "No CONNECT privilege on the database: nothing can be backed up"
    elif not has_excl:
        reason = None
    elif n_patterns > MAX_EXCLUSION_PATTERNS:
        reason = (f"Too many objects to exclude ({n_patterns} exclusion patterns, limit "
                  f"{MAX_EXCLUSION_PATTERNS}): grant the privileges instead")
    elif schema_pats and selected and selected <= excl_schemas:
        reason = "Every selected schema is inaccessible"
    else:
        defs_left, data_left = plan.leftovers(excl_schemas, excl_data)
        lo_left = (lo_dumped and lo_issue is None and lo_info["total"] > 0)
        had_data = bool(data_needed or seq_needed or lo_info["total"])
        if need_data and had_data and not (data_left or lo_left):
            reason = "No table data would be left in the backup"
        elif not need_data and lock_needed and not defs_left:
            reason = "No table would be left in the backup"
    res["can_exclude"] = has_excl and reason is None
    res["can_exclude_reason"] = reason

    fix_sql = _build_fix_sql(
        role_name, dbname, version,
        usage_fail=sorted(usage_fail_set | ext_usage_fix), schema_rows=schema_rows,
        fix_tables=fix_tables, seq_fail=seq_fail, rls_fail=rls_fail,
        lock_needed=lock_needed, data_needed=data_needed, seq_needed=seq_needed,
        connect_issue=connect_issue, lo_info=lo_info if lo_issue else None,
    ) if issues else ""

    _finalize(res, issues, max_issues)
    res["fix_sql"] = fix_sql
    return res


class _ExclusionPlan:
    """Turns failures into pg_dump exclusion patterns.

    - schemas: --exclude-schema (or removal from the --schema list);
    - tables: --exclude-table, only for plain/partitioned tables that cannot be
      locked (LOCK happens even for schema-only dumps), plus every dumped
      descendant of a removed table, foreign-table partitions included (a
      child/partition cannot be restored without its parent);
    - data: --exclude-table-data for everything that can be locked but whose
      data cannot be read (no SELECT, RLS) and for sequences — owned
      sequences ignore --exclude-table, and keeping the definition keeps
      column DEFAULT nextval(...) restorable.
    """

    def __init__(self, rels, selected, usage_fail, lock_excluded, children_of,
                 data_needed, seq_needed, data_fail_ids, child_info=None):
        self.rels = rels
        self.selected = selected
        self.usage_fail = usage_fail
        self.lock_excluded = lock_excluded
        self.children_of = children_of
        self.data_needed = data_needed
        self.seq_needed = seq_needed
        self.data_fail_ids = data_fail_ids
        self.child_info = child_info or {}
        self._gone_cache: Dict[frozenset, Set[int]] = {}

    @staticmethod
    def _key(r) -> Tuple[str, str]:
        return (r["nspname"], r["relname"])

    def _gone(self, S: Set[str]) -> Set[int]:
        """OIDs of dumped tables removed by schema exclusions S or lock failures."""
        k = frozenset(S)
        if k not in self._gone_cache:
            roots = set(self.lock_excluded) | {
                o for o, r in self.rels.items()
                if r.get("dumped") and r["relkind"] in ("r", "p") and r["nspname"] in S}
            self._gone_cache[k] = {
                o for o in _descendants_closure(roots, self.children_of)
                if o in self.rels and self.rels[o].get("dumped")
                and self.rels[o]["relkind"] in ("r", "p")}
        return self._gone_cache[k]

    def _table_kept(self, r, S) -> bool:
        return bool(r.get("dumped") and r["oid"] not in self._gone(S))

    def _seq_kept(self, r, S) -> bool:
        if r.get("ext_data"):
            return r["nspname"] not in S
        owner = r.get("owner_table")
        owner_kept = bool(owner is not None and self._table_kept(owner, S))
        if r.get("owned_deptype") == "i":
            return owner_kept
        return bool(r["selected"] and r["nspname"] not in S) or owner_kept

    def _data_kept(self, r, S) -> bool:
        if r.get("ext_data"):
            return r["nspname"] not in S
        return self._table_kept(r, S)

    def build(self, S: Set[str]) -> Tuple[Set[Tuple[str, str]], Set[Tuple[str, str]]]:
        gone = self._gone(S)
        T = {self._key(self.rels[o]) for o in gone if self.rels[o]["nspname"] not in S}
        # Foreign-table (or other non r/p) partitions/children of a removed
        # table: pg_dump still dumps their definition (CREATE FOREIGN TABLE
        # ... PARTITION OF parent), which would fail at restore time.
        for o in _descendants_closure(gone, self.children_of):
            info = self.child_info.get(o)
            if (info and info.get("relkind") not in ("r", "p")
                    and info["nspname"] in self.selected and info["nspname"] not in S):
                T.add((info["nspname"], info["relname"]))
        D: Set[Tuple[str, str]] = set()
        for r in self.data_needed:
            if self._data_kept(r, S) and (r["oid"] in self.data_fail_ids
                                          or r["nspname"] in self.usage_fail):
                D.add(self._key(r))
        for r in self.seq_needed:
            if self._seq_kept(r, S) and (r["can_select"] is False
                                         or r["nspname"] in self.usage_fail):
                D.add(self._key(r))
        return T, D

    def collapsible(self, S, T, D) -> List[str]:
        """Selected schemas whose every dumped object is already excluded
        (whole table or data): replacing their entries by one schema pattern."""
        gone = self._gone(S)
        per_schema: Dict[str, List[bool]] = {}
        for o, r in self.rels.items():
            nsp = r["nspname"]
            if nsp in S or nsp not in self.selected:
                continue
            if r["relkind"] in ("r", "p"):
                if r.get("dumped"):
                    per_schema.setdefault(nsp, []).append(o in gone or self._key(r) in D)
                elif r.get("ext_data"):
                    per_schema.setdefault(nsp, []).append(self._key(r) in D)
            elif r["relkind"] == "S" and self._seq_kept(r, S):
                per_schema.setdefault(nsp, []).append(self._key(r) in D)
        return sorted(s for s, flags in per_schema.items() if flags and all(flags))

    def leftovers(self, S, D) -> Tuple[bool, bool]:
        defs_left = any(self._table_kept(r, S) for r in self.rels.values()
                        if r["relkind"] in ("r", "p"))
        data_left = any(self._data_kept(r, S) and self._key(r) not in D for r in self.data_needed) \
            or any(self._seq_kept(r, S) and self._key(r) not in D for r in self.seq_needed)
        return defs_left, data_left


def _type_of(r: Dict[str, Any]) -> str:
    return {"r": "table", "p": "partitioned table", "S": "sequence",
            "f": "foreign table"}.get(r.get("relkind"), "relation")


def _ancestors(oid: int, parents_of: Dict[int, List[int]]) -> Iterable[int]:
    seen: Set[int] = set()
    stack = list(parents_of.get(oid, []))
    while stack:
        p = stack.pop()
        if p in seen:
            continue
        seen.add(p)
        yield p
        stack.extend(parents_of.get(p, []))


def _descendants_closure(roots: Set[int], children_of: Dict[int, List[int]]) -> Set[int]:
    """roots plus every (transitive) descendant — O(V + E) overall."""
    seen: Set[int] = set()
    stack = list(roots)
    while stack:
        o = stack.pop()
        if o in seen:
            continue
        seen.add(o)
        stack.extend(children_of.get(o, []))
    return seen


# ---------------------------------------------------------------------------
# Fix SQL
# ---------------------------------------------------------------------------

def _fix_header(role: str) -> List[str]:
    return [
        f"-- Privileges needed by role {_qi(role)} to run pg_dump.",
        "-- Run as a superuser or as the owner of the objects below.",
        "-- MagikUp shows this script only: it never executes it. Review before running.",
        "",
    ]


def _join_fix(lines: List[str]) -> str:
    # Defence in depth: no line may contain a line break or other control /
    # format character (names are already escaped by _qi).
    return "\n".join(_clean(line) for line in lines).rstrip("\n") + "\n"


def _chunks(items: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _use_all(affected: int, total: int) -> bool:
    """GRANT ... ON ALL ... IN SCHEMA when (almost) every object is affected."""
    return affected >= 2 and affected * 4 >= total * 3


def _build_fix_sql(role: str, dbname: str, version: int, *, usage_fail: List[str],
                   schema_rows: Dict[str, Dict[str, Any]], fix_tables: List[Dict[str, Any]],
                   seq_fail: List[Dict[str, Any]], rls_fail: List[Dict[str, Any]],
                   lock_needed: List[Dict[str, Any]], data_needed: List[Dict[str, Any]],
                   seq_needed: List[Dict[str, Any]], connect_issue: bool,
                   lo_info: Optional[Dict[str, Any]]) -> str:
    r_q = _qi(role)
    out = _fix_header(role)

    if connect_issue:
        out += [f"GRANT CONNECT ON DATABASE {_qi(dbname)} TO {r_q};", ""]

    tables_by_schema: Dict[str, Dict[int, Dict[str, Any]]] = {}
    for r in fix_tables:
        tables_by_schema.setdefault(r["nspname"], {})[r["oid"]] = r
    seqs_by_schema: Dict[str, List[Dict[str, Any]]] = {}
    for r in seq_fail:
        seqs_by_schema.setdefault(r["nspname"], []).append(r)

    total_tables: Dict[str, Set[int]] = {}
    for r in lock_needed + data_needed + fix_tables:
        total_tables.setdefault(r["nspname"], set()).add(r["oid"])
    total_seqs: Dict[str, int] = {}
    for r in seq_needed:
        total_seqs[r["nspname"]] = total_seqs.get(r["nspname"], 0) + 1

    defaults: List[str] = []
    for s in sorted(set(usage_fail) | set(tables_by_schema) | set(seqs_by_schema)):
        out.append(f"-- Schema {_qi(s)}")
        if s in usage_fail:
            out.append(f"GRANT USAGE ON SCHEMA {_qi(s)} TO {r_q};")
        tabs = sorted(tables_by_schema.get(s, {}).values(), key=lambda r: r["relname"])
        if tabs:
            total = len(total_tables.get(s, ()))
            if _use_all(len(tabs), total):
                out.append(f"-- {len(tabs)} of {total} affected tables "
                           "(this also grants SELECT on the schema's other tables and views)")
                out.append(f"GRANT SELECT ON ALL TABLES IN SCHEMA {_qi(s)} TO {r_q};")
            else:
                for chunk in _chunks([_qn(s, r["relname"]) for r in tabs], _GRANT_CHUNK):
                    out.append(f"GRANT SELECT ON TABLE {', '.join(chunk)} TO {r_q};")
            for owner in sorted({r["owner"] for r in tabs
                                 if r.get("owner") and not r.get("ext_member")}):
                defaults.append(f"ALTER DEFAULT PRIVILEGES FOR ROLE {_qi(owner)} IN SCHEMA "
                                f"{_qi(s)} GRANT SELECT ON TABLES TO {r_q};")
        seqs = sorted(seqs_by_schema.get(s, []), key=lambda r: r["relname"])
        if seqs:
            total = total_seqs.get(s, 0)
            if _use_all(len(seqs), total):
                out.append(f"GRANT SELECT ON ALL SEQUENCES IN SCHEMA {_qi(s)} TO {r_q};")
            else:
                for chunk in _chunks([_qn(s, r["relname"]) for r in seqs], _GRANT_CHUNK):
                    out.append(f"GRANT SELECT ON SEQUENCE {', '.join(chunk)} TO {r_q};")
            for owner in sorted({r["owner"] for r in seqs
                                 if r.get("owner") and not r.get("ext_member")}):
                defaults.append(f"ALTER DEFAULT PRIVILEGES FOR ROLE {_qi(owner)} IN SCHEMA "
                                f"{_qi(s)} GRANT SELECT ON SEQUENCES TO {r_q};")
        out.append("")

    if rls_fail:
        names = sorted(_qn(r["nspname"], r["relname"]) for r in rls_fail)
        shown = ", ".join(names[:_FIX_LIST_PREVIEW])
        if len(names) > _FIX_LIST_PREVIEW:
            shown += f" ... (+{len(names) - _FIX_LIST_PREVIEW} more)"
        out += [
            f"-- Row-level security: pg_dump runs with row_security=off and fails on {len(names)} table(s):",
            f"--   {shown}",
            "-- Requires superuser privileges. On managed services (e.g. AWS RDS/Aurora)",
            "-- BYPASSRLS may not be grantable: verify on your platform.",
            f"ALTER ROLE {r_q} BYPASSRLS;",
            "-- Alternatives: run the backup as the tables' owner (works unless the table",
            "-- uses FORCE ROW LEVEL SECURITY), or exclude their data (Exclude inaccessible",
            "-- objects). pg_dump --enable-row-security would dump only the rows visible",
            "-- to the role, i.e. PARTIAL data.",
            "",
        ]

    if lo_info:
        n = lo_info["unreadable"]
        sample = lo_info.get("sample") or []
        if n is not None:
            out.append(f"-- Large objects: {n} large object(s) are not readable by {r_q}.")
            out.append("-- Run as each large object's owner or as a superuser:")
            for s in sample[:n]:
                out.append(f"GRANT SELECT ON LARGE OBJECT {int(s['oid'])} TO {r_q};")
        else:
            out.append(f"-- Large objects: more than {_LO_SAMPLE} large objects are not "
                       f"readable by {r_q}.")
            out.append("-- Grant SELECT on each of them as its owner or as a superuser, e.g.:")
            for s in sample[:_LO_SAMPLE]:
                out.append(f"-- GRANT SELECT ON LARGE OBJECT {int(s['oid'])} TO {r_q};")
            out.append(f"-- ... and more (only the first {_LO_SAMPLE} are listed).")
        out += [
            "-- Alternatively back up without large objects (Exclude inaccessible objects).",
            "",
        ]

    if defaults:
        out += ["-- Optional: prevent recurrence for objects created later",
                "-- (run as each owner role or as a superuser).",
                *defaults, ""]

    if version >= _PG14 and (fix_tables or seq_fail or usage_fail):
        out += [
            "-- Alternative (PostgreSQL 14+): read access to all tables, views and sequences",
            "-- and USAGE on all schemas. It does NOT bypass row-level security.",
            f"-- GRANT pg_read_all_data TO {r_q};",
            "",
        ]

    return _join_fix(out)


# ---------------------------------------------------------------------------
# Plain-text summary (logs / emails)
# ---------------------------------------------------------------------------

def format_issue_summary(result: dict, max_lines: int = 20) -> str:
    """Multi-line plain-text summary of a check_backup_privileges result.

    Object names, owners and messages are rendered on a single line each
    (control/format characters replaced), so a crafted name cannot forge
    extra lines in logs or emails.
    """
    result = result or {}
    user = _clean(result.get("current_user") or "?")
    if not result.get("success", False):
        return f"Backup privilege check could not run: {_clean(result.get('error') or 'unknown error')}"
    if result.get("ok"):
        return f"Backup privilege check passed for role {user}."

    summary = result.get("summary") or {}
    issues = result.get("issues") or []
    total = summary.get("issues_total", len(issues))
    lines = [f"Backup privilege check failed for role {user}: {total} issue(s) "
             f"({summary.get('errors', total)} error(s), {summary.get('warnings', 0)} warning(s))."]
    by_kind = {k: v for k, v in (summary.get("by_kind") or {}).items() if v}
    if by_kind:
        lines.append("By kind: " + ", ".join(f"{k}={v}" for k, v in by_kind.items()))
    by_schema = summary.get("by_schema") or []
    if by_schema:
        lines.append("By schema: " + ", ".join(
            f"{_clean(e.get('schema'))}={e.get('count')}" for e in by_schema[:20])
            + (" ..." if len(by_schema) > 20 else ""))
    if issues:
        limit = max(0, int(max_lines))
        lines.append(f"Issues (first {min(limit, len(issues))} of {total}):")
        for i in issues[:limit]:
            where = ".".join(_clean(p) for p in (i.get("schema"), i.get("object")) if p)
            extra = _clean(i.get("object_type") or "")
            if i.get("owner"):
                extra += f", owner {_clean(i['owner'])}"
            lines.append(f"  [{_clean(i.get('severity', 'error'))}] {_clean(i.get('kind'))} {where} "
                         f"({extra}): {_clean(i.get('message', ''))}")
        if total > limit:
            lines.append(f"  ... {total - limit} more")
    fix = (result.get("fix_sql") or "").strip()
    if fix:
        lines += ["", "Suggested fix (run as superuser/object owner; MagikUp never executes it):", fix]
    return "\n".join(lines)
