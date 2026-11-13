"""Backup privilege preflight — app.privilege_check.

No real database: db_service.get_connection is replaced by a fake connection
whose cursor routes each tagged catalog query (/* magikup:<name> */) to rows
supplied by the test. The privilege booleans normally computed by PostgreSQL
(has_table_privilege, pg_has_role, ...) are part of those rows.
"""
import pytest

from app import db_service, privilege_check as pc

# conftest stubs check_backup_privileges for every test (hermetic integration
# tests); keep a handle on the real implementation captured at import time.
REAL_CHECK = pc.check_backup_privileges

PASSWORD = "s3cret-pw"


# --------------------------------------------------------------------------
# fake DB
# --------------------------------------------------------------------------
class FakeCursor:
    def __init__(self, db):
        self.db = db
        self.description = None
        self._rows = []

    def execute(self, sql, params=None):
        self.db.executed.append((sql, params))
        if self.db.fail_on and self.db.fail_on in sql:
            raise RuntimeError("canceling statement due to statement timeout")
        tag = None
        if "/* magikup:" in sql:
            tag = sql.split("/* magikup:", 1)[1].split("*/", 1)[0].strip()
        rows = self.db.data.get(tag, []) if tag else []
        if callable(rows):
            rows = rows(sql, params)
        if rows:
            cols = list(rows[0].keys())
            self.description = [(c,) for c in cols]
            self._rows = [tuple(r[c] for c in cols) for r in rows]
        else:
            self.description = [("x",)]
            self._rows = []

    def fetchall(self):
        return list(self._rows)


class FakeConn:
    def __init__(self, db):
        self.db = db
        self.closed = False

    def cursor(self):
        return FakeCursor(self.db)

    def rollback(self):
        pass

    def close(self):
        self.closed = True
        self.db.closed = True


class FakeDB:
    def __init__(self):
        self.executed = []
        self.closed = False
        self.fail_on = None
        self.connect_error = None
        self.connect_kwargs = None
        self.data = {
            "role": [role()],
            "schemas": [schema("public")],
            "relations": [],
            "inherits": [],
            "lo_count": [{"total": 0}],
            "lo_sample": [],
        }

    def sql_for(self, tag):
        return [(s, p) for s, p in self.executed if f"magikup:{tag}" in s]


@pytest.fixture
def db(monkeypatch):
    fake = FakeDB()

    def _connect(host, port, database, username, password, **kw):
        fake.connect_kwargs = dict(host=host, port=port, database=database,
                                   username=username, password=password, **kw)
        if fake.connect_error:
            raise fake.connect_error
        return FakeConn(fake)

    monkeypatch.setattr(db_service, "get_connection", _connect)
    return fake


def run(**kw):
    return REAL_CHECK("db.local", 5432, "appdb", "app_backup", PASSWORD, **kw)


# --------------------------------------------------------------------------
# row builders
# --------------------------------------------------------------------------
def role(**over):
    r = {"role_name": "app_backup", "database": "appdb", "is_superuser": False,
         "bypass_rls": False, "server_version_num": 160004, "can_connect": True,
         "lo_compat_privileges": "off"}
    r.update(over)
    return r


def schema(name, usage=True, owner="owner"):
    return {"nspname": name, "owner": owner, "can_usage": usage}


_OID = [1000]


def rel(nsp, name, kind="r", **over):
    _OID[0] += 1
    r = {"oid": _OID[0], "nspname": nsp, "relname": name, "relkind": kind,
         "relpersistence": "p", "owner": "owner", "rowsecurity": False,
         "forcerowsecurity": False, "is_owner": False, "can_select": True,
         "can_lock": True if kind in ("r", "p") else None, "ext_member": False,
         "ext_config": False, "ext_user_member": False, "has_policies": False,
         "has_children": False, "visible": None, "owned_by": None, "owned_deptype": None}
    if kind not in ("r", "p"):
        r["has_policies"] = None
    r.update(over)
    return r


def inh(child, parent, **over):
    """pg_inherits edge as returned by the inherits query (child's lock privilege)."""
    r = {"child": child["oid"], "parent": parent["oid"], "nspname": child["nspname"],
         "relname": child["relname"], "relkind": child["relkind"], "owner": child["owner"],
         "can_lock": child.get("can_lock")}
    r.update(over)
    return r


def kinds(res):
    return sorted((i["kind"], i["schema"], i["object"]) for i in res["issues"])


# --------------------------------------------------------------------------
# basics
# --------------------------------------------------------------------------
def test_superuser_short_circuits(db):
    db.data["role"] = [role(is_superuser=True)]
    db.data["relations"] = [rel("public", "t", can_select=False, can_lock=False)]
    res = run()
    assert res["success"] and res["ok"] and res["is_superuser"] and res["bypass_rls"]
    assert res["issues"] == [] and res["fix_sql"] == ""
    assert not db.sql_for("relations")
    assert db.closed


def test_session_is_read_only_with_timeout_and_closed(db):
    res = run()
    assert res["success"] and res["ok"]
    sqls = [s for s, _ in db.executed]
    assert sqls[0] == "SET TRANSACTION READ ONLY"
    assert "statement_timeout" in sqls[1] and db.executed[1][1] == ("60000",)
    assert db.closed
    assert db.connect_kwargs["sslmode"] is None


def test_all_granted_is_ok(db):
    db.data["relations"] = [rel("public", "a"), rel("public", "a_id_seq", "S")]
    res = run()
    assert res["ok"] and res["issues"] == [] and not res["truncated"]
    assert res["summary"]["issues_total"] == 0
    assert set(res["summary"]["by_kind"]) == set(pc.ISSUE_KINDS)
    assert res["can_exclude"] is False and res["fix_sql"] == ""
    assert res["exclusions"]["schemas"] == [] and res["exclusions"]["tables"] == []


def test_mutually_exclusive_modes():
    res = REAL_CHECK("h", 1, "d", "u", "p", data_only=True, schema_only=True)
    assert res["success"] is False and "mutually exclusive" in res["error"]


# --------------------------------------------------------------------------
# tables / schemas
# --------------------------------------------------------------------------
def test_table_without_select_full_mode(db):
    db.data["relations"] = [rel("billing", "invoices", can_select=False, owner="bill_owner"),
                            rel("billing", "ok1"), rel("billing", "ok2")]
    db.data["schemas"] = [schema("billing")]
    res = run()
    assert res["success"] and not res["ok"]
    assert kinds(res) == [("table_select", "billing", "invoices")]
    issue = res["issues"][0]
    assert issue["severity"] == "error" and issue["owner"] == "bill_owner"
    assert issue["object_type"] == "table"
    # PG16: lockable (can_lock) but unreadable -> only its data is excluded
    assert res["exclusions"]["tables"] == []
    assert res["exclusions"]["table_data"] == [["billing", "invoices"]]
    assert res["can_exclude"] is True and res["can_exclude_reason"] is None
    fix = res["fix_sql"]
    assert 'GRANT SELECT ON TABLE "billing"."invoices" TO "app_backup";' in fix
    assert "ALL TABLES" not in fix and "GRANT USAGE" not in fix
    assert ('ALTER DEFAULT PRIVILEGES FOR ROLE "bill_owner" IN SCHEMA "billing" '
            'GRANT SELECT ON TABLES TO "app_backup";') in fix
    assert "never executes" in fix
    assert res["summary"]["by_schema"] == [{"schema": "billing", "count": 1}]


def test_schema_without_usage(db):
    db.data["schemas"] = [schema("public"), schema("audit", usage=False, owner="aud")]
    db.data["relations"] = [rel("public", "a"), rel("audit", "log", can_select=False)]
    res = run()
    assert kinds(res) == [("schema_usage", "audit", "audit"), ("table_select", "audit", "log")]
    assert res["issues"][0]["kind"] == "schema_usage"  # sorted by kind order within schema
    assert res["exclusions"]["schemas"] == ["audit"]
    # tables in an excluded schema are not listed again
    assert res["exclusions"]["tables"] == []
    assert 'GRANT USAGE ON SCHEMA "audit" TO "app_backup";' in res["fix_sql"]
    assert res["can_exclude"] is True


def test_schema_without_usage_but_nothing_to_read_is_fine(db):
    db.data["schemas"] = [schema("public"), schema("funcs_only", usage=False)]
    db.data["relations"] = [rel("public", "a")]
    assert run()["ok"]


def test_majority_affected_uses_grant_all(db):
    db.data["relations"] = [rel("s", f"t{i}", can_select=False) for i in range(4)] + [rel("s", "ok")]
    db.data["schemas"] = [schema("s")]
    res = run()
    assert 'GRANT SELECT ON ALL TABLES IN SCHEMA "s" TO "app_backup";' in res["fix_sql"]
    assert "GRANT SELECT ON TABLE \"" not in res["fix_sql"]


def test_identifiers_are_quoted_safely(db):
    db.data["role"] = [role(role_name='we"ird')]
    db.data["schemas"] = [schema('My"Schema')]
    db.data["relations"] = [rel('My"Schema', 'Tab"le', can_select=False, owner='o"wn')]
    fix = run()["fix_sql"]
    assert 'GRANT SELECT ON TABLE "My""Schema"."Tab""le" TO "we""ird";' in fix
    assert 'FOR ROLE "o""wn"' in fix


# --------------------------------------------------------------------------
# modes / lock privileges
# --------------------------------------------------------------------------
@pytest.mark.parametrize("version,expected", [
    (120010, "SELECT"),
    (150004, "SELECT"),
    (160004, "SELECT, INSERT, UPDATE, DELETE, TRUNCATE"),
    (170002, "SELECT, INSERT, UPDATE, DELETE, TRUNCATE, MAINTAIN"),
])
def test_lock_privileges_by_version(db, version, expected):
    db.data["role"] = [role(server_version_num=version)]
    run()
    (_, params), = db.sql_for("relations")
    assert params["lock_privs"] == expected


def test_schema_only_needs_lock_not_select(db):
    db.data["relations"] = [rel("public", "a", can_select=False, can_lock=True),
                            rel("public", "s", "S", can_select=False)]
    res = run(schema_only=True)
    assert res["ok"]
    assert not db.sql_for("lo_count")  # LOs are data: never read in schema-only


def test_schema_only_lock_failure(db):
    db.data["relations"] = [rel("public", "a", can_select=False, can_lock=False), rel("public", "b")]
    res = run(schema_only=True)
    assert kinds(res) == [("table_lock", "public", "a")]
    assert "LOCK TABLE" in res["issues"][0]["message"]
    assert 'GRANT SELECT ON TABLE "public"."a"' in res["fix_sql"]


def test_select_and_lock_failure_reported_once(db):
    db.data["relations"] = [rel("public", "a", can_select=False, can_lock=False), rel("public", "b")]
    res = run()
    assert kinds(res) == [("table_select", "public", "a")]
    assert "nor lock" in res["issues"][0]["message"]


def test_unlogged_table_needs_lock_only(db):
    db.data["relations"] = [rel("public", "u", relpersistence="u", can_select=False)]
    assert run()["ok"]


def test_partitioned_parent_has_no_data(db):
    db.data["relations"] = [rel("public", "p", "p", can_select=False, can_lock=True)]
    assert run()["ok"]


# --------------------------------------------------------------------------
# sequences
# --------------------------------------------------------------------------
def test_owned_sequence_without_select(db):
    t = rel("public", "orders")
    s = rel("public", "orders_id_seq", "S", can_select=False, owned_by=t["oid"], owned_deptype="a")
    db.data["relations"] = [t, s, rel("public", "x")]
    res = run()
    assert kinds(res) == [("sequence_select", "public", "orders_id_seq")]
    ex = res["exclusions"]
    assert ex["tables"] == []   # --exclude-table has no effect on an owned sequence
    assert ex["table_data"] == [["public", "orders_id_seq"]]
    assert 'GRANT SELECT ON SEQUENCE "public"."orders_id_seq" TO "app_backup";' in res["fix_sql"]
    assert "GRANT SELECT ON SEQUENCES TO" in res["fix_sql"]


def test_sequence_ignored_in_schema_only(db):
    db.data["relations"] = [rel("public", "s", "S", can_select=False)]
    assert run(schema_only=True)["ok"]


def test_owned_sequence_follows_table_even_outside_selected_schema(db):
    db.data["schemas"] = [schema("app"), schema("seqs")]
    t = rel("app", "orders")
    s = rel("seqs", "orders_id_seq", "S", can_select=False, owned_by=t["oid"], owned_deptype="a")
    db.data["relations"] = [t, s]
    res = run(schemas=["app"])
    assert kinds(res) == [("sequence_select", "seqs", "orders_id_seq")]


def test_identity_sequence_dropped_with_its_table(db):
    t = rel("public", "orders")
    s = rel("public", "orders_id_seq", "S", can_select=False, owned_by=t["oid"], owned_deptype="i")
    db.data["relations"] = [t, s]
    assert run(exclude_table="public.orders")["ok"]


def test_sequence_data_excluded(db):
    db.data["relations"] = [rel("public", "s1", "S", can_select=False)]
    assert run(exclude_table_data="public.s*")["ok"]


# --------------------------------------------------------------------------
# RLS
# --------------------------------------------------------------------------
@pytest.mark.parametrize("is_owner,force,bypass,expect_issue", [
    (False, False, False, True),
    (True, False, False, False),
    (True, True, False, True),
    (False, False, True, False),
])
def test_rls(db, is_owner, force, bypass, expect_issue):
    db.data["role"] = [role(bypass_rls=bypass, server_version_num=130000)]
    db.data["relations"] = [rel("public", "secret", rowsecurity=True, is_owner=is_owner,
                                forcerowsecurity=force), rel("public", "other")]
    res = run()
    assert (("rls", "public", "secret") in kinds(res)) is expect_issue
    if expect_issue:
        assert 'ALTER ROLE "app_backup" BYPASSRLS;' in res["fix_sql"]
        assert "verify on your platform" in res["fix_sql"]
        # SELECT granted -> lockable: keep the table, skip only its rows
        assert res["exclusions"]["tables"] == []
        assert res["exclusions"]["table_data"] == [["public", "secret"]]
        assert "--enable-row-security" in res["fix_sql"] and "FORCE ROW LEVEL SECURITY" in res["fix_sql"]
        assert "pg_read_all_data" not in res["fix_sql"]  # PG13: not offered


def test_rls_not_checked_in_schema_only(db):
    db.data["relations"] = [rel("public", "secret", rowsecurity=True)]
    assert run(schema_only=True)["ok"]


def test_pg_read_all_data_alternative_on_pg14(db):
    db.data["role"] = [role(server_version_num=140005)]
    db.data["relations"] = [rel("public", "a", can_select=False), rel("public", "b")]
    fix = run()["fix_sql"]
    assert '-- GRANT pg_read_all_data TO "app_backup";' in fix
    assert "NOT bypass row-level security" in fix


# --------------------------------------------------------------------------
# selection: patterns, schemas, extensions
# --------------------------------------------------------------------------
def test_exclude_table_qualified_pattern(db):
    db.data["schemas"] = [schema("billing")]
    db.data["relations"] = [rel("billing", "inv_2020", can_select=False, can_lock=False),
                            rel("billing", "keep")]
    res = run(exclude_table="Billing.INV_*")  # unquoted -> folded to lower case
    assert res["ok"]
    (_, params), = db.sql_for("relations")
    assert params["need_vis"] is False


def test_exclude_table_unqualified_uses_visibility(db):
    db.data["schemas"] = [schema("public"), schema("other")]
    db.data["relations"] = [rel("public", "tmp1", can_select=False, visible=True),
                            rel("other", "tmp2", can_select=False, visible=False)]
    res = run(exclude_table="tmp?")
    (_, params), = db.sql_for("relations")
    assert params["need_vis"] is True
    assert kinds(res) == [("table_select", "other", "tmp2")]


def test_exclude_table_data_keeps_lock(db):
    db.data["relations"] = [rel("public", "big", can_select=False, can_lock=False),
                            rel("public", "ok")]
    res = run(exclude_table_data="public.big")
    assert kinds(res) == [("table_lock", "public", "big")]


def test_exclude_schema_pattern(db):
    db.data["schemas"] = [schema("public"), schema("audit_2020", usage=False)]
    db.data["relations"] = [rel("public", "a"), rel("audit_2020", "x", can_select=False)]
    assert run(exclude_schema="audit_*")["ok"]


def test_schemas_list_limits_scope(db):
    db.data["schemas"] = [schema("app"), schema("hidden", usage=False)]
    db.data["relations"] = [rel("app", "a"), rel("hidden", "h", can_select=False)]
    assert run(schemas=["APP"])["ok"]  # folded to lower case like pg_dump


def test_all_selected_schemas_inaccessible_cannot_exclude(db):
    db.data["schemas"] = [schema("app", usage=False), schema("other")]
    db.data["relations"] = [rel("app", "a"), rel("other", "o")]
    res = run(schemas=["app"], large_objects=False)
    assert kinds(res) == [("schema_usage", "app", "app")]
    assert res["can_exclude"] is False


def test_nothing_left_cannot_exclude(db):
    db.data["relations"] = [rel("public", "a", can_select=False), rel("public", "b", can_select=False)]
    res = run()
    assert not res["ok"] and res["can_exclude"] is False
    assert len(res["exclusions"]["table_data"]) == 2
    assert "No table data" in res["can_exclude_reason"]


def test_nothing_left_pg15_whole_tables(db):
    # PG <= 15: ACCESS SHARE needs SELECT, so no SELECT also means no LOCK
    db.data["role"] = [role(server_version_num=150004)]
    db.data["relations"] = [rel("public", "a", can_select=False, can_lock=False),
                            rel("public", "b", can_select=False, can_lock=False)]
    res = run(schema_only=True)
    assert res["exclusions"]["tables"] == [["public", "a"], ["public", "b"]]
    assert res["can_exclude"] is False and "No table" in res["can_exclude_reason"]


def test_extension_members_skipped_but_config_data_checked(db):
    db.data["relations"] = [
        rel("public", "ext_internal", ext_member=True, can_select=False, can_lock=False),
        rel("public", "ext_cfg", ext_member=True, ext_config=True, can_select=False, can_lock=False),
        rel("public", "a"),
    ]
    res = run()
    assert kinds(res) == [("table_select", "public", "ext_cfg")]
    # with --schema the extension itself is not dumped, but its config table
    # data still is when the table's schema is selected
    assert kinds(run(schemas=["public"])) == [("table_select", "public", "ext_cfg")]
    assert run(schema_only=True)["ok"]


# --------------------------------------------------------------------------
# inheritance / partitions
# --------------------------------------------------------------------------
def test_unlockable_partition_blocks_parent_and_excludes_tree(db):
    db.data["role"] = [role(server_version_num=120022)]   # PG 12: children ACL-checked
    parent = rel("public", "events", "p", has_children=True)
    p1 = rel("public", "events_2024", can_select=False, can_lock=False)
    p2 = rel("public", "events_2025")
    other = rel("public", "users")
    db.data["relations"] = [parent, p1, p2, other]
    db.data["inherits"] = [inh(p1, parent), inh(p2, parent)]
    res = run()
    assert kinds(res) == [("table_lock", "public", "events"),
                          ("table_select", "public", "events_2024")]
    assert "events_2024" in [i for i in res["issues"] if i["object"] == "events"][0]["message"]
    assert res["exclusions"]["tables"] == [["public", "events"], ["public", "events_2024"],
                                           ["public", "events_2025"]]
    # the parent is not a root cause: no GRANT on it
    assert '"public"."events" ' not in res["fix_sql"] and '"public"."events",' not in res["fix_sql"]
    assert res["can_exclude"] is True


def test_inherits_not_queried_without_children(db):
    db.data["relations"] = [rel("public", "a", can_select=False, can_lock=True), rel("public", "b")]
    run()
    assert not db.sql_for("inherits")


# --------------------------------------------------------------------------
# large objects
# --------------------------------------------------------------------------
def test_large_objects_unreadable(db):
    db.data["relations"] = [rel("public", "a")]
    db.data["lo_count"] = [{"total": 10}]
    db.data["lo_sample"] = [{"oid": 16501, "owner": "lo_owner"}, {"oid": 16500, "owner": "lo_owner"}]
    res = run()
    assert kinds(res) == [("large_object", None, "2 large object(s)")]
    assert "2 of 10" in res["issues"][0]["message"]
    assert res["exclusions"]["large_objects"] is True and res["can_exclude"] is True
    assert 'GRANT SELECT ON LARGE OBJECT 16500 TO "app_backup";' in res["fix_sql"]
    # totals: plain count, no ACL evaluation; detection: one bounded scan
    (count_sql, _), = db.sql_for("lo_count")
    assert "aclexplode" not in count_sql and "FILTER" not in count_sql
    (sample_sql, _), = db.sql_for("lo_sample")
    assert "aclexplode" in sample_sql and "has_largeobject_privilege" not in sample_sql
    assert f"LIMIT {pc._LO_SAMPLE + 1}" in sample_sql


def test_large_objects_none_skips_acl_scan(db):
    db.data["lo_count"] = [{"total": 0}]
    assert run()["ok"]
    assert not db.sql_for("lo_sample")


def test_large_objects_many_are_commented_samples(db):
    db.data["lo_count"] = [{"total": 100}]
    db.data["lo_sample"] = [{"oid": 20000 + i, "owner": "o"} for i in range(21)]
    res = run()
    fix = res["fix_sql"]
    assert "-- GRANT SELECT ON LARGE OBJECT 20000" in fix and "-- ... and more" in fix
    assert "-- GRANT SELECT ON LARGE OBJECT 20020" not in fix  # only the first 20
    assert "\nGRANT SELECT ON LARGE OBJECT" not in fix
    assert res["issues"][0]["message"].startswith("More than 20 of 100")


def test_large_objects_pg18_uses_builtin(db):
    db.data["role"] = [role(server_version_num=180000)]
    db.data["lo_count"] = [{"total": 3}]
    run()
    (sql, _), = db.sql_for("lo_sample")
    assert "has_largeobject_privilege" in sql and "aclexplode" not in sql


@pytest.mark.parametrize("kw,queried", [
    ({}, True),
    ({"schemas": ["public"], "large_objects": False}, False),
    ({"schemas": ["public"], "large_objects": True}, True),
    ({"large_objects": False}, True),   # include-everything dump still has LOs
    ({"schema_only": True}, False),
    ({"data_only": True}, True),
])
def test_large_objects_dump_rules(db, kw, queried):
    run(**kw)
    assert bool(db.sql_for("lo_count")) is queried


def test_lo_compat_privileges_skips_lo_check(db):
    db.data["role"] = [role(lo_compat_privileges="on")]
    assert run()["ok"]
    assert not db.sql_for("lo_count")


# --------------------------------------------------------------------------
# errors / connection
# --------------------------------------------------------------------------
def test_connection_error_never_raises_nor_leaks_password(db):
    db.connect_error = RuntimeError(f"could not connect: password {PASSWORD} rejected")
    res = run()
    assert res["success"] is False and res["ok"] is False
    assert PASSWORD not in res["error"] and "Connection failed" in res["error"]


def test_connect_denied_reported_as_issue(db):
    db.connect_error = RuntimeError('FATAL:  permission denied for database "appdb"\n'
                                    "DETAIL:  User does not have CONNECT privilege.")
    res = run()
    assert res["success"] is True and res["ok"] is False
    assert kinds(res) == [("database_connect", None, "appdb")]
    assert res["can_exclude"] is False
    assert 'GRANT CONNECT ON DATABASE "appdb" TO "app_backup";' in res["fix_sql"]


def test_no_connect_privilege_after_connect(db):
    db.data["role"] = [role(can_connect=False)]
    db.data["relations"] = [rel("public", "a", can_select=False), rel("public", "b")]
    res = run()
    assert ("database_connect", None, "appdb") in kinds(res)
    assert res["can_exclude"] is False


def test_query_failure_returns_error_and_closes(db):
    db.fail_on = "magikup:relations"
    res = run()
    assert res["success"] is False and "statement timeout" in res["error"]
    assert db.closed


def test_truncation_keeps_full_counts(db):
    db.data["relations"] = [rel("s", f"t{i:02d}", can_select=False) for i in range(30)]
    db.data["schemas"] = [schema("s")]
    res = run(max_issues=5)
    assert len(res["issues"]) == 5 and res["truncated"] is True
    assert res["summary"]["issues_total"] == 30 and res["summary"]["by_kind"]["table_select"] == 30
    assert [i["object"] for i in res["issues"]] == ["t00", "t01", "t02", "t03", "t04"]
    assert len(res["exclusions"]["table_data"]) == 30  # never truncated


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def test_quote_dump_pattern():
    assert pc.quote_dump_pattern("public") == '"public"'
    assert pc.quote_dump_pattern("My", 'we"ird*') == '"My"."we""ird*"'


@pytest.mark.parametrize("pattern,nsp,name,visible,expected", [
    ("public.t*", "public", "tab", None, True),
    ("public.t*", "other", "tab", None, False),
    ("t?b", "x", "tab", True, True),
    ("t?b", "x", "tab", False, False),
    ("PUBLIC.TAB", "public", "tab", None, True),
    ("appdb.public.tab", "public", "tab", None, True),
    ("a-b.c", "a-b", "c", None, True),
    ("public.", "public", "anything", None, True),
    ('"My"."T*"', "My", "T*", None, True),
    ('"My"."T*"', "My", "Tx", None, False),
])
def test_rel_pattern(pattern, nsp, name, visible, expected):
    assert pc._RelPattern(pattern, "appdb").matches(nsp, name, visible) is expected


def test_quoted_pattern_roundtrip():
    pat = pc.quote_dump_pattern('S"c.h', "t.a*b")
    assert pc._RelPattern(pat, "db").matches('S"c.h', "t.a*b", None)
    assert not pc._RelPattern(pat, "db").matches('S"c.h', "t.aXb", None)


def test_format_issue_summary(db):
    db.data["relations"] = [rel("billing", "invoices", can_select=False), rel("billing", "x")]
    db.data["schemas"] = [schema("billing")]
    res = run()
    text = pc.format_issue_summary(res, max_lines=1)
    assert "app_backup" in text and "table_select=1" in text and "billing=1" in text
    assert "billing.invoices" in text and "GRANT SELECT" in text
    assert pc.format_issue_summary({"success": False, "error": "boom"}).endswith("boom")
    assert "passed" in pc.format_issue_summary({"success": True, "ok": True, "current_user": "u"})
    # tolerant to sparse dicts (e.g. test stubs)
    assert pc.format_issue_summary({"success": True, "ok": False, "summary": {}, "issues": []})


# --------------------------------------------------------------------------
# fix SQL injection safety (names are attacker-controllable)
# --------------------------------------------------------------------------
import re as _re

_IDENT = _re.compile(r'(?:U&)?"(?:[^"]|"")*"')


def _decode_ident(tok):
    """Inverse of pc._qi for one quoted identifier token."""
    uni = tok.startswith("U&")
    body = tok[3:-1] if uni else tok[1:-1]
    body = body.replace('""', '"')
    if not uni:
        return body
    out, i = [], 0
    while i < len(body):
        if body[i] == "\\":
            if body[i + 1] == "\\":
                out.append("\\"); i += 2
            elif body[i + 1] == "+":
                out.append(chr(int(body[i + 2:i + 8], 16))); i += 8
            else:
                out.append(chr(int(body[i + 1:i + 5], 16))); i += 5
        else:
            out.append(body[i]); i += 1
    return "".join(out)


def _assert_fix_sql_safe(fix):
    for bad in ("\r", " ", " ", "\x85", "‮"):
        assert bad not in fix
    for line in fix.split("\n"):
        if not line or line.startswith("--"):
            continue
        rest = _IDENT.sub("X", line)
        assert _re.fullmatch(r"[A-Z0-9_ ,;.()X]*", rest), line
        assert rest.endswith(";"), line


EVIL_ROLE = 'r ole"\n; DROP ROLE x; --'
EVIL_SCHEMA = 'ev"il\nGRANT ALL ON ALL TABLES IN SCHEMA public TO PUBLIC; --'
EVIL_SCHEMA2 = "pub\r\nx\\y"
EVIL_TABLE = "t\nDROP TABLE y; --"
EVIL_RLS = "sec ret‮"


def test_fix_sql_never_lets_a_name_escape(db):
    db.data["role"] = [role(role_name=EVIL_ROLE)]
    db.data["schemas"] = [schema(EVIL_SCHEMA, usage=False), schema(EVIL_SCHEMA2)]
    db.data["relations"] = [
        rel(EVIL_SCHEMA, "a"),
        rel(EVIL_SCHEMA2, EVIL_TABLE, can_select=False, owner="o\nwn"),
        rel(EVIL_SCHEMA2, EVIL_RLS, rowsecurity=True),
        rel(EVIL_SCHEMA2, "ok"),
    ]
    db.data["lo_count"] = [{"total": 2}]
    db.data["lo_sample"] = [{"oid": 16500, "owner": "x\ny"}]
    res = run()
    fix = res["fix_sql"]
    _assert_fix_sql_safe(fix)
    # every identifier token round-trips to a real name
    idents = {_decode_ident(t) for t in _IDENT.findall(fix)}
    assert {EVIL_ROLE, EVIL_SCHEMA, EVIL_SCHEMA2, EVIL_TABLE, EVIL_RLS, "o\nwn"} <= idents
    assert ("GRANT SELECT ON TABLE " + pc._qn(EVIL_SCHEMA2, EVIL_TABLE)
            + " TO " + pc._qi(EVIL_ROLE) + ";") in fix
    # summaries for logs/emails stay one line per issue
    text = pc.format_issue_summary(res, max_lines=50)
    issue_lines = [ln for ln in text.split("\n") if ln.startswith("  [")]
    assert len(issue_lines) == res["summary"]["issues_total"]
    assert "\r" not in text and " " not in text and " " not in text


def test_connect_denied_fix_is_safe(db):
    db.connect_error = RuntimeError('permission denied for database "x"')
    res = REAL_CHECK("h", 1, "db\nDROP DATABASE x;", EVIL_ROLE, PASSWORD)
    _assert_fix_sql_safe(res["fix_sql"])


def test_qi_plain_names_unchanged():
    assert pc._qi('a"b') == '"a""b"'
    assert pc._qi("a\nb") == 'U&"a\\000Ab"'
    assert pc._qi("a\\b\n") == 'U&"a\\\\b\\000A"'
    assert _decode_ident(pc._qi("x\U0001F600 \\")) == "x\U0001F600 \\"
    # pg_dump patterns (argv, not SQL) keep the raw name
    assert pc.quote_dump_pattern("a\nb", "c") == '"a\nb"."c"'


# --------------------------------------------------------------------------
# LOCK TABLE recursion into descendants that are not dumped
# --------------------------------------------------------------------------
def _foreign_child(nsp, name, can_lock=False):
    pc_oid = rel(nsp, name, "f")  # only used for oid/name; foreign tables are not in "relations"
    pc_oid["can_lock"] = can_lock
    return pc_oid


def test_lock_recurses_into_unlockable_foreign_partition(db):
    db.data["role"] = [role(server_version_num=120022)]
    parent = rel("public", "events", "p", has_children=True)
    local = rel("public", "events_2025")
    remote = _foreign_child("public", "events_2024_remote")
    other = rel("public", "users")
    db.data["relations"] = [parent, local, other]
    db.data["inherits"] = [inh(local, parent), inh(remote, parent)]
    res = run()
    assert kinds(res) == [("table_lock", "public", "events")]
    assert "events_2024_remote" in res["issues"][0]["message"]
    # the foreign partition goes too: CREATE FOREIGN TABLE ... PARTITION OF
    # "events" would fail at restore time without its parent
    assert res["exclusions"]["tables"] == [["public", "events"], ["public", "events_2024_remote"],
                                           ["public", "events_2025"]]
    assert 'GRANT SELECT ON TABLE "public"."events_2024_remote" TO "app_backup";' in res["fix_sql"]
    assert res["can_exclude"] is True
    (_, params), = db.sql_for("inherits")
    assert params["lock_privs"] == "SELECT"


def test_lock_recurses_into_child_outside_selection(db):
    db.data["role"] = [role(server_version_num=120022)]
    db.data["schemas"] = [schema("app"), schema("archive", usage=False)]
    parent = rel("app", "log", has_children=True)
    child = rel("archive", "log_old", can_select=False, can_lock=False)
    excluded = rel("app", "log_tmp", can_select=False, can_lock=False)
    db.data["relations"] = [parent, child, excluded, rel("app", "ok")]
    db.data["inherits"] = [inh(child, parent), inh(excluded, parent)]
    # child in a non-selected schema (no USAGE needed: recursion is by OID),
    # sibling excluded by the user: both are still locked through the parent
    res = run(schemas=["app"], exclude_table="app.log_tmp")
    assert kinds(res) == [("table_lock", "app", "log")]
    msg = res["issues"][0]["message"]
    assert "archive.log_old" in msg and "app.log_tmp" in msg
    assert res["exclusions"]["schemas"] == []
    assert res["exclusions"]["tables"] == [["app", "log"]]
    assert '"archive"."log_old"' in res["fix_sql"] and '"app"."log_tmp"' in res["fix_sql"]


def test_multiple_inheritance_does_not_exclude_other_parent(db):
    db.data["role"] = [role(server_version_num=120022)]
    a = rel("public", "a", has_children=True)
    b = rel("public", "b", has_children=True)
    c = rel("public", "c")                       # INHERITS (a, b)
    d = rel("public", "d", can_lock=False)       # INHERITS (a), SELECT ok but not lockable?
    d["can_select"] = True
    db.data["relations"] = [a, b, c, d]
    db.data["inherits"] = [inh(c, a), inh(c, b), inh(d, a)]
    res = run()
    assert kinds(res) == [("table_lock", "public", "a"), ("table_lock", "public", "d")]
    # a recurses into d; c cannot be restored without a; b only loses child c
    assert res["exclusions"]["tables"] == [["public", "a"], ["public", "c"], ["public", "d"]]


def test_deep_descendant_blocks_every_dumped_ancestor(db):
    db.data["role"] = [role(server_version_num=120022)]
    top = rel("public", "top", "p", has_children=True)
    mid = rel("public", "mid", "p", has_children=True)
    leaf = _foreign_child("public", "leaf")
    db.data["relations"] = [top, mid, rel("public", "keep")]
    db.data["inherits"] = [inh(mid, top), inh(leaf, mid)]
    res = run()
    assert kinds(res) == [("table_lock", "public", "mid"), ("table_lock", "public", "top")]
    assert res["exclusions"]["tables"] == [["public", "leaf"], ["public", "mid"], ["public", "top"]]


def test_child_of_table_in_excluded_schema_is_excluded(db):
    db.data["schemas"] = [schema("public"), schema("audit", usage=False)]
    parent = rel("audit", "events", "p", has_children=True)
    part = rel("public", "events_1")
    db.data["relations"] = [parent, part, rel("public", "keep")]
    db.data["inherits"] = [inh(part, parent)]
    res = run()
    assert res["exclusions"]["schemas"] == ["audit"]
    # the partition cannot be restored without its parent
    assert res["exclusions"]["tables"] == [["public", "events_1"]]


# --------------------------------------------------------------------------
# data-only exclusions (item: keep restorable definitions)
# --------------------------------------------------------------------------
def test_pg16_insert_only_table_keeps_definition(db):
    # PG16+: INSERT allows ACCESS SHARE, so the table is locked/defined but unreadable
    db.data["relations"] = [rel("public", "inbox", can_select=False, can_lock=True),
                            rel("public", "users")]
    res = run()
    assert kinds(res) == [("table_select", "public", "inbox")]
    assert res["exclusions"]["tables"] == []
    assert res["exclusions"]["table_data"] == [["public", "inbox"]]


def test_select_and_lock_fail_excludes_whole_table(db):
    db.data["role"] = [role(server_version_num=150004)]
    db.data["relations"] = [rel("public", "inbox", can_select=False, can_lock=False),
                            rel("public", "users")]
    res = run()
    assert res["exclusions"]["tables"] == [["public", "inbox"]]
    assert res["exclusions"]["table_data"] == []


def test_owned_sequence_in_unselected_schema_without_usage(db):
    db.data["schemas"] = [schema("app"), schema("seqs", usage=False)]
    t = rel("app", "orders")
    s = rel("seqs", "orders_id_seq", "S", owned_by=t["oid"], owned_deptype="a")
    db.data["relations"] = [t, s, rel("app", "x")]
    res = run(schemas=["app"], large_objects=False)
    assert kinds(res) == [("schema_usage", "seqs", "seqs")]
    # "seqs" is not a --schema entry: excluding it would do nothing
    assert res["exclusions"]["schemas"] == []
    assert res["exclusions"]["table_data"] == [["seqs", "orders_id_seq"]]
    assert res["can_exclude"] is True


# --------------------------------------------------------------------------
# extensions
# --------------------------------------------------------------------------
def test_extension_config_sequence_data_checked(db):
    db.data["relations"] = [
        rel("public", "ext_seq", "S", ext_member=True, ext_user_member=True,
            ext_config=True, can_select=False),
        rel("public", "ext_internal_seq", "S", ext_member=True, ext_user_member=True,
            can_select=False),
        rel("public", "a"),
    ]
    res = run()
    assert kinds(res) == [("sequence_select", "public", "ext_seq")]
    assert res["exclusions"]["table_data"] == [["public", "ext_seq"]]
    # pg_dump reads config sequence values even with --schema-only
    so = run(schema_only=True)
    assert kinds(so) == [("sequence_select", "public", "ext_seq")]
    assert so["exclusions"]["table_data"] == [["public", "ext_seq"]]
    assert run(exclude_table_data="public.ext_seq")["ok"]


def test_extension_config_table_data_excluded_not_table(db):
    db.data["relations"] = [
        rel("public", "ext_cfg", ext_member=True, ext_user_member=True, ext_config=True,
            can_select=False, can_lock=True),
        rel("public", "a"),
    ]
    res = run()
    assert res["exclusions"]["tables"] == []
    assert res["exclusions"]["table_data"] == [["public", "ext_cfg"]]


def test_extension_member_lock_is_warning_only(db):
    # Current pg_dump minors never lock extension members (verified on PG 12-17
    # with pg_dump 15-17, RLS + policy on the member table included).
    db.data["schemas"] = [schema("public"), schema("cron")]
    db.data["relations"] = [
        rel("cron", "job", ext_member=True, ext_user_member=True, can_select=False,
            can_lock=False, rowsecurity=True, has_policies=True),
        rel("public", "a"),
    ]
    res = run()
    assert kinds(res) == [("table_lock", "cron", "job")]
    issue = res["issues"][0]
    assert issue["severity"] == "warning" and "cannot be excluded" in issue["message"]
    assert res["ok"] is True
    assert res["can_exclude"] is False and res["can_exclude_reason"] is None
    assert 'GRANT SELECT ON TABLE "cron"."job" TO "app_backup";' in res["fix_sql"]
    assert 'FOR ROLE "owner" IN SCHEMA "cron"' not in res["fix_sql"]
    # --schema: extensions are not dumped, nothing reported
    assert run(schemas=["public"])["issues"] == []
    # exclusion switches do not remove extension members: still a warning
    assert kinds(run(exclude_schema="cron")) == [("table_lock", "cron", "job")]


def test_extension_member_lock_without_policies_is_warning(db):
    db.data["relations"] = [
        rel("public", "ext_t", ext_member=True, ext_user_member=True, can_select=False,
            can_lock=False),
        rel("public", "a"),
    ]
    res = run()
    assert res["ok"] is True
    assert [i["severity"] for i in res["issues"]] == ["warning"]
    assert res["summary"]["warnings"] == 1 and res["summary"]["errors"] == 0


def test_builtin_extension_members_never_locked(db):
    db.data["relations"] = [rel("public", "ext_t", ext_member=True, ext_user_member=False,
                                can_select=False, can_lock=False, has_policies=True),
                            rel("public", "a")]
    assert run()["ok"]


def test_extension_member_in_schema_without_usage(db):
    db.data["schemas"] = [schema("public"), schema("ext", usage=False)]
    db.data["relations"] = [rel("ext", "t", ext_member=True, ext_user_member=True,
                                rowsecurity=True, has_policies=True), rel("public", "a")]
    res = run()
    assert kinds(res) == [("table_lock", "ext", "t")]
    assert "USAGE" in res["issues"][0]["message"]
    assert 'GRANT USAGE ON SCHEMA "ext" TO "app_backup";' in res["fix_sql"]


# --------------------------------------------------------------------------
# exclusion scaling
# --------------------------------------------------------------------------
def test_many_exclusions_collapse_to_schema(db):
    db.data["role"] = [role(server_version_num=150004)]
    db.data["schemas"] = [schema("public"), schema("big")]
    db.data["relations"] = [rel("big", f"t{i}", can_select=False, can_lock=False)
                            for i in range(pc.MAX_EXCLUSION_PATTERNS + 1)] + [rel("public", "ok")]
    res = run()
    ex = res["exclusions"]
    assert ex["schemas"] == ["big"] and ex["tables"] == [] and ex["table_data"] == []
    assert ex["collapsed_schemas"] == ["big"]
    assert res["can_exclude"] is True


def test_few_exclusions_are_not_collapsed(db):
    db.data["role"] = [role(server_version_num=150004)]
    db.data["schemas"] = [schema("public"), schema("big")]
    db.data["relations"] = [rel("big", f"t{i}", can_select=False, can_lock=False)
                            for i in range(3)] + [rel("public", "ok")]
    ex = run()["exclusions"]
    assert ex["schemas"] == [] and len(ex["tables"]) == 3 and "collapsed_schemas" not in ex


def test_too_many_exclusions_refused(db):
    db.data["role"] = [role(server_version_num=150004)]
    db.data["schemas"] = [schema("public"), schema("big")]
    db.data["relations"] = [rel("big", f"t{i}", can_select=False, can_lock=False)
                            for i in range(pc.MAX_EXCLUSION_PATTERNS + 1)] + \
        [rel("big", "readable"), rel("public", "ok")]
    res = run()
    assert res["exclusions"]["schemas"] == []  # "big" still has a readable table
    assert res["can_exclude"] is False and "Too many" in res["can_exclude_reason"]


# --------------------------------------------------------------------------
# patterns pg_dump would reject
# --------------------------------------------------------------------------
@pytest.mark.parametrize("kw,needle", [
    ({"exclude_table": "a.b.c.d"}, "too many dotted names"),
    ({"exclude_table_data": "otherdb.public.t"}, "cross-database"),
    ({"exclude_schema": "otherdb.s"}, "cross-database"),
    ({"exclude_schema": "a.b.c"}, "too many dotted names"),
    ({"schemas": ["x.y.z"]}, "too many dotted names"),
])
def test_invalid_patterns_fail_clearly(db, kw, needle):
    res = run(**kw)
    assert res["success"] is False and needle in res["error"]
    assert "pg_dump would reject" in res["error"]


def test_invalid_pattern_reported_for_superuser_too(db):
    db.data["role"] = [role(is_superuser=True)]
    assert run(exclude_table="x.public.t")["success"] is False


def test_same_database_prefix_accepted(db):
    db.data["relations"] = [rel("public", "t", can_select=False), rel("public", "u")]
    assert run(exclude_table="appdb.public.t")["ok"]


# --------------------------------------------------------------------------
# misc
# --------------------------------------------------------------------------
def test_connect_denied_by_sqlstate(db):
    class OpErr(Exception):
        pgcode = "42501"
    db.connect_error = OpErr('FATAL:  accès refusé pour la base de données « appdb »')
    res = run()
    assert res["success"] is True and kinds(res) == [("database_connect", None, "appdb")]
    assert res["can_exclude"] is False and res["can_exclude_reason"]


def test_column_level_select_accepted_in_query(db):
    run()
    (sql, _), = db.sql_for("relations")
    assert "has_column_privilege" in sql and "attgenerated" in sql
    assert "has_policies" in sql and "relhassubclass" in sql


def test_ok_result_has_no_exclusion_reason(db):
    res = run()
    assert res["ok"] and res["can_exclude"] is False and res["can_exclude_reason"] is None


# --------------------------------------------------------------------------
# Regressions found against real PostgreSQL 12/15/16/17 + pg_dump 15/16/17
# (rows mirror the catalog state of the Docker harness scenarios)
# --------------------------------------------------------------------------
def test_pg13_plus_lock_recursion_does_not_check_children(db):
    # s06/s07: from PG 13 LockTableRecurse locks children by OID without an ACL
    # check: only the unreadable partition itself fails, the parent stays.
    db.data["role"] = [role(server_version_num=170012)]
    db.data["schemas"] = [schema("app"), schema("other", usage=False)]
    parted = rel("app", "parted", "p", has_children=True)
    p1 = rel("app", "p1")
    p2 = rel("app", "p2", can_select=False, can_lock=False)
    parted3 = rel("app", "parted3", "p", has_children=True)
    r0 = rel("app", "r0")
    r1 = rel("other", "r1", can_select=False, can_lock=False)   # not selected below
    parted4 = rel("app", "parted4", "p", has_children=True)
    f0 = rel("app", "f0")
    f1 = _foreign_child("app", "f1")                              # postgres_fdw, no grant
    db.data["relations"] = [parted, p1, p2, parted3, r0, r1, parted4, f0]
    db.data["inherits"] = [inh(p1, parted), inh(p2, parted), inh(r0, parted3),
                           inh(r1, parted3), inh(f0, parted4), inh(f1, parted4)]
    res = run(schemas=["app"])
    assert kinds(res) == [("table_select", "app", "p2")]
    assert res["exclusions"]["tables"] == [["app", "p2"]]
    assert res["exclusions"]["schemas"] == []
    assert res["can_exclude"] is True
    assert '"app"."f1"' not in res["fix_sql"] and '"other"."r1"' not in res["fix_sql"]


def test_pg13_plus_inheritance_child_without_privileges(db):
    # s07 on PG 15/16/17: parents of an unreadable child are dumped fine.
    db.data["role"] = [role(server_version_num=150020)]
    parent = rel("app", "parent", has_children=True)
    child = rel("app", "child", can_select=False, can_lock=False)
    pa = rel("app", "pa", has_children=True)
    pb = rel("app", "pb", has_children=True)
    mchild = rel("app", "mchild", can_select=False, can_lock=False)
    db.data["schemas"] = [schema("public"), schema("app")]
    db.data["relations"] = [parent, child, pa, pb, mchild, rel("app", "solo")]
    db.data["inherits"] = [inh(child, parent), inh(mchild, pa), inh(mchild, pb)]
    res = run()
    assert kinds(res) == [("table_select", "app", "child"), ("table_select", "app", "mchild")]
    assert res["exclusions"]["tables"] == [["app", "child"], ["app", "mchild"]]


def test_foreign_partition_of_excluded_parent_is_excluded(db):
    # s06 restore failure: "relation app.parted4 does not exist" while
    # restoring CREATE FOREIGN TABLE app.f1 PARTITION OF app.parted4.
    db.data["role"] = [role(server_version_num=160016)]
    db.data["schemas"] = [schema("public"), schema("app")]
    parted4 = rel("app", "parted4", "p", has_children=True, can_select=False, can_lock=False)
    f0 = rel("app", "f0")
    f1 = _foreign_child("app", "f1", can_lock=True)
    db.data["relations"] = [parted4, f0, rel("app", "solo")]
    db.data["inherits"] = [inh(f0, parted4), inh(f1, parted4)]
    res = run()
    assert kinds(res) == [("table_lock", "app", "parted4")]
    assert res["exclusions"]["tables"] == [["app", "f0"], ["app", "f1"], ["app", "parted4"]]
    # not selected: no pattern for it
    res = run(schemas=["public"])
    assert res["ok"] and res["exclusions"]["tables"] == []


def test_extension_config_table_data_not_read_in_schema_only(db):
    # s09a: with --schema-only pg_dump skips the config table COPY but still
    # reads the config sequences (dumpSequenceData runs eagerly).
    db.data["schemas"] = [schema("public"), schema("app")]
    cfg = rel("app", "mk_cfg", ext_member=True, ext_user_member=True, ext_config=True,
              can_select=False, can_lock=False)
    seq = rel("app", "mk_cfg_id_seq", "S", ext_member=True, ext_user_member=True,
              ext_config=True, can_select=False, owned_by=cfg["oid"], owned_deptype="a")
    db.data["relations"] = [cfg, seq, rel("app", "t")]
    full = run()
    assert ("table_select", "app", "mk_cfg") in kinds(full)
    assert full["exclusions"]["table_data"] == [["app", "mk_cfg"], ["app", "mk_cfg_id_seq"]]
    so = run(schema_only=True)
    assert [k for k in kinds(so) if k[0] != "table_lock"] == [
        ("sequence_select", "app", "mk_cfg_id_seq")]
    assert so["ok"] is False
    assert so["exclusions"]["table_data"] == [["app", "mk_cfg_id_seq"]]


def test_schema_selection_matching_nothing_is_rejected_like_pg_dump(db):
    # s12: --schema UPPER (unquoted) folds to "upper": pg_dump fails with
    # "no matching schemas were found".
    db.data["schemas"] = [schema("public"), schema("UPPER")]
    res = run(schemas=["UPPER"])
    assert res["success"] is False and "no matching schemas" in res["error"]
    assert run(schemas=["UPPER", "public"])["success"] is True
    assert run(schemas=["information_schema"])["success"] is True
