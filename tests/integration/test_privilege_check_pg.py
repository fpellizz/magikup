"""Backup privilege preflight against a real PostgreSQL server (optional).

Skipped unless PG_TEST_DSN is set to a *superuser* libpq DSN (e.g.
``host=localhost port=5432 user=postgres password=... dbname=postgres``) and
the real psycopg2 is installed. Each test creates a throwaway database plus
uniquely named roles and drops them afterwards.

When a pg_dump binary is available (PG_DUMP env var, else ``pg_dump`` on PATH)
the prediction is compared with a real pg_dump run using the flags
app.backup_restore.run_backup builds; if the check proposes exclusions the
partial dump must succeed too.
"""
import os
import shutil
import subprocess
import tempfile
import uuid

import pytest

pytestmark = pytest.mark.integration

psycopg2 = pytest.importorskip("psycopg2")
if not getattr(psycopg2, "__libpq_version__", None):  # local stub, not the real driver
    pytest.skip("real psycopg2 not installed", allow_module_level=True)
DSN = os.environ.get("PG_TEST_DSN")
if not DSN:
    pytest.skip("PG_TEST_DSN not set", allow_module_level=True)

from psycopg2 import sql as psql  # noqa: E402
from psycopg2.extensions import parse_dsn  # noqa: E402

from app import privilege_check as pc  # noqa: E402

# conftest stubs check_backup_privileges for every test: keep the real one.
REAL_CHECK = pc.check_backup_privileges
PW = "pw-" + uuid.uuid4().hex[:12]
PG_DUMP = os.environ.get("PG_DUMP") or shutil.which("pg_dump")
_P = parse_dsn(DSN)
HOST = _P.get("host", "localhost")
PORT = int(_P.get("port", 5432))


def _su(dbname=None):
    kw = dict(_P)
    if dbname:
        kw["dbname"] = dbname
    conn = psycopg2.connect(**kw)
    conn.autocommit = True
    return conn


class Env:
    """A throwaway database with an object owner and a backup login role."""

    def __init__(self):
        sfx = uuid.uuid4().hex[:8]
        self.db = f"mkp_it_{sfx}"
        self.owner = f"mkp_own_{sfx}"
        self.role = f"mkp_bk_{sfx}"
        c = _su()
        try:
            cur = c.cursor()
            cur.execute("SELECT current_setting('server_version_num')::int")
            self.version = cur.fetchone()[0]
            cur.execute(psql.SQL("CREATE ROLE {} NOLOGIN").format(psql.Identifier(self.owner)))
            cur.execute(psql.SQL("CREATE ROLE {} LOGIN PASSWORD %s").format(
                psql.Identifier(self.role)), (PW,))
            cur.execute(psql.SQL("CREATE DATABASE {} OWNER {}").format(
                psql.Identifier(self.db), psql.Identifier(self.owner)))
        finally:
            c.close()
        self.tmp = tempfile.mkdtemp(prefix="mkp-it-")

    def sql(self, text):
        """Run setup SQL as superuser; {own} / {bk} expand to the role names."""
        c = _su(self.db)
        try:
            with c.cursor() as cur:
                cur.execute(text.replace("{own}", f'"{self.owner}"').replace("{bk}", f'"{self.role}"'))
        finally:
            c.close()

    def check(self, **kw):
        return REAL_CHECK(HOST, PORT, self.db, self.role, PW, None, **kw)

    def dump(self, result=None, **kw):
        """pg_dump with run_backup's flags (+ the result's exclusions)."""
        out = os.path.join(self.tmp, uuid.uuid4().hex + ".dump")
        cmd = [PG_DUMP, "--file", out, "--host", HOST, "--port", str(PORT),
               "--username", self.role, "--no-password", "--format=c"]
        if kw.get("data_only"):
            cmd.append("--data-only")
        elif kw.get("schema_only"):
            cmd.append("--schema-only")
        else:
            cmd += ["--section=pre-data", "--section=data", "--section=post-data"]
        ex = (result or {}).get("exclusions") or {}
        if ex.get("large_objects"):
            cmd.append("--no-blobs")
        elif kw.get("large_objects", True):
            cmd.append("--blobs")
        cmd += ["--no-owner", "--no-privileges", "--no-tablespaces", "--no-comments"]
        for s in ex.get("schemas") or []:
            if not kw.get("schemas"):
                cmd += ["--exclude-schema", pc.quote_dump_pattern(s)]
        for s, t in ex.get("tables") or []:
            cmd += ["--exclude-table", pc.quote_dump_pattern(s, t)]
        for s, t in ex.get("table_data") or []:
            cmd += ["--exclude-table-data", pc.quote_dump_pattern(s, t)]
        for s in kw.get("schemas") or []:
            if s not in (ex.get("schemas") or []):
                cmd += ["--schema", s]
        cmd += ["--no-publications", "--no-subscriptions", "--no-security-labels",
                "--no-unlogged-table-data", self.db]
        p = subprocess.run(cmd, capture_output=True, text=True,
                           env=dict(os.environ, PGPASSWORD=PW), timeout=300)
        return p.returncode == 0 and "error:" not in p.stderr.lower(), p.stderr

    def close(self):
        c = _su()
        try:
            cur = c.cursor()
            cur.execute(psql.SQL("DROP DATABASE IF EXISTS {}").format(psql.Identifier(self.db)))
            for r in (self.role, self.owner):
                cur.execute(psql.SQL("DROP ROLE IF EXISTS {}").format(psql.Identifier(r)))
        finally:
            c.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


@pytest.fixture
def env():
    e = Env()
    try:
        yield e
    finally:
        e.close()


def kinds(res):
    return sorted((i["kind"], i["schema"], i["object"]) for i in res["issues"]
                  if i["severity"] == "error")


def assert_matches_pg_dump(env, res, **kw):
    """check ok <=> pg_dump succeeds; proposed exclusions make it succeed."""
    assert res["success"], res.get("error")
    if not PG_DUMP:
        return
    ok, err = env.dump(**kw)
    assert ok == res["ok"], f"check ok={res['ok']} but pg_dump ok={ok}: {err[-500:]}"
    if not res["ok"] and res["can_exclude"]:
        ok, err = env.dump(res, **kw)
        assert ok, f"partial dump failed: {err[-500:]}"


SETUP_APP = """
SET ROLE {own};
CREATE SCHEMA app;
CREATE TABLE app.t(id serial PRIMARY KEY, v text); INSERT INTO app.t(v) VALUES ('a');
RESET ROLE;
GRANT USAGE ON SCHEMA app TO {bk};
"""


def test_baseline_all_grants(env):
    env.sql(SETUP_APP + "GRANT SELECT ON ALL TABLES IN SCHEMA app TO {bk};"
                        "GRANT SELECT ON ALL SEQUENCES IN SCHEMA app TO {bk};")
    for kw in ({}, {"schema_only": True}, {"data_only": True}, {"schemas": ["app"]}):
        res = env.check(**kw)
        assert res["ok"], res["issues"]
        assert_matches_pg_dump(env, res, **kw)


def test_schema_without_usage(env):
    env.sql(SETUP_APP + """
GRANT SELECT ON ALL TABLES IN SCHEMA app TO {bk}; GRANT SELECT ON ALL SEQUENCES IN SCHEMA app TO {bk};
SET ROLE {own}; CREATE SCHEMA secret; CREATE TABLE secret.s(id int); CREATE SCHEMA emptyns; RESET ROLE;
GRANT SELECT ON secret.s TO {bk};""")
    res = env.check()
    assert kinds(res) == [("schema_usage", "secret", "secret")]
    assert res["exclusions"]["schemas"] == ["secret"] and res["can_exclude"]
    assert_matches_pg_dump(env, res)
    res = env.check(schemas=["app", "emptyns"])
    assert res["ok"]
    assert_matches_pg_dump(env, res, schemas=["app", "emptyns"])


def test_table_without_select(env):
    env.sql(SETUP_APP + """
GRANT SELECT ON app.t TO {bk}; GRANT SELECT ON ALL SEQUENCES IN SCHEMA app TO {bk};
SET ROLE {own};
CREATE TABLE app.priv(id int); CREATE TABLE app.upd(id int);
GRANT UPDATE ON app.upd TO {bk};
RESET ROLE;""")
    res = env.check()
    assert ("table_select", "app", "priv") in kinds(res)
    assert ["app", "priv"] in res["exclusions"]["tables"]
    upd_where = "table_data" if env.version >= 160000 else "tables"   # PG16: UPDATE allows LOCK
    assert ["app", "upd"] in res["exclusions"][upd_where]
    assert_matches_pg_dump(env, res)
    res = env.check(schema_only=True)
    assert_matches_pg_dump(env, res, schema_only=True)


def test_sequences_without_select(env):
    env.sql(SETUP_APP + """
SET ROLE {own};
CREATE TABLE app.idt(id int GENERATED BY DEFAULT AS IDENTITY, v text);
CREATE SEQUENCE app.free_seq;
GRANT SELECT ON app.t, app.idt TO {bk}; GRANT USAGE ON SEQUENCE app.free_seq TO {bk};
RESET ROLE;""")
    res = env.check()
    assert kinds(res) == [("sequence_select", "app", "free_seq"),
                          ("sequence_select", "app", "idt_id_seq"),
                          ("sequence_select", "app", "t_id_seq")]
    assert res["exclusions"]["tables"] == []
    assert len(res["exclusions"]["table_data"]) == 3
    assert_matches_pg_dump(env, res)
    res = env.check(schema_only=True)
    assert res["ok"]
    assert_matches_pg_dump(env, res, schema_only=True)


def test_rls_tables(env):
    env.sql(SETUP_APP + """
GRANT SELECT ON ALL TABLES IN SCHEMA app TO {bk}; GRANT SELECT ON ALL SEQUENCES IN SCHEMA app TO {bk};
SET ROLE {own};
CREATE TABLE app.rls_t(id int); ALTER TABLE app.rls_t ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON app.rls_t USING (true); GRANT SELECT ON app.rls_t TO {bk};
RESET ROLE;
CREATE TABLE app.forced(id int); ALTER TABLE app.forced OWNER TO {bk};
ALTER TABLE app.forced ENABLE ROW LEVEL SECURITY; ALTER TABLE app.forced FORCE ROW LEVEL SECURITY;
CREATE TABLE app.own_rls(id int); ALTER TABLE app.own_rls OWNER TO {bk};
ALTER TABLE app.own_rls ENABLE ROW LEVEL SECURITY;""")
    res = env.check()
    assert kinds(res) == [("rls", "app", "forced"), ("rls", "app", "rls_t")]
    assert res["exclusions"]["table_data"] == [["app", "forced"], ["app", "rls_t"]]
    assert_matches_pg_dump(env, res)
    res = env.check(schema_only=True)
    assert res["ok"]
    assert_matches_pg_dump(env, res, schema_only=True)


def test_partition_without_privileges(env):
    env.sql(SETUP_APP + """
GRANT SELECT ON ALL SEQUENCES IN SCHEMA app TO {bk};
SET ROLE {own};
CREATE TABLE app.parted(k int) PARTITION BY LIST (k);
CREATE TABLE app.p1 PARTITION OF app.parted FOR VALUES IN (1);
CREATE TABLE app.p2 PARTITION OF app.parted FOR VALUES IN (2);
INSERT INTO app.parted VALUES (1), (2);
GRANT SELECT ON app.t, app.parted, app.p1 TO {bk};
RESET ROLE;""")
    res = env.check()
    if env.version >= 130000:    # LOCK recursion no longer checks child ACLs
        assert kinds(res) == [("table_select", "app", "p2")]
        assert res["exclusions"]["tables"] == [["app", "p2"]]
    else:
        assert kinds(res) == [("table_lock", "app", "parted"), ("table_select", "app", "p2")]
        assert res["exclusions"]["tables"] == [["app", "p1"], ["app", "p2"], ["app", "parted"]]
    assert_matches_pg_dump(env, res)


def test_large_objects_without_select(env):
    env.sql(SETUP_APP + """
GRANT SELECT ON ALL TABLES IN SCHEMA app TO {bk}; GRANT SELECT ON ALL SEQUENCES IN SCHEMA app TO {bk};
SET ROLE {own}; SELECT lo_from_bytea(0, 'secret'::bytea); RESET ROLE;""")
    res = env.check()
    assert kinds(res) == [("large_object", None, "1 large object(s)")]
    assert res["exclusions"]["large_objects"] is True and res["can_exclude"]
    assert_matches_pg_dump(env, res)
    # --schema without --blobs: large objects are not dumped
    res = env.check(schemas=["app"], large_objects=False)
    assert res["ok"]
    assert_matches_pg_dump(env, res, schemas=["app"], large_objects=False)
