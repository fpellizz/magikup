"""API tests for the Query-page DB / user-management endpoints (v4.2.0).

These exercise the guards that run *before* any database connection is opened, so
the whole suite is hermetic — no live PostgreSQL and no psycopg2 socket is ever
required. Each mutating handler shares `_resolve_mgmt_endpoint`, which enforces
(in order) 404 unknown-endpoint -> endpoint access -> 403 read-only, and then the
handler validates identifiers before calling `ensure_tunnel_sync` / opening a
connection.

The `client` fixture (conftest) overrides auth to act as an admin with access to
all endpoints; `cfg` is redirected to a throwaway temp config.
"""
import pytest

import app.config as cfg


# All mutating DB-admin endpoints: (path, body-with-endpoint_name-placeholder).
# `{ep}` is substituted with the target endpoint name per test.
def _mutating_cases(ep):
    return [
        ("/api/db/database",
         {"endpoint_name": ep, "name": "newdb"}),
        ("/api/db/role",
         {"endpoint_name": ep, "name": "newrole", "password": "pw"}),
        ("/api/db/role/alter",
         {"endpoint_name": ep, "name": "existingrole", "login": True}),
        ("/api/db/role/membership",
         {"endpoint_name": ep, "role": "grp", "member": "usr", "grant": True}),
        ("/api/db/database/privileges",
         {"endpoint_name": ep, "target_database": "appdb", "role": "usr",
          "privileges": ["CONNECT"]}),
    ]


def _mkendpoint(name="prod-aurora", read_only=False):
    """Register a direct (non-SSM) endpoint. `read_only` flags it as read-only."""
    cfg.save_database_config(cfg.DatabaseConfig(
        name=name, host="127.0.0.1", port=5432,
        username="postgres", password="pw", read_only=read_only))


@pytest.fixture
def no_db(monkeypatch):
    """Make any attempt to open a psycopg2 connection blow up loudly.

    Guarantees the tests below never reach a real database: if a guard were to
    let the request through to the DB layer, psycopg2.connect would raise and the
    test would fail rather than silently trying to dial a socket.
    """
    import app.db_service as dbs

    def _boom(*a, **k):
        raise AssertionError("psycopg2.connect must not be called in these tests")

    monkeypatch.setattr(dbs.psycopg2, "connect", _boom)
    return monkeypatch


# --------------------------------------------------------------------------
# read-only endpoints: every mutating action is refused with 403
# --------------------------------------------------------------------------
@pytest.mark.parametrize("path,body", _mutating_cases("ro-endpoint"))
def test_mutating_endpoint_refused_on_read_only(client, no_db, path, body):
    _mkendpoint("ro-endpoint", read_only=True)
    r = client.post(path, json=body)
    assert r.status_code == 403, r.text
    assert "read-only" in r.text.lower()


def test_read_only_check_precedes_validation(client, no_db):
    """A read-only endpoint is refused with 403 even when the identifier is also
    invalid — the writable check fires before validation and before any DB I/O."""
    _mkendpoint("ro-endpoint", read_only=True)
    r = client.post("/api/db/database",
                    json={"endpoint_name": "ro-endpoint", "name": "a; DROP"})
    assert r.status_code == 403, r.text


# --------------------------------------------------------------------------
# identifier validation: bad names -> 400, before any DB access
# --------------------------------------------------------------------------
BAD_IDENTS = [
    "a; DROP",          # semicolon / space / injection attempt
    "1bad",             # starts with a digit
    "has space",        # whitespace
    'quote"d',          # embedded quote
    "x" * 64,           # 64 chars -> exceeds the 63-char limit
    "",                 # empty
]


@pytest.mark.parametrize("bad", BAD_IDENTS)
def test_create_database_rejects_bad_name(client, no_db, bad):
    _mkendpoint("prod-aurora")
    r = client.post("/api/db/database",
                    json={"endpoint_name": "prod-aurora", "name": bad})
    assert r.status_code == 400, r.text


@pytest.mark.parametrize("bad", BAD_IDENTS)
def test_create_role_rejects_bad_name(client, no_db, bad):
    _mkendpoint("prod-aurora")
    r = client.post("/api/db/role",
                    json={"endpoint_name": "prod-aurora", "name": bad, "password": "pw"})
    assert r.status_code == 400, r.text


@pytest.mark.parametrize("bad", BAD_IDENTS)
def test_alter_role_rejects_bad_name(client, no_db, bad):
    _mkendpoint("prod-aurora")
    r = client.post("/api/db/role/alter",
                    json={"endpoint_name": "prod-aurora", "name": bad, "login": True})
    assert r.status_code == 400, r.text


@pytest.mark.parametrize("field", ["role", "member"])
def test_membership_rejects_bad_idents(client, no_db, field):
    _mkendpoint("prod-aurora")
    body = {"endpoint_name": "prod-aurora", "role": "grp", "member": "usr"}
    body[field] = "a; DROP"
    r = client.post("/api/db/role/membership", json=body)
    assert r.status_code == 400, r.text


def test_privileges_rejects_bad_target_database(client, no_db):
    _mkendpoint("prod-aurora")
    r = client.post("/api/db/database/privileges", json={
        "endpoint_name": "prod-aurora", "target_database": "a; DROP",
        "role": "usr", "privileges": ["CONNECT"]})
    assert r.status_code == 400, r.text


def test_privileges_rejects_bad_role(client, no_db):
    _mkendpoint("prod-aurora")
    r = client.post("/api/db/database/privileges", json={
        "endpoint_name": "prod-aurora", "target_database": "appdb",
        "role": "1bad", "privileges": ["CONNECT"]})
    assert r.status_code == 400, r.text


def test_privileges_rejects_unknown_privilege(client, no_db):
    _mkendpoint("prod-aurora")
    r = client.post("/api/db/database/privileges", json={
        "endpoint_name": "prod-aurora", "target_database": "appdb",
        "role": "usr", "privileges": ["DROP"]})
    assert r.status_code == 400, r.text


def test_privileges_rejects_empty_privilege_list(client, no_db):
    _mkendpoint("prod-aurora")
    r = client.post("/api/db/database/privileges", json={
        "endpoint_name": "prod-aurora", "target_database": "appdb",
        "role": "usr", "privileges": []})
    assert r.status_code == 400, r.text


# --------------------------------------------------------------------------
# unknown endpoint -> 404 (before validation, on a writable-agnostic path)
# --------------------------------------------------------------------------
@pytest.mark.parametrize("path,body", _mutating_cases("ghost"))
def test_mutating_unknown_endpoint_404(client, no_db, path, body):
    # no endpoint registered under "ghost"
    r = client.post(path, json=body)
    assert r.status_code == 404, r.text


@pytest.mark.parametrize("path", [
    "/api/db/capabilities/ghost",
    "/api/db/roles/ghost",
])
def test_get_unknown_endpoint_404(client, no_db, path):
    r = client.get(path)
    assert r.status_code == 404, r.text


# --------------------------------------------------------------------------
# capabilities / roles GET endpoints require authentication
# --------------------------------------------------------------------------
@pytest.mark.parametrize("path", [
    "/api/db/capabilities/prod-aurora",
    "/api/db/roles/prod-aurora",
])
def test_get_endpoints_require_auth(no_db, path):
    """Without an authenticated session the GET endpoints do not reach the DB —
    they redirect (303) to the login page. Built with a bare TestClient that has
    NO auth dependency overrides, unlike the `client` fixture."""
    import app.main as main
    from fastapi.testclient import TestClient

    _mkendpoint("prod-aurora")
    # Ensure no leftover overrides from another fixture make us look authed.
    main.app.dependency_overrides.clear()
    with TestClient(main.app, follow_redirects=False) as c:
        r = c.get(path)
    assert r.status_code == 303, r.text
    assert "/login" in r.headers.get("location", "")


def test_mutating_endpoints_require_auth(no_db):
    """A mutating POST without auth is rejected before any DB work."""
    import app.main as main
    from fastapi.testclient import TestClient

    _mkendpoint("prod-aurora")
    main.app.dependency_overrides.clear()
    with TestClient(main.app, follow_redirects=False) as c:
        r = c.post("/api/db/database",
                   json={"endpoint_name": "prod-aurora", "name": "newdb"})
    assert r.status_code == 303, r.text
