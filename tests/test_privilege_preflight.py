"""Backup privilege preflight — backend integration.

No real DB / pg_dump: privilege_check.check_backup_privileges is monkeypatched,
asyncio.create_subprocess_exec is captured for argv assertions, and
br.run_backup is replaced by a recorder for the scheduler path."""
import asyncio
from pathlib import Path
from unittest import mock

import pytest

import app.config as cfg
import app.main as main
import app.backup_restore as br
import app.schedule_state as state
from app import email_service, privilege_check

# Real function captured at import (the autouse stub patches the module attribute later).
_REAL_CHECK = privilege_check.check_backup_privileges


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _result(ok=True, success=True, **over):
    base = {
        "success": success, "error": None if success else "boom", "ok": ok,
        "current_user": "app_backup", "is_superuser": False, "bypass_rls": False,
        "server_version_num": 160004,
        "summary": {"issues_total": 0 if ok else 3, "errors": 0 if ok else 3, "warnings": 0,
                    "by_kind": {}, "by_schema": []},
        "issues": [], "truncated": False,
        "exclusions": {"schemas": [], "tables": [], "large_objects": False},
        "can_exclude": True, "fix_sql": "GRANT ...",
    }
    base.update(over)
    return base


def _mkendpoint(name="prod", **kw):
    cfg.save_database_config(cfg.DatabaseConfig(
        name=name, host="127.0.0.1", port=5432, username="postgres", password="pw", **kw))


@pytest.fixture
def pf(monkeypatch):
    """Record check_backup_privileges calls; return value set via pf.result."""
    class Rec:
        calls = []
        result = _result()
    rec = Rec()

    # Signature-checked: a wrong/missing kwarg in the caller raises TypeError.
    m = mock.create_autospec(_REAL_CHECK,
                             side_effect=lambda *a, **k: rec.result)
    rec.calls = m.call_args_list
    monkeypatch.setattr(privilege_check, "check_backup_privileges", m)
    monkeypatch.setattr(main, "get_endpoint_host_port", lambda ep: (ep.host, ep.port))
    return rec


# --------------------------------------------------------------------------
# endpoint
# --------------------------------------------------------------------------
def _body(**over):
    b = {"endpoint_name": "prod", "database": "maindb"}
    b.update(over)
    return b


def test_preflight_ok_passthrough(client, pf):
    _mkendpoint()
    pf.result = _result(ok=True)
    r = client.post("/api/db/backup-preflight", json=_body(
        schemas=["public"], exclude_table="tmp_*", data_only=True, large_objects=False))
    assert r.status_code == 200
    assert r.json() == pf.result
    (args, kwargs), = pf.calls
    assert args[:5] == ("127.0.0.1", 5432, "maindb", "postgres", "pw")
    assert kwargs["schemas"] == ["public"]
    assert kwargs["exclude_table"] == "tmp_*"
    assert kwargs["data_only"] is True and kwargs["large_objects"] is False


def test_preflight_issues_passthrough(client, pf):
    _mkendpoint()
    pf.result = _result(ok=False, issues=[{"kind": "table_select"}])
    r = client.post("/api/db/backup-preflight", json=_body())
    assert r.status_code == 200 and r.json()["ok"] is False


def test_preflight_check_failure_is_200(client, pf):
    _mkendpoint()
    pf.result = _result(success=False, ok=False)
    r = client.post("/api/db/backup-preflight", json=_body())
    assert r.status_code == 200
    assert r.json()["success"] is False and r.json()["error"] == "boom"


def test_preflight_uses_replica_host(client, pf):
    _mkendpoint(replica_host="replica.example", backup_use_replica=True)
    client.post("/api/db/backup-preflight", json=_body())
    assert pf.calls[0][0][0] == "replica.example"


def test_preflight_unknown_endpoint_404(client, pf):
    r = client.post("/api/db/backup-preflight", json=_body(endpoint_name="nope"))
    assert r.status_code == 404 and pf.calls == []


def test_preflight_viewer_forbidden(pf):
    import app.main as m
    from app import auth
    from fastapi import HTTPException
    from fastapi.testclient import TestClient

    def deny():
        raise HTTPException(status_code=403, detail="Operator access required")
    _mkendpoint()
    m.app.dependency_overrides[auth.require_operator] = deny
    try:
        with TestClient(m.app) as c:
            r = c.post("/api/db/backup-preflight", json=_body())
    finally:
        m.app.dependency_overrides.clear()
    assert r.status_code == 403 and pf.calls == []


def test_preflight_no_endpoint_access_403(pf):
    import app.main as m
    from app import auth
    from fastapi.testclient import TestClient
    _mkendpoint()
    m.app.dependency_overrides[auth.require_operator] = lambda: {
        "username": "op", "role": "operator", "endpoints": ["other"]}
    try:
        with TestClient(m.app) as c:
            r = c.post("/api/db/backup-preflight", json=_body())
    finally:
        m.app.dependency_overrides.clear()
    assert r.status_code == 403 and pf.calls == []


@pytest.mark.parametrize("over", [
    {"exclude_table": "a;drop"},
    {"exclude_table_data": "bad name"},
    {"schemas": ["ok", "bad;schema"]},
    {"schemas": [""]},
    {"database": "bad;db"},
    {"data_only": True, "schema_only": True},
])
def test_preflight_validation_400(client, pf, over):
    _mkendpoint()
    r = client.post("/api/db/backup-preflight", json=_body(**over))
    assert r.status_code == 400, r.text
    assert pf.calls == []


# --------------------------------------------------------------------------
# run_backup argv
# --------------------------------------------------------------------------
def _capture_argv(monkeypatch, options):
    captured = {}

    async def boom(*a, **k):
        captured["argv"] = list(a)
        raise RuntimeError("stop")
    monkeypatch.setattr(br.asyncio, "create_subprocess_exec", boom)
    monkeypatch.setattr(br, "validate_pg_tool_path", lambda *a, **k: None)
    monkeypatch.setattr(br, "check_backup_quota", lambda *a, **k: (True, None))

    async def go():
        async for _ in br.run_backup(database="db", host="h", port=5432, username="u",
                                     password="pw", options=options,
                                     pg_dump_path="/usr/bin/pg_dump"):
            pass
    asyncio.run(go())
    return captured["argv"]


def _pairs(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == flag]


def test_run_backup_quoted_privilege_exclusions(monkeypatch):
    argv = _capture_argv(monkeypatch, br.BackupOptions(
        exclude_schema="old",
        privilege_exclude_schemas=["audit", 'we"ird'],
        privilege_exclude_tables=[("billing", "invoices"), ("billing", "inv seq")],
    ))
    assert _pairs(argv, "--exclude-schema") == ["old", '"audit"', '"we""ird"']
    assert _pairs(argv, "--exclude-table") == ['"billing"."invoices"', '"billing"."inv seq"']


def test_run_backup_no_blobs_replaces_blobs(monkeypatch):
    argv = _capture_argv(monkeypatch, br.BackupOptions(large_objects=True, no_large_objects=True))
    assert "--no-blobs" in argv and "--blobs" not in argv
    argv = _capture_argv(monkeypatch, br.BackupOptions(large_objects=True))
    assert "--blobs" in argv and "--no-blobs" not in argv


def test_run_backup_schemas_pruned_not_excluded(monkeypatch):
    argv = _capture_argv(monkeypatch, br.BackupOptions(
        schemas=["public", "audit"], privilege_exclude_schemas=["audit"]))
    assert _pairs(argv, "--schema") == ["public"]
    assert "--exclude-schema" not in argv


def test_run_backup_schema_pruning_matches_folded_name(monkeypatch):
    # pg_dump folds an unquoted --schema to lowercase; the check reports real names.
    argv = _capture_argv(monkeypatch, br.BackupOptions(
        schemas=["public", "Audit"], privilege_exclude_schemas=["audit"]))
    assert _pairs(argv, "--schema") == ["public"]


def test_run_backup_owned_sequence_data_excluded(monkeypatch):
    argv = _capture_argv(monkeypatch, br.BackupOptions(
        privilege_exclude_tables=[("app", "orders_id_seq")],
        privilege_exclude_table_data=[("app", "orders_id_seq")]))
    assert _pairs(argv, "--exclude-table") == ['"app"."orders_id_seq"']
    assert _pairs(argv, "--exclude-table-data") == ['"app"."orders_id_seq"']


def test_apply_exclusions_sets_table_data():
    opts = br.BackupOptions()
    main._apply_privilege_exclusions(opts, _result(exclusions={
        "schemas": [], "tables": [["app", "s1"]], "table_data": [["app", "s1"]],
        "large_objects": False}))
    assert opts.privilege_exclude_table_data == [("app", "s1")]


def test_run_backup_all_schemas_pruned_refuses(monkeypatch):
    with pytest.raises(ValueError):
        _capture_argv(monkeypatch, br.BackupOptions(
            schemas=["audit"], privilege_exclude_schemas=["audit"]))


# --------------------------------------------------------------------------
# _apply_privilege_exclusions (pure helper used by the WS "exclude" path)
# --------------------------------------------------------------------------
def test_apply_exclusions_sets_options_and_info():
    opts = br.BackupOptions()
    tables = [["s", f"t{i}"] for i in range(150)]
    info = main._apply_privilege_exclusions(opts, _result(
        exclusions={"schemas": ["audit"], "tables": tables, "large_objects": True}))
    assert opts.privilege_exclude_schemas == ["audit"]
    assert len(opts.privilege_exclude_tables) == 150
    assert opts.privilege_exclude_tables[0] == ("s", "t0")
    assert opts.no_large_objects is True
    assert info["count"] == 152 and info["tables_count"] == 150
    assert len(info["tables"]) == 100 and info["large_objects"] is True


def test_apply_exclusions_empty_is_noop():
    opts = br.BackupOptions()
    info = main._apply_privilege_exclusions(opts, _result())
    assert opts.privilege_exclude_schemas is None and opts.privilege_exclude_tables is None
    assert opts.no_large_objects is False and info["count"] == 0


# --------------------------------------------------------------------------
# scheduler
# --------------------------------------------------------------------------
@pytest.fixture
def sched_state(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "STATE_FILE", tmp_path / "schedule_state.json")
    return state


def _sched(**over):
    base = dict(name="job", cron="30 2 * * *", endpoint="prod", database="maindb",
                dest_kind="none", dest_target="", delete_local_after_copy=False,
                keep_last_n=0, schemas="public, audit", exclude_table="tmp_*")
    base.update(over)
    return cfg.ScheduleConfig(**base)


@pytest.fixture
def dump_calls(monkeypatch):
    calls = []

    async def fake(**kwargs):
        calls.append(kwargs)
        Path(kwargs["output_file"]).write_bytes(b"PGDMP" * 10)
        yield {"type": "complete", "success": True}
    monkeypatch.setattr(main.br, "run_backup", fake)
    return calls


@pytest.fixture
def notify_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(email_service, "send_schedule_notification",
                        lambda *a, **k: calls.append((a, k)))
    cfg.save_smtp_config(cfg.SMTPConfig(enabled=True, host="smtp.example.com", port=587,
                                        security="starttls", from_address="n@example.com"))
    return calls


FN = "maindb_20260101_000000.backup"


def _run(sched):
    asyncio.run(main._execute_schedule("job", sched, trigger="manual-schedule", filename=FN))


def test_scheduler_blocking_issues_fail_before_dump(sched_state, pf, dump_calls, notify_calls):
    _mkendpoint()
    pf.result = _result(ok=False)
    monkey_summary = "SUMMARY-TEXT"
    orig = privilege_check.format_issue_summary
    privilege_check.format_issue_summary = lambda r, *a, **k: monkey_summary
    try:
        _run(_sched(notify="always", notify_recipients="ops@example.com"))
    finally:
        privilege_check.format_issue_summary = orig
    assert dump_calls == []
    assert not main._running_operations
    st = state.load()["job"]
    assert st["last_status"] == "failed"
    assert "Insufficient privileges" in st["last_error"] and "app_backup" in st["last_error"]
    (_a, kw), = notify_calls
    assert kw["status"] == "failed" and kw["details"] == monkey_summary
    assert "Insufficient privileges" in kw["error"]
    # preflight used the schedule's options
    kwargs = pf.calls[0][1]
    assert kwargs["schemas"] == ["public", "audit"] and kwargs["exclude_table"] == "tmp_*"


def test_scheduler_blocking_issues_respects_notify_off(sched_state, pf, dump_calls, notify_calls):
    _mkendpoint()
    pf.result = _result(ok=False)
    _run(_sched(notify="off"))
    assert dump_calls == [] and notify_calls == []
    assert state.load()["job"]["last_status"] == "failed"


def test_scheduler_check_cannot_run_fails_open(sched_state, pf, dump_calls):
    _mkendpoint()
    pf.result = _result(success=False, ok=False)
    _run(_sched())
    assert len(dump_calls) == 1
    assert state.load()["job"]["last_status"] == "success"


def test_scheduler_check_raises_fails_open(sched_state, monkeypatch, dump_calls):
    _mkendpoint()

    def boom(*a, **k):
        raise RuntimeError("x")
    monkeypatch.setattr(privilege_check, "check_backup_privileges", boom)
    monkeypatch.setattr(main, "get_endpoint_host_port", lambda ep: (ep.host, ep.port))
    _run(_sched())
    assert len(dump_calls) == 1


def test_scheduler_ok_proceeds(sched_state, pf, dump_calls, monkeypatch):
    _mkendpoint()
    logged = []
    orig = main.op_logger.get_logger().__class__.log_message
    monkeypatch.setattr(main.op_logger.get_logger().__class__, "log_message",
                        lambda self, oid, msg, *a, **k: (logged.append(msg), orig(self, oid, msg, *a, **k))[1])
    _run(_sched())
    assert len(dump_calls) == 1
    assert "Privilege check passed" in logged
    assert state.load()["job"]["last_status"] == "success"


def test_scheduler_blocking_email_details_capped(sched_state, pf, dump_calls, notify_calls, monkeypatch):
    _mkendpoint()
    pf.result = _result(ok=False)
    big = "x" * (main._EMAIL_DETAILS_MAX + 5000)
    monkeypatch.setattr(privilege_check, "format_issue_summary", lambda r, *a, **k: big)
    _run(_sched(notify="always", notify_recipients="ops@example.com"))
    (_a, kw), = notify_calls
    assert kw["details"] == main._cap_text(big, main._EMAIL_DETAILS_MAX)
    assert len(kw["details"]) < len(big) and "more characters" in kw["details"]


# --------------------------------------------------------------------------
# email details
# --------------------------------------------------------------------------
def test_email_details_rendered_and_escaped(monkeypatch):
    sent = {}
    monkeypatch.setattr(email_service, "send_email",
                        lambda to, subject, html, text=None, **k: sent.update(html=html, text=text))
    email_service.send_schedule_notification(
        ["a@example.com"], schedule_name="job", status="failed", endpoint="prod",
        database="db", error="Insufficient privileges",
        details="table <script>alert(1)</script> & \"x\"")
    assert "Details:" in sent["text"] and "<script>alert(1)</script>" in sent["text"]
    assert "<pre" in sent["html"]
    assert "<script>" not in sent["html"]
    assert "&lt;script&gt;" in sent["html"] and "&amp;" in sent["html"]


def test_email_without_details_has_no_pre(monkeypatch):
    sent = {}
    monkeypatch.setattr(email_service, "send_email",
                        lambda to, subject, html, text=None, **k: sent.update(html=html, text=text))
    email_service.send_schedule_notification(
        ["a@example.com"], schedule_name="job", status="failed", endpoint="p", database="d")
    assert "<pre" not in sent["html"] and "Details:" not in sent["text"]


def test_email_details_never_raises(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("smtp")
    monkeypatch.setattr(email_service, "send_email", boom)
    email_service.send_schedule_notification(
        ["a@example.com"], schedule_name="j", status="failed", endpoint="p",
        database="d", details="x")


# --------------------------------------------------------------------------
# WS /ws/backup  privilege_mode="exclude"
# --------------------------------------------------------------------------
@pytest.fixture
def ws_env(client, pf, monkeypatch):
    """TestClient + authenticated WS + run_backup recorder. The WS auth helper is
    patched (it reads a signed session cookie); everything else is real."""
    async def _auth(websocket):
        return {"username": "tester", "role": "admin", "endpoints": ["*"]}
    monkeypatch.setattr(main, "check_websocket_auth", _auth)
    runs = []

    async def fake_run_backup(**kwargs):
        runs.append(kwargs)
        yield {"type": "complete", "success": True, "message": "done",
               "output_file": "x.backup", "file_size_human": "1 KB"}
    monkeypatch.setattr(main.br, "run_backup", fake_run_backup)
    _mkendpoint()

    class Env:
        pass
    env = Env()
    env.client, env.pf, env.runs = client, pf, runs

    def talk(**payload):
        msgs = []
        with client.websocket_connect("/ws/backup") as ws:
            ws.send_json({"endpoint_name": "prod", "database": "maindb", **payload})
            try:
                while True:
                    m = ws.receive_json()
                    msgs.append(m)
                    if m.get("type") in ("complete", "error"):
                        break
            except Exception:
                pass
        return msgs
    env.talk = talk

    def last_op():
        hist = main.op_logger.get_logger().get_operation_history(limit=1)
        return hist[0]
    env.last_op = last_op
    return env


def _excl_result(**over):
    return _result(ok=False, exclusions={
        "schemas": ["audit"], "tables": [["billing", "invoices"]],
        "table_data": [], "large_objects": True}, **over)


def test_ws_exclude_success_marks_partial(ws_env):
    ws_env.pf.result = _excl_result()
    msgs = ws_env.talk(privilege_mode="exclude")
    assert len(ws_env.pf.calls) == 1            # server re-ran the check
    assert msgs[-1]["type"] == "complete" and msgs[-1]["success"] is True
    assert any("PARTIAL backup" in (m.get("message") or "") for m in msgs)
    (kwargs,) = ws_env.runs
    opts = kwargs["options"]
    assert opts.privilege_exclude_schemas == ["audit"]
    assert opts.privilege_exclude_tables == [("billing", "invoices")]
    assert opts.no_large_objects is True
    meta = ws_env.last_op()["metadata"]
    assert meta["partial_backup"] is True
    pe = meta["privilege_excluded"]
    assert pe["schemas"] == ["audit"] and pe["tables_count"] == 1 and pe["large_objects"] is True


def test_ws_exclude_ignores_client_lists(ws_env):
    ws_env.pf.result = _excl_result()
    ws_env.talk(privilege_mode="exclude",
                exclusions={"schemas": ["evil"], "tables": [["a", "b"]]},
                privilege_exclude_schemas=["evil"],
                privilege_exclude_tables=[["a", "b"]],
                no_large_objects=False)
    opts = ws_env.runs[0]["options"]
    assert opts.privilege_exclude_schemas == ["audit"]
    assert opts.privilege_exclude_tables == [("billing", "invoices")]


def test_ws_exclude_check_failure_sends_error(ws_env):
    ws_env.pf.result = _result(success=False, ok=False)
    msgs = ws_env.talk(privilege_mode="exclude")
    assert len(ws_env.pf.calls) == 1
    assert msgs[-1]["type"] == "error" and "Privilege check failed" in msgs[-1]["message"]
    assert ws_env.runs == []


def test_ws_exclude_cannot_exclude_sends_error(ws_env):
    ws_env.pf.result = _excl_result(can_exclude=False)
    msgs = ws_env.talk(privilege_mode="exclude")
    assert msgs[-1]["type"] == "error" and "partial backup" in msgs[-1]["message"].lower()
    assert ws_env.runs == []


def test_ws_exclude_ok_without_exclusions_not_partial(ws_env):
    ws_env.pf.result = _result(ok=True)
    msgs = ws_env.talk(privilege_mode="exclude")
    assert msgs[-1]["type"] == "complete"
    assert "partial_backup" not in ws_env.last_op()["metadata"]
    assert not any("PARTIAL" in (m.get("message") or "") for m in msgs)


def test_ws_without_privilege_mode_skips_check(ws_env):
    msgs = ws_env.talk()
    assert ws_env.pf.calls == [] and msgs[-1]["type"] == "complete"
    assert "partial_backup" not in ws_env.last_op()["metadata"]


# --------------------------------------------------------------------------
# data-only privilege exclusions (table_data) count as a PARTIAL backup
# --------------------------------------------------------------------------
def test_apply_exclusions_counts_table_data():
    opts = br.BackupOptions()
    data = [["app", f"t{i}"] for i in range(120)]
    info = main._apply_privilege_exclusions(opts, _result(exclusions={
        "schemas": [], "tables": [], "table_data": data, "large_objects": False}))
    assert info["count"] == 120 and info["table_data_count"] == 120
    assert len(info["table_data"]) == 100 and info["table_data"][0] == ["app", "t0"]


def test_ws_exclude_data_only_marks_partial(ws_env):
    ws_env.pf.result = _result(ok=False, exclusions={
        "schemas": [], "tables": [], "table_data": [["billing", "invoices"]],
        "large_objects": False})
    msgs = ws_env.talk(privilege_mode="exclude")
    assert msgs[-1]["type"] == "complete"
    assert any("PARTIAL backup: 1 objects" in (m.get("message") or "") for m in msgs)
    opts = ws_env.runs[0]["options"]
    assert opts.privilege_exclude_table_data == [("billing", "invoices")]
    meta = ws_env.last_op()["metadata"]
    assert meta["partial_backup"] is True
    pe = meta["privilege_excluded"]
    assert pe["table_data_count"] == 1 and pe["table_data"] == [["billing", "invoices"]]


def test_ws_exclude_refusal_carries_reason(ws_env):
    ws_env.pf.result = _excl_result(can_exclude=False,
                                    can_exclude_reason="Too many objects to exclude (900)")
    msgs = ws_env.talk(privilege_mode="exclude")
    assert msgs[-1]["type"] == "error" and "Too many objects" in msgs[-1]["message"]
    assert ws_env.runs == []


def test_run_backup_data_only_privilege_exclusions_argv(monkeypatch):
    argv = _capture_argv(monkeypatch, br.BackupOptions(
        privilege_exclude_table_data=[("billing", "inv*"), ("app", 'we"ird')]))
    assert _pairs(argv, "--exclude-table-data") == ['"billing"."inv*"', '"app"."we""ird"']
    assert _pairs(argv, "--exclude-table") == []
