"""Scheduled-backup email notifications (v4.4.0).

Three layers, all without a live SMTP server or DB:
- config: notify policy + recipients round-trip; invalid policy / bad address
  rejected; legacy sections default to off/"".
- API: POST /api/schedules returns 400 for a bad policy or a bad recipient.
- policy gate: main._notify_schedule_outcome fires the sender only for the
  matching outcomes, and a raising sender never breaks _execute_schedule.

The sender (email_service.send_schedule_notification) is monkeypatched to a
recorder; br.run_backup is monkeypatched to an async generator (no pg_dump);
the coroutine is driven with asyncio.run (no pytest-asyncio needed), matching
the rest of the suite."""
import asyncio
from pathlib import Path

import pytest

import app.config as cfg
import app.main as main
import app.schedule_state as state
from app import email_service


# =============================================================================
# helpers / fixtures
# =============================================================================
def _sched(name="job", database="maindb", **over):
    base = dict(name=name, cron="30 2 * * *", endpoint="prod", database=database,
                dest_kind="none", dest_target="", delete_local_after_copy=False,
                keep_last_n=0)
    base.update(over)
    return cfg.ScheduleConfig(**base)


def _enable_smtp():
    cfg.save_smtp_config(cfg.SMTPConfig(
        enabled=True, host="smtp.example.com", port=587, security="starttls",
        from_address="noreply@example.com"))


# --- config-layer round-trip -------------------------------------------------
def test_notify_config_round_trips():
    cfg.save_schedule(_sched(notify="on_failure",
                             notify_recipients="a@example.com,b@example.com"))
    got = cfg.get_schedule("job")
    assert got.notify == "on_failure"
    assert got.notify_recipients == "a@example.com,b@example.com"


def test_notify_defaults_off_empty_round_trip():
    cfg.save_schedule(_sched())            # notify defaults to "off"
    got = cfg.get_schedule("job")
    assert got.notify == "off"
    assert got.notify_recipients == ""


@pytest.mark.parametrize("policy", ["off", "on_failure", "on_success", "always"])
def test_notify_all_valid_policies_persist(policy):
    cfg.save_schedule(_sched(notify=policy, notify_recipients="ops@example.com"))
    assert cfg.get_schedule("job").notify == policy


def test_notify_invalid_policy_rejected():
    with pytest.raises(ValueError):
        cfg.save_schedule(_sched(notify="sometimes"))


def test_notify_bad_recipient_rejected():
    with pytest.raises(ValueError):
        cfg.save_schedule(_sched(notify="always", notify_recipients="not-an-email"))


def test_notify_bad_recipient_among_valid_rejected():
    with pytest.raises(ValueError):
        cfg.save_schedule(_sched(notify="always",
                                 notify_recipients="ok@example.com,broken"))


def test_notify_recipients_normalized_whitespace():
    cfg.save_schedule(_sched(notify="always",
                             notify_recipients=" a@example.com , b@example.com "))
    assert cfg.get_schedule("job").notify_recipients == "a@example.com,b@example.com"


def test_legacy_section_without_notify_keys_defaults_off():
    """A [schedule:*] section written before v4.4.0 has neither key; get_schedules
    must fall back to off/"" rather than raise."""
    config = cfg.read_config()
    config.add_section("schedule:legacy")
    config.set("schedule:legacy", "cron", "30 2 * * *")
    config.set("schedule:legacy", "endpoint", "prod")
    config.set("schedule:legacy", "database", "maindb")
    cfg.write_config(config)

    got = cfg.get_schedule("legacy")
    assert got is not None
    assert got.notify == "off"
    assert got.notify_recipients == ""


# =============================================================================
# API layer — 400 on bad notify input
# =============================================================================
def _mkendpoint(name="prod-aurora"):
    cfg.save_database_config(cfg.DatabaseConfig(
        name=name, host="127.0.0.1", port=5432, username="postgres", password="pw"))


def _payload(name="nightly-prod", **over):
    p = {"name": name, "cron": "30 2 * * *", "endpoint": "prod-aurora",
         "database": "appdb", "enabled": True, "dest_kind": "none", "keep_last_n": 0}
    p.update(over)
    return p


def test_api_accepts_valid_notify(client):
    _mkendpoint()
    r = client.post("/api/schedules", json=_payload(
        notify="on_failure", notify_recipients=["ops@example.com"]))
    assert r.status_code == 200, r.text
    got = cfg.get_schedule("nightly-prod")
    assert got.notify == "on_failure"
    assert got.notify_recipients == "ops@example.com"


def test_api_rejects_bad_notify_policy(client):
    _mkendpoint()
    r = client.post("/api/schedules", json=_payload(notify="whenever"))
    assert r.status_code == 400
    assert cfg.get_schedule("nightly-prod") is None


def test_api_rejects_bad_notify_recipient(client):
    _mkendpoint()
    r = client.post("/api/schedules", json=_payload(
        notify="always", notify_recipients=["not-an-email"]))
    assert r.status_code == 400
    assert cfg.get_schedule("nightly-prod") is None


def test_api_notify_recipients_round_trip_as_list(client):
    _mkendpoint()
    client.post("/api/schedules", json=_payload(
        notify="always", notify_recipients=["a@example.com", "b@example.com"]))
    r = client.get("/api/schedules/nightly-prod")
    assert r.status_code == 200
    body = r.json()
    assert body["notify"] == "always"
    assert body["notify_recipients"] == ["a@example.com", "b@example.com"]


# =============================================================================
# policy gate — main._notify_schedule_outcome
# =============================================================================
@pytest.fixture
def notify_recorder(monkeypatch):
    """Capture calls to the notification sender without touching SMTP."""
    calls = []
    monkeypatch.setattr(email_service, "send_schedule_notification",
                        lambda *a, **k: calls.append((a, k)))
    return calls


# (policy, run status, expected send?) — success is the only "success"; every
# other status (failed, copy_failed) is a failure.
@pytest.mark.parametrize("policy,status,expected", [
    ("off", "success", False),
    ("off", "failed", False),
    ("on_success", "success", True),
    ("on_success", "failed", False),
    ("on_success", "copy_failed", False),
    ("on_failure", "success", False),
    ("on_failure", "failed", True),
    ("on_failure", "copy_failed", True),
    ("always", "success", True),
    ("always", "failed", True),
    ("always", "copy_failed", True),
])
def test_policy_gate_fires_only_on_matching_outcome(notify_recorder, policy, status, expected):
    _enable_smtp()
    sched = _sched(notify=policy, notify_recipients="ops@example.com")
    main._notify_schedule_outcome(sched, status=status, trigger="schedule")
    assert bool(notify_recorder) is expected


def test_gate_suppressed_when_smtp_disabled(notify_recorder):
    # SMTP left disabled by the default config: a matching policy still no-ops.
    sched = _sched(notify="always", notify_recipients="ops@example.com")
    main._notify_schedule_outcome(sched, status="failed", trigger="schedule")
    assert notify_recorder == []


def test_gate_suppressed_when_no_recipients(notify_recorder):
    _enable_smtp()
    sched = _sched(notify="always", notify_recipients="")
    main._notify_schedule_outcome(sched, status="failed", trigger="schedule")
    assert notify_recorder == []


def test_gate_derives_destination_and_forwards_details(notify_recorder):
    _enable_smtp()
    sched = _sched(notify="always", notify_recipients="ops@example.com",
                   dest_kind="s3", dest_target="tgt")
    main._notify_schedule_outcome(sched, status="success", trigger="manual-schedule",
                                  filename="db.backup", size=123, duration_seconds=5)
    assert len(notify_recorder) == 1
    _args, kwargs = notify_recorder[0]
    assert kwargs["destination"] == "s3"
    assert kwargs["trigger"] == "manual-schedule"
    assert kwargs["filename"] == "db.backup"
    assert kwargs["status"] == "success"


# =============================================================================
# a raising sender never breaks _execute_schedule
# =============================================================================
@pytest.fixture
def sched_state(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "STATE_FILE", tmp_path / "schedule_state.json")
    return state


@pytest.fixture
def endpoint():
    cfg.save_database_config(cfg.DatabaseConfig(
        name="prod", host="127.0.0.1", port=5432, username="postgres", password="pw"))
    return "prod"


def _fake_run_backup(success=True, create_file=True):
    async def fake(**kwargs):
        if create_file:
            Path(kwargs["output_file"]).write_bytes(b"PGDMP-fake" * 100)
        yield {"type": "progress", "message": "dumping"}
        yield {"type": "complete", "success": success}
    return fake


def test_raising_sender_never_breaks_backup(sched_state, endpoint, backup_dir, monkeypatch):
    """Even if the notification sender raises, the backup still completes and is
    marked success — email is strictly best-effort."""
    _enable_smtp()
    monkeypatch.setattr(main.br, "run_backup", _fake_run_backup(success=True))

    def boom(*a, **k):
        raise RuntimeError("smtp exploded")
    monkeypatch.setattr(email_service, "send_schedule_notification", boom)

    fn = "maindb_20260101_000000.backup"
    sched = _sched(dest_kind="none", notify="always", notify_recipients="ops@example.com")
    asyncio.run(main._execute_schedule("job", sched, trigger="manual-schedule", filename=fn))

    assert (backup_dir / fn).exists()                       # backup written
    assert state.load()["job"]["last_status"] == "success"  # not derailed by email


def test_execute_schedule_success_notifies(sched_state, endpoint, backup_dir,
                                            notify_recorder, monkeypatch):
    """End-to-end: a successful run with notify=always dispatches exactly one
    notification carrying the success status."""
    _enable_smtp()
    monkeypatch.setattr(main.br, "run_backup", _fake_run_backup(success=True))

    fn = "maindb_20260101_000000.backup"
    sched = _sched(dest_kind="none", notify="on_success",
                   notify_recipients="ops@example.com")
    asyncio.run(main._execute_schedule("job", sched, trigger="schedule", filename=fn))

    assert len(notify_recorder) == 1
    _args, kwargs = notify_recorder[0]
    assert kwargs["status"] == "success"
    assert kwargs["schedule_name"] == "job"


def test_execute_schedule_failure_suppressed_under_on_success(sched_state, endpoint,
                                                              backup_dir, notify_recorder,
                                                              monkeypatch):
    """A failed run under an on_success policy sends nothing."""
    _enable_smtp()
    monkeypatch.setattr(main.br, "run_backup",
                        _fake_run_backup(success=False, create_file=False))

    sched = _sched(dest_kind="none", notify="on_success",
                   notify_recipients="ops@example.com")
    asyncio.run(main._execute_schedule("job", sched, trigger="schedule",
                                       filename="maindb_20260101_000000.backup"))

    assert notify_recorder == []
