"""Tests for the headless execution path: main._execute_schedule and
main.apply_local_retention.

`br.run_backup` is monkeypatched to an async generator (no real pg_dump); the
remote push uses the in-memory `fake_s3` fixture or a monkeypatched upload
function. The coroutine is driven with ``asyncio.run`` so the suite needs no
pytest-asyncio plugin (matching the sync TestClient style of the rest of the
suite)."""
import asyncio
import os
from pathlib import Path

import pytest

import app.config as cfg
import app.main as main
import app.backup_restore as br
import app.schedule_state as state


# --------------------------------------------------------------------------
# fixtures / helpers
# --------------------------------------------------------------------------
@pytest.fixture
def sched_state(tmp_path, monkeypatch):
    """Isolate the run-state file per test so consecutive_failures don't leak."""
    monkeypatch.setattr(state, "STATE_FILE", tmp_path / "schedule_state.json")
    return state


@pytest.fixture
def endpoint():
    cfg.save_database_config(cfg.DatabaseConfig(
        name="prod", host="127.0.0.1", port=5432, username="postgres", password="pw"))
    return "prod"


def _sched(name="job", database="maindb", **over):
    base = dict(name=name, cron="30 2 * * *", endpoint="prod", database=database,
                dest_kind="none", dest_target="", delete_local_after_copy=False,
                keep_last_n=0)
    base.update(over)
    return cfg.ScheduleConfig(**base)


def _fake_run_backup(success=True, create_file=True):
    """Return an async-generator function matching br.run_backup's contract."""
    async def fake(**kwargs):
        if create_file:
            Path(kwargs["output_file"]).write_bytes(b"PGDMP-fake" * 100)
        yield {"type": "progress", "message": "dumping"}
        yield {"type": "complete", "success": success}
    return fake


def _run(name, sched, **kw):
    asyncio.run(main._execute_schedule(name, sched, **kw))


FN = "maindb_20260101_000000.backup"


# --------------------------------------------------------------------------
# dest_kind = none
# --------------------------------------------------------------------------
def test_local_only_keeps_file_and_marks_success(sched_state, endpoint, backup_dir, monkeypatch):
    monkeypatch.setattr(main.br, "run_backup", _fake_run_backup(success=True))
    _run("job", _sched(dest_kind="none"), trigger="manual-schedule", filename=FN)
    assert (backup_dir / FN).exists()
    assert state.load()["job"]["last_status"] == "success"
    assert state.load()["job"]["consecutive_failures"] == 0


# --------------------------------------------------------------------------
# dest_kind = s3 (real fake_s3 upload) — keep vs verified-delete
# --------------------------------------------------------------------------
def test_s3_no_delete_keeps_file(sched_state, endpoint, backup_dir, fake_s3, monkeypatch):
    cfg.save_s3_storage_config(cfg.S3StorageConfig(name="tgt", bucket="b"))
    monkeypatch.setattr(main.br, "run_backup", _fake_run_backup(success=True))
    _run("job", _sched(dest_kind="s3", dest_target="tgt", delete_local_after_copy=False),
         trigger="manual-schedule", filename=FN)
    assert (backup_dir / FN).exists()                 # kept
    assert FN in fake_s3                              # uploaded (no prefix configured)
    assert state.load()["job"]["last_status"] == "success"


def test_s3_delete_after_verified_upload(sched_state, endpoint, backup_dir, fake_s3, monkeypatch):
    cfg.save_s3_storage_config(cfg.S3StorageConfig(name="tgt", bucket="b"))
    monkeypatch.setattr(main.br, "run_backup", _fake_run_backup(success=True))
    _run("job", _sched(dest_kind="s3", dest_target="tgt", delete_local_after_copy=True),
         trigger="manual-schedule", filename=FN)
    assert not (backup_dir / FN).exists()             # deleted after verified upload
    assert FN in fake_s3                              # but safe remotely
    assert state.load()["job"]["last_status"] == "success"


# --------------------------------------------------------------------------
# push failure -> keep local, copy_failed, delete never called
# --------------------------------------------------------------------------
def test_push_failure_keeps_file_marks_copy_failed(sched_state, endpoint, backup_dir, monkeypatch):
    monkeypatch.setattr(main.br, "run_backup", _fake_run_backup(success=True))

    deletes = []
    monkeypatch.setattr(main.br, "delete_backup", lambda fn: deletes.append(fn) or {"success": True})

    def failing_upload(target, filename, progress_cb=None):
        return {"success": False, "error": "boom"}
    monkeypatch.setattr(main.rs, "s3_upload_backup", failing_upload)

    _run("job", _sched(dest_kind="s3", dest_target="tgt", delete_local_after_copy=True),
         trigger="manual-schedule", filename=FN)

    assert (backup_dir / FN).exists()                 # local copy kept
    assert deletes == []                              # never deleted on failure
    st = state.load()["job"]
    assert st["last_status"] == "copy_failed"
    assert st["consecutive_failures"] == 1


# --------------------------------------------------------------------------
# size mismatch -> keep local even with delete flag
# --------------------------------------------------------------------------
def test_size_mismatch_keeps_file(sched_state, endpoint, backup_dir, monkeypatch):
    monkeypatch.setattr(main.br, "run_backup", _fake_run_backup(success=True))

    deletes = []
    monkeypatch.setattr(main.br, "delete_backup", lambda fn: deletes.append(fn) or {"success": True})

    def wrong_size_upload(target, filename, progress_cb=None):
        # success, but the reported size does not match the local file
        return {"success": True, "size": 999999999}
    monkeypatch.setattr(main.rs, "s3_upload_backup", wrong_size_upload)

    _run("job", _sched(dest_kind="s3", dest_target="tgt", delete_local_after_copy=True),
         trigger="manual-schedule", filename=FN)

    assert (backup_dir / FN).exists()                 # kept despite delete flag
    assert deletes == []                              # unverified -> not deleted
    assert state.load()["job"]["last_status"] == "success"


# --------------------------------------------------------------------------
# run_backup failure -> failed, no push attempted, failure streak bumps
# --------------------------------------------------------------------------
def test_backup_failure_no_push_and_bumps_streak(sched_state, endpoint, backup_dir, monkeypatch):
    monkeypatch.setattr(main.br, "run_backup", _fake_run_backup(success=False, create_file=False))

    pushed = []
    monkeypatch.setattr(main.rs, "s3_upload_backup",
                        lambda *a, **k: pushed.append(True) or {"success": True, "size": 0})

    _run("job", _sched(dest_kind="s3", dest_target="tgt"), trigger="manual-schedule", filename=FN)

    assert pushed == []                               # push never attempted
    st = state.load()["job"]
    assert st["last_status"] == "failed"
    assert st["consecutive_failures"] == 1


def test_fifth_consecutive_failure_auto_disables(sched_state, endpoint, monkeypatch):
    monkeypatch.setattr(main.br, "run_backup", _fake_run_backup(success=False, create_file=False))
    sched = _sched(dest_kind="none", enabled=True)
    cfg.save_schedule(sched)  # so auto-disable's re-save has a section to update

    for i in range(5):
        # distinct filenames avoid any same-name churn; trigger=manual bypasses
        # the same-minute de-dup so all five attempts execute.
        _run("job", sched, trigger="manual-schedule",
             filename=f"maindb_2026010100000{i}.backup")

    assert state.load()["job"]["consecutive_failures"] == 5
    assert cfg.get_schedule("job").enabled is False   # auto-disabled at the 5th


# --------------------------------------------------------------------------
# apply_local_retention
# --------------------------------------------------------------------------
def test_apply_local_retention_keeps_newest_n(reset_state, backup_dir):
    # 10 backups for maindb + 2 for another DB.
    for i in range(10):
        p = backup_dir / f"maindb_202601{i:02d}_000000.backup"
        p.write_bytes(b"x" * 10)
        os.utime(p, (1000000 + i * 100, 1000000 + i * 100))  # ascending mtime
    for i in range(2):
        p = backup_dir / f"otherdb_202601{i:02d}_000000.backup"
        p.write_bytes(b"y" * 10)
        os.utime(p, (2000000 + i * 100, 2000000 + i * 100))

    main.apply_local_retention(_sched(database="maindb", keep_last_n=3))

    remaining = sorted(f.name for f in backup_dir.glob("*.backup"))
    maindb_left = sorted(n for n in remaining if n.startswith("maindb_"))
    otherdb_left = [n for n in remaining if n.startswith("otherdb_")]
    # The 3 newest maindb backups (highest mtime = indices 7, 8, 9) survive.
    assert maindb_left == [
        "maindb_20260107_000000.backup",
        "maindb_20260108_000000.backup",
        "maindb_20260109_000000.backup",
    ]
    # other-DB files are never touched.
    assert len(otherdb_left) == 2


def test_apply_local_retention_zero_means_unlimited(reset_state, backup_dir):
    for i in range(5):
        (backup_dir / f"maindb_202601{i:02d}_000000.backup").write_bytes(b"x" * 10)
    main.apply_local_retention(_sched(database="maindb", keep_last_n=0))
    assert len(list(backup_dir.glob("maindb_*.backup"))) == 5


def test_apply_local_retention_no_prefix_collision(reset_state, backup_dir):
    # A schedule for DB "sales" must NOT delete "sales_archive" backups: the match
    # is anchored to "{db}_YYYYMMDD_HHMMSS.backup", not a startswith prefix.
    for i in range(5):
        (backup_dir / f"sales_202601{i:02d}_000000.backup").write_bytes(b"x")
        (backup_dir / f"sales_archive_202601{i:02d}_000000.backup").write_bytes(b"y")
    main.apply_local_retention(_sched(database="sales", keep_last_n=1))
    left = sorted(f.name for f in backup_dir.glob("*.backup"))
    assert len([n for n in left if n.startswith("sales_2026")]) == 1      # trimmed to 1
    assert len([n for n in left if n.startswith("sales_archive_")]) == 5  # untouched
