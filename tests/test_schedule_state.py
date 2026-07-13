"""Unit tests for the atomic schedule run-state store."""
import json

import pytest

import app.schedule_state as state


@pytest.fixture
def state_file(tmp_path, monkeypatch):
    """Redirect the state file into an isolated temp dir."""
    p = tmp_path / "schedule_state.json"
    monkeypatch.setattr(state, "STATE_FILE", p)
    return p


def test_load_missing_file_returns_empty(state_file):
    assert not state_file.exists()
    assert state.load() == {}


def test_load_corrupt_file_returns_empty(state_file):
    state_file.write_text("{not valid json")
    assert state.load() == {}


def test_mark_creates_and_persists(state_file):
    state.mark("nightly", last_status="running", last_run="2026-07-13T02:30:04Z")
    assert state_file.exists()
    on_disk = json.loads(state_file.read_text())
    assert on_disk == {
        "nightly": {"last_status": "running", "last_run": "2026-07-13T02:30:04Z"}
    }


def test_mark_merges_fields(state_file):
    state.mark("nightly", last_status="running", consecutive_failures=0)
    state.mark("nightly", last_status="success", last_filename="db.backup")
    entry = state.load()["nightly"]
    assert entry == {
        "last_status": "success",
        "consecutive_failures": 0,
        "last_filename": "db.backup",
    }


def test_mark_isolates_entries(state_file):
    state.mark("one", last_status="success")
    state.mark("two", last_status="failed")
    loaded = state.load()
    assert loaded["one"] == {"last_status": "success"}
    assert loaded["two"] == {"last_status": "failed"}


def test_drop_removes_entry(state_file):
    state.mark("one", last_status="success")
    state.mark("two", last_status="failed")
    state.drop("one")
    loaded = state.load()
    assert "one" not in loaded
    assert loaded["two"] == {"last_status": "failed"}


def test_drop_missing_is_noop(state_file):
    state.mark("one", last_status="success")
    state.drop("does-not-exist")
    assert state.load() == {"one": {"last_status": "success"}}


def test_atomic_write_leaves_no_tmp_files(state_file):
    state.mark("one", last_status="success")
    leftovers = list(state_file.parent.glob(".schedule_state-*.tmp"))
    assert leftovers == []
