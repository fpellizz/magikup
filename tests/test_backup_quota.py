"""Backup storage quota + storage stats.

Covers the cumulative MAX_TOTAL_BACKUP_GB ceiling (distinct from the per-file
upload limit) and the figures the dashboard / Backup files cards render.
"""
import asyncio

import pytest

from app import backup_restore as br


@pytest.fixture
def quota_mb(monkeypatch):
    """Set MAX_TOTAL_BACKUP_GB to a fractional-GB-free value by patching the
    byte-level helper: the env var is whole GB, too coarse for a temp dir."""
    def _set(megabytes):
        monkeypatch.setattr(br, "get_backup_quota_bytes",
                            lambda: megabytes * 1024 * 1024)
        monkeypatch.setattr(br, "get_backup_quota_gb",
                            lambda: max(1, megabytes // 1024))
    return _set


# --- quota parsing -----------------------------------------------------------

def test_quota_defaults_to_100gb(monkeypatch):
    monkeypatch.delenv("MAX_TOTAL_BACKUP_GB", raising=False)
    assert br.get_backup_quota_gb() == 100
    assert br.get_backup_quota_bytes() == 100 * 1024 ** 3


def test_quota_read_from_env(monkeypatch):
    monkeypatch.setenv("MAX_TOTAL_BACKUP_GB", "7")
    assert br.get_backup_quota_gb() == 7


def test_quota_zero_means_unlimited(monkeypatch):
    monkeypatch.setenv("MAX_TOTAL_BACKUP_GB", "0")
    assert br.get_backup_quota_bytes() == 0
    # No ceiling: even an absurd request fits.
    ok, err = br.check_backup_quota(500 * 1024 ** 3)
    assert ok and err == ""


def test_quota_bogus_value_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("MAX_TOTAL_BACKUP_GB", "not-a-number")
    assert br.get_backup_quota_gb() == br.DEFAULT_BACKUP_QUOTA_GB


def test_quota_negative_value_is_clamped_to_unlimited(monkeypatch):
    monkeypatch.setenv("MAX_TOTAL_BACKUP_GB", "-5")
    assert br.get_backup_quota_gb() == 0


# --- check_backup_quota ------------------------------------------------------

def test_check_quota_allows_a_fitting_file(quota_mb, sample_backup):
    quota_mb(10)
    ok, err = br.check_backup_quota(1024)
    assert ok and err == ""


def test_check_quota_refuses_a_file_that_would_overflow(quota_mb, backup_dir):
    quota_mb(1)
    (backup_dir / "a.backup").write_bytes(b"x" * (900 * 1024))
    ok, err = br.check_backup_quota(200 * 1024)
    assert not ok
    assert "quota exceeded" in err
    assert "MAX_TOTAL_BACKUP_GB" in err


def test_check_quota_reports_a_full_quota_with_no_new_bytes(quota_mb, backup_dir):
    """additional_bytes=0 asks 'is there any room left', so an exactly-full
    quota is a refusal — that is what the pre-flight backup check relies on."""
    quota_mb(1)
    (backup_dir / "a.backup").write_bytes(b"x" * (1024 * 1024))
    ok, _ = br.check_backup_quota()
    assert not ok


def test_check_quota_counts_only_backup_files(quota_mb, backup_dir):
    """An in-flight .tmp (upload / pull) must not be double-counted."""
    quota_mb(1)
    (backup_dir / ".upload_x.backup.tmp").write_bytes(b"x" * (900 * 1024))
    ok, _ = br.check_backup_quota(200 * 1024)
    assert ok


# --- get_backup_stats --------------------------------------------------------

def test_stats_reports_quota_and_volume(quota_mb, backup_dir):
    quota_mb(4)
    (backup_dir / "a.backup").write_bytes(b"x" * (1024 * 1024))

    stats = br.get_backup_stats()
    assert stats["count"] == 1
    assert stats["quota_enabled"] is True
    assert stats["quota_total"] == 4 * 1024 * 1024
    assert stats["quota_percent"] == 25
    assert stats["quota_free"] == stats["quota_total"] - stats["total_size"]
    # The volume that hosts the temp workspace really exists, so this is real.
    assert stats["disk_total"] > 0
    assert stats["disk_percent"] == round(stats["disk_used"] / stats["disk_total"] * 100)


def test_stats_splits_the_volume_between_backups_and_the_rest(backup_dir):
    (backup_dir / "a.backup").write_bytes(b"x" * 4096)
    stats = br.get_backup_stats()
    assert stats["disk_other_used"] == stats["disk_used"] - stats["total_size"]
    assert stats["backups_disk_percent"] + stats["other_disk_percent"] <= 100


def test_stats_shares_add_up_even_on_a_compressing_filesystem(backup_dir):
    """A sparse (or compressed) backup can look bigger than the space it takes;
    the two shares of the volume must still add up to what is used."""
    import shutil
    # Apparent size deliberately above whatever the host volume has in use, so
    # the clamp is exercised wherever the suite runs.
    apparent = shutil.disk_usage(backup_dir).used + 1024 ** 3
    with open(backup_dir / "sparse.backup", "wb") as f:
        f.truncate(apparent)  # sparse: ~0 bytes actually on disk

    stats = br.get_backup_stats()
    assert stats["total_size"] > stats["disk_used"]
    assert stats["disk_other_used"] == 0
    assert stats["backups_disk_percent"] == stats["disk_percent"]
    assert stats["backups_disk_percent"] + stats["other_disk_percent"] <= 100


def test_stats_available_is_the_tighter_of_quota_and_volume(quota_mb, backup_dir):
    # A 1MB quota is far tighter than any real volume's free space.
    quota_mb(1)
    stats = br.get_backup_stats()
    assert stats["limited_by"] == "quota"
    assert stats["available"] == stats["quota_free"]


def test_stats_without_a_quota_falls_back_to_the_volume(monkeypatch):
    monkeypatch.setenv("MAX_TOTAL_BACKUP_GB", "0")
    stats = br.get_backup_stats()
    assert stats["quota_enabled"] is False
    assert stats["quota_total_human"] == "unlimited"
    assert stats["limited_by"] == "volume"
    assert stats["available"] == stats["disk_free"]


# --- API ---------------------------------------------------------------------

def test_stats_endpoint(client, sample_backup):
    res = client.get("/api/backups/stats")
    assert res.status_code == 200
    body = res.json()
    assert body["count"] == 1
    for key in ("total_size_human", "quota_total_human", "disk_total_human",
                "available_human", "limited_by"):
        assert key in body


def test_stats_is_not_read_as_a_filename(client):
    """/api/backups/stats must not be captured by /api/backups/{filename}."""
    res = client.get("/api/backups/stats")
    assert res.status_code == 200
    assert "count" in res.json()


def test_upload_refused_when_the_quota_is_full(client, backup_dir, monkeypatch):
    monkeypatch.setattr(br, "get_backup_quota_bytes", lambda: 1024 * 1024)
    monkeypatch.setattr(br, "get_backup_quota_gb", lambda: 1)
    (backup_dir / "old.backup").write_bytes(b"x" * (1000 * 1024))

    res = client.post("/api/backups/upload",
                      files={"file": ("new.backup", b"y" * (100 * 1024))})
    assert res.status_code == 413
    assert "quota exceeded" in res.json()["detail"]
    # The rejected upload leaves nothing behind.
    assert not (backup_dir / "new.backup").exists()
    assert not list(backup_dir.glob("*.tmp"))


def test_upload_allowed_within_the_quota(client, backup_dir, monkeypatch):
    monkeypatch.setattr(br, "get_backup_quota_bytes", lambda: 10 * 1024 * 1024)
    monkeypatch.setattr(br, "get_backup_quota_gb", lambda: 1)

    res = client.post("/api/backups/upload",
                      files={"file": ("new.backup", b"y" * (100 * 1024))})
    assert res.status_code == 200, res.text
    assert (backup_dir / "new.backup").exists()


# --- pg_dump pre-flight ------------------------------------------------------

def test_run_backup_refuses_to_start_on_a_full_quota(monkeypatch, backup_dir):
    """The dump size is unknown up front, so a full quota must stop it before
    pg_dump is ever exec'd (this is also the scheduled-backup path)."""
    monkeypatch.setattr(br, "get_backup_quota_bytes", lambda: 1024 * 1024)
    monkeypatch.setattr(br, "get_backup_quota_gb", lambda: 1)
    (backup_dir / "old.backup").write_bytes(b"x" * (1024 * 1024))

    async def collect():
        # Driven by hand: the suite has no pytest-asyncio.
        return [e async for e in br.run_backup(database="testdb", host="localhost")]

    events = asyncio.run(collect())
    assert len(events) == 1
    assert events[0]["type"] == "complete"
    assert events[0]["success"] is False
    assert "quota exceeded" in events[0]["message"]


# --- remote pulls ------------------------------------------------------------

def test_pull_from_link_refused_when_the_quota_is_full(webdav, backup_dir, monkeypatch):
    """A pull lands in the backup directory, so it answers to the same quota."""
    import app.config as cfg
    import app.remote_storage as rs

    monkeypatch.setattr(br, "get_backup_quota_bytes", lambda: 1024 * 1024)
    monkeypatch.setattr(br, "get_backup_quota_gb", lambda: 1)
    (backup_dir / "old.backup").write_bytes(b"x" * (1024 * 1024))
    (webdav.store_root / "pulled_20260202_010101.backup").write_bytes(b"y" * 4096)
    cfg.save_fileshare_config(cfg.FileShareConfig(name="local", base_url=webdav.base_url))

    r = rs.download_from_link(f"{webdav.base_url}/pulled_20260202_010101.backup")
    assert r["success"] is False
    assert "quota exceeded" in r["error"]
    assert not (backup_dir / "pulled_20260202_010101.backup").exists()
    assert not list(backup_dir.glob("*.tmp"))
