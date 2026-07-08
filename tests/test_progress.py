"""Progress registry + that transfers report bytes through progress_cb."""
import app.progress as P
import app.config as cfg
import app.remote_storage as rs


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------
def test_registry_lifecycle():
    P.clear()
    op = P.start("upload", "s3", "t", "f.backup", total=100)
    snap = P.snapshot()
    assert len(snap) == 1 and snap[0]["percent"] == 0 and snap[0]["status"] == "running"
    P.update(op, done=50)
    assert P.snapshot()[0]["percent"] == 50
    P.finish(op, "done")
    s = P.snapshot()[0]
    assert s["status"] == "done" and s["percent"] == 100 and s["done"] == 100
    P.clear()


def test_registry_percent_none_when_total_unknown():
    P.clear()
    op = P.start("download", "link", "link", "x.backup", total=0)
    P.update(op, done=1234)
    s = P.snapshot()[0]
    assert s["percent"] is None and s["done"] == 1234
    P.clear()


def test_registry_error():
    P.clear()
    op = P.start("upload", "fileshare", "t", "f.backup")
    P.finish(op, "error", "boom")
    s = P.snapshot()[0]
    assert s["status"] == "error" and s["error"] == "boom"
    P.clear()


def test_registry_percent_capped():
    P.clear()
    op = P.start("download", "s3", "t", "f.backup", total=100)
    P.update(op, done=150)  # server under-reported total
    assert P.snapshot()[0]["percent"] == 100
    P.clear()


# --------------------------------------------------------------------------
# progress_cb reaches total on the urllib3-based transfers
# --------------------------------------------------------------------------
def test_webdav_upload_reports_progress(webdav, sample_backup):
    cfg.save_fileshare_config(cfg.FileShareConfig(
        name="local", base_url=webdav.base_url, username="u", password="p"))
    seen = []
    r = rs.webdav_upload_backup("local", sample_backup.name, progress_cb=lambda d, t: seen.append((d, t)))
    assert r["success"] is True
    size = sample_backup.stat().st_size
    assert seen and seen[-1] == (size, size)


def test_link_download_reports_progress(webdav, backup_dir):
    (webdav.store_root / "dl_20260101_000000.backup").write_bytes(b"Z" * 4096)
    cfg.save_fileshare_config(cfg.FileShareConfig(name="local", base_url=webdav.base_url, username="u", password="p"))
    seen = []
    r = rs.download_from_link(f"{webdav.base_url}/dl_20260101_000000.backup",
                             progress_cb=lambda d, t: seen.append((d, t)))
    assert r["success"] is True
    assert seen and seen[-1][0] == 4096 and seen[-1][1] == 4096


def test_filebrowser_upload_download_report_progress(filebrowser_fake, sample_backup, backup_dir):
    cfg.save_filebrowser_config(cfg.FileBrowserConfig(
        name="fb", base_url=filebrowser_fake.base_url, root_path="backups",
        username="admin", password="pw", verify_ssl=True))
    up = []
    r = rs.filebrowser_upload_backup("fb", sample_backup.name, progress_cb=lambda d, t: up.append((d, t)))
    assert r["success"] is True
    size = sample_backup.stat().st_size
    assert up and up[-1] == (size, size)

    sample_backup.unlink()
    down = []
    r = rs.filebrowser_download_backup("fb", "db_20260101_120000.backup",
                                       progress_cb=lambda d, t: down.append((d, t)))
    assert r["success"] is True
    assert down and down[-1][0] == down[-1][1] == size


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------
def test_operations_endpoint(client):
    P.clear()
    assert client.get("/api/storage/operations").json() == {"operations": []}
