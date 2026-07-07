"""Module-level behavior of app.remote_storage: WebDAV, S3 (fake), and the
credential-scoping security guard."""
import app.config as cfg
import app.remote_storage as rs


# --------------------------------------------------------------------------
# _url_within_base — the guard that decides if a share's creds may be sent
# --------------------------------------------------------------------------
def test_url_within_base_boundaries():
    W = rs._url_within_base
    assert W("https://h/dav/f.backup", "https://h/dav") is True
    assert W("https://h/dav", "https://h/dav") is True
    assert W("https://h/dav-evil/f", "https://h/dav") is False   # prefix trick
    assert W("https://h.evil/dav/f", "https://h/dav") is False   # host differs
    assert W("http://h/dav/f", "https://h/dav") is False         # scheme differs
    assert W("https://h/anything", "https://h") is True          # bare origin
    assert W("https://h/x", "") is False


# --------------------------------------------------------------------------
# WebDAV
# --------------------------------------------------------------------------
def test_webdav_test_connection(webdav):
    cfg.save_fileshare_config(cfg.FileShareConfig(name="local", base_url=webdav.base_url, username="u", password="p"))
    assert rs.webdav_test_connection("local")["success"] is True


def test_webdav_upload(webdav, sample_backup):
    cfg.save_fileshare_config(cfg.FileShareConfig(name="local", base_url=webdav.base_url, username="u", password="p"))
    r = rs.webdav_upload_backup("local", sample_backup.name)
    assert r["success"] is True
    assert (webdav.store_root / sample_backup.name).read_bytes() == sample_backup.read_bytes()


def test_webdav_upload_rejects_missing_and_traversal(webdav):
    cfg.save_fileshare_config(cfg.FileShareConfig(name="local", base_url=webdav.base_url))
    assert rs.webdav_upload_backup("local", "nope_20200101_000000.backup")["success"] is False
    assert rs.webdav_upload_backup("local", "../../etc/passwd")["success"] is False


def test_download_from_link_in_base_sends_creds(webdav, backup_dir):
    (webdav.store_root / "restored_20260202_010101.backup").write_bytes(b"HELLO" * 100)
    cfg.save_fileshare_config(cfg.FileShareConfig(name="local", base_url=webdav.base_url, username="u", password="p"))
    r = rs.download_from_link(f"{webdav.base_url}/restored_20260202_010101.backup")
    assert r["success"] is True
    assert (backup_dir / "restored_20260202_010101.backup").exists()
    # auto-matched the configured share (same origin+path) => creds were sent
    assert webdav.seen_auth() is not None and webdav.seen_auth().startswith("Basic ")


def test_download_from_link_rejects_non_http():
    assert rs.download_from_link("file:///etc/passwd")["success"] is False


def test_download_from_link_refuses_overwrite(webdav, backup_dir):
    (backup_dir / "dup_20260101_000000.backup").write_bytes(b"x")
    (webdav.store_root / "dup_20260101_000000.backup").write_bytes(b"y" * 50)
    r = rs.download_from_link(f"{webdav.base_url}/dup_20260101_000000.backup")
    assert r["success"] is False


def test_download_explicit_share_out_of_base_rejected(webdav):
    # explicit share, but URL path is NOT under the share base -> rejected, no request
    cfg.save_fileshare_config(cfg.FileShareConfig(name="local", base_url=webdav.base_url, username="u", password="p"))
    other = webdav.base_url.replace("/dav", "/other") + "/x_20260101_000000.backup"
    r = rs.download_from_link(other, share_name="local")
    assert r["success"] is False
    assert "not within" in r["error"]
    assert webdav.seen_auth() is None  # nothing was ever requested


def test_download_cross_host_sends_no_creds(webdav, backup_dir):
    # a share configured for a DIFFERENT host must not leak creds to this server
    (webdav.store_root / "x_20260303_000000.backup").write_bytes(b"z" * 40)
    cfg.save_fileshare_config(cfg.FileShareConfig(
        name="elsewhere", base_url="https://storage.example.com/dav", username="u2", password="p2"))
    r = rs.download_from_link(f"{webdav.base_url}/x_20260303_000000.backup")
    assert r["success"] is True
    assert webdav.seen_auth() is None


# --------------------------------------------------------------------------
# S3 (fake client)
# --------------------------------------------------------------------------
def test_s3_upload_list_download(fake_s3, sample_backup, backup_dir):
    cfg.save_s3_storage_config(cfg.S3StorageConfig(
        name="minio", bucket="backups", prefix="magikup/", cred_mode="dedicated",
        access_key_id="AK", secret_access_key="SK"))
    assert rs.s3_test_connection("minio")["success"] is True

    up = rs.s3_upload_backup("minio", sample_backup.name)
    assert up["success"] is True
    assert ("magikup/" + sample_backup.name) in fake_s3

    ls = rs.s3_list_backups("minio")
    assert ls["success"] is True
    assert sample_backup.name in [o["name"] for o in ls["objects"]]  # prefix stripped

    sample_backup.unlink()  # avoid collision
    dl = rs.s3_download_backup("minio", "magikup/" + sample_backup.name)
    assert dl["success"] is True
    assert (backup_dir / sample_backup.name).exists()


def test_s3_download_rejects_non_backup(fake_s3):
    cfg.save_s3_storage_config(cfg.S3StorageConfig(name="minio", bucket="b", prefix="p/"))
    fake_s3["p/evil.txt"] = b"x"
    assert rs.s3_download_backup("minio", "p/evil.txt")["success"] is False


def test_s3_unknown_store():
    assert rs.s3_upload_backup("nope", "db_20260101_000000.backup")["success"] is False
