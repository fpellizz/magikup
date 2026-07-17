"""API integration for the remote-storage endpoints (FastAPI TestClient)."""


def test_fileshare_crud_and_masking(client):
    r = client.post("/api/config/fileshare",
                    json={"name": "local", "base_url": "https://h/dav", "username": "u",
                          "password": "secret", "verify_ssl": True})
    assert r.status_code == 200 and r.json()["success"]

    # list masks the password
    lst = client.get("/api/config/fileshare").json()
    assert lst[0]["password"] == "***"

    # single GET never returns cleartext
    single = client.get("/api/config/fileshare/local").json()
    assert "password" not in single and single["has_password"] is True

    # blank password on edit preserves the stored one
    client.post("/api/config/fileshare",
                json={"name": "local", "base_url": "https://h/dav2", "username": "u",
                      "password": "", "verify_ssl": True})
    import app.config as cfg
    assert cfg.get_fileshare_config("local").password == "secret"
    assert cfg.get_fileshare_config("local").base_url == "https://h/dav2"

    assert client.delete("/api/config/fileshare/local").status_code == 200
    assert client.get("/api/config/fileshare").json() == []


def test_s3_crud_and_masking(client):
    r = client.post("/api/config/s3",
                    json={"name": "minio", "bucket": "b", "region": "eu", "prefix": "mk/",
                          "path_style": True, "cred_mode": "dedicated",
                          "access_key_id": "AK", "secret_access_key": "SK"})
    assert r.status_code == 200 and r.json()["success"]
    assert client.get("/api/config/s3").json()[0]["secret_access_key"] == "***"
    single = client.get("/api/config/s3/minio").json()
    assert "secret_access_key" not in single and single["has_secret"] is True

    # blank secret on edit preserves stored secret
    client.post("/api/config/s3",
                json={"name": "minio", "bucket": "b2", "cred_mode": "dedicated",
                      "access_key_id": "AK", "secret_access_key": ""})
    import app.config as cfg
    assert cfg.get_s3_storage_config("minio").secret_access_key == "SK"


def test_targets_endpoint(client):
    client.post("/api/config/s3", json={"name": "s1", "bucket": "b"})
    client.post("/api/config/fileshare", json={"name": "f1", "base_url": "https://h/d"})
    t = client.get("/api/storage/targets").json()
    assert any(s["name"] == "s1" for s in t["s3"])
    assert any(s["name"] == "f1" for s in t["fileshare"])


def test_push_and_pull_fileshare(client, webdav, sample_backup, backup_dir):
    client.post("/api/config/fileshare",
                json={"name": "local", "base_url": webdav.base_url, "username": "u", "password": "p"})
    r = client.post(f"/api/backups/{sample_backup.name}/push/fileshare", json={"target": "local"})
    assert r.status_code == 200
    assert (webdav.store_root / sample_backup.name).exists()

    (webdav.store_root / "pulled_20260202_000000.backup").write_bytes(b"R" * 100)
    r = client.post("/api/storage/fileshare/pull",
                    json={"url": f"{webdav.base_url}/pulled_20260202_000000.backup"})
    assert r.status_code == 200
    assert (backup_dir / "pulled_20260202_000000.backup").exists()


def test_push_browse_pull_s3(client, fake_s3, sample_backup, backup_dir):
    client.post("/api/config/s3",
                json={"name": "minio", "bucket": "b", "prefix": "mk/", "cred_mode": "dedicated",
                      "access_key_id": "AK", "secret_access_key": "SK"})
    assert client.post(f"/api/backups/{sample_backup.name}/push/s3", json={"target": "minio"}).status_code == 200
    assert ("mk/" + sample_backup.name) in fake_s3

    objs = client.get("/api/storage/s3/minio/objects").json()
    assert any(o["name"] == sample_backup.name for o in objs["objects"])

    sample_backup.unlink()
    r = client.post("/api/storage/s3/minio/pull", json={"key": "mk/" + sample_backup.name})
    assert r.status_code == 200
    assert (backup_dir / sample_backup.name).exists()


def test_error_paths(client, fake_s3):
    client.post("/api/config/s3", json={"name": "minio", "bucket": "b"})
    assert client.post("/api/backups/missing.backup/push/s3", json={"target": "minio"}).status_code == 400
    assert client.post("/api/backups/x.backup/push/s3", json={"target": "nope"}).status_code == 400


def test_pages_render(client):
    admin = client.get("/admin")
    assert admin.status_code == 200
    assert "Remote Storage" in admin.text and "addS3Modal" in admin.text
    files = client.get("/files")
    assert files.status_code == 200
    assert "Retrieve from remote storage" in files.text
