"""Config layer: S3 / file-share persistence, secret encryption, % handling."""
import app.config as cfg


def test_s3_dedicated_round_trip():
    cfg.save_s3_storage_config(cfg.S3StorageConfig(
        name="minio", bucket="backups", region="eu-west-1",
        endpoint_url="https://minio.local:9000", prefix="magikup/",
        path_style=True, cred_mode="dedicated",
        access_key_id="AKIA", secret_access_key="supersecret"))
    s = cfg.get_s3_storage_config("minio")
    assert s.bucket == "backups"
    assert s.region == "eu-west-1"
    assert s.endpoint_url == "https://minio.local:9000"
    assert s.prefix == "magikup/"
    assert s.path_style is True
    assert s.cred_mode == "dedicated"
    assert s.access_key_id == "AKIA"
    assert s.secret_access_key == "supersecret"  # decrypted


def test_s3_aws_account_mode():
    cfg.save_s3_storage_config(cfg.S3StorageConfig(
        name="aws1", bucket="b2", cred_mode="aws_account", aws_account_alias="default"))
    s = cfg.get_s3_storage_config("aws1")
    assert s.cred_mode == "aws_account"
    assert s.aws_account_alias == "default"
    assert s.secret_access_key == ""


def test_s3_secret_encrypted_at_rest():
    cfg.save_s3_storage_config(cfg.S3StorageConfig(
        name="e", bucket="b", cred_mode="dedicated",
        access_key_id="AK", secret_access_key="plaintextsecret"))
    raw = cfg.CONFIG_FILE.read_text()
    assert "ENC:" in raw
    assert "plaintextsecret" not in raw


def test_fileshare_round_trip_and_encryption():
    cfg.save_fileshare_config(cfg.FileShareConfig(
        name="nc", base_url="https://nc.local/dav", username="u",
        password="pw123", verify_ssl=False))
    s = cfg.get_fileshare_config("nc")
    assert s.base_url == "https://nc.local/dav"
    assert s.username == "u"
    assert s.password == "pw123"
    assert s.verify_ssl is False
    raw = cfg.CONFIG_FILE.read_text()
    assert "pw123" not in raw


def test_delete():
    cfg.save_s3_storage_config(cfg.S3StorageConfig(name="x", bucket="b"))
    cfg.save_fileshare_config(cfg.FileShareConfig(name="y", base_url="https://h/d"))
    cfg.delete_s3_storage_config("x")
    cfg.delete_fileshare_config("y")
    assert cfg.get_s3_storage_config("x") is None
    assert cfg.get_fileshare_config("y") is None


def test_percent_in_values_round_trips():
    # A literal '%' must be stored verbatim (ConfigParser interpolation disabled).
    cfg.save_fileshare_config(cfg.FileShareConfig(
        name="pct", base_url="https://h/dav/My%20Backups", username="u", password="p%zz"))
    s = cfg.get_fileshare_config("pct")
    assert s.base_url == "https://h/dav/My%20Backups"
    assert s.password == "p%zz"
    cfg.save_s3_storage_config(cfg.S3StorageConfig(
        name="p2", bucket="b", endpoint_url="https://h/%x", prefix="a%b/",
        secret_access_key="k%1"))
    s2 = cfg.get_s3_storage_config("p2")
    assert s2.endpoint_url == "https://h/%x"
    assert s2.prefix == "a%b/"
    assert s2.secret_access_key == "k%1"


def test_multiple_instances():
    for i in range(3):
        cfg.save_s3_storage_config(cfg.S3StorageConfig(name=f"b{i}", bucket=f"bucket{i}"))
        cfg.save_fileshare_config(cfg.FileShareConfig(name=f"f{i}", base_url=f"https://h/{i}"))
    assert len(cfg.get_s3_storage_configs()) == 3
    assert len(cfg.get_fileshare_configs()) == 3


def test_filebrowser_round_trip_and_encryption():
    cfg.save_filebrowser_config(cfg.FileBrowserConfig(
        name="fb", base_url="https://files.example.com", root_path="backups",
        username="admin", password="fbsecret", verify_ssl=False))
    s = cfg.get_filebrowser_config("fb")
    assert s.base_url == "https://files.example.com"
    assert s.root_path == "backups"
    assert s.username == "admin"
    assert s.password == "fbsecret"       # decrypted
    assert s.verify_ssl is False
    raw = cfg.CONFIG_FILE.read_text()
    assert "fbsecret" not in raw           # encrypted at rest
    cfg.delete_filebrowser_config("fb")
    assert cfg.get_filebrowser_config("fb") is None
