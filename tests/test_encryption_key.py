"""Encryption-key durability: the key persists on the config volume and survives
a redeploy / a changed-or-lost ENCRYPTION_KEY env, so stored passwords never
silently break."""
from cryptography.fernet import Fernet

import app.config as cfg


def test_env_seeds_and_persists_key(tmp_path, monkeypatch):
    kf = tmp_path / ".encryption_key"
    monkeypatch.setattr(cfg, "ENCRYPTION_KEY_FILE", kf)
    k = Fernet.generate_key().decode()
    monkeypatch.setenv("ENCRYPTION_KEY", k)
    got = cfg._get_or_create_encryption_key()
    assert got == k.encode()
    assert kf.exists() and kf.read_text().strip() == k   # captured to the volume


def test_persisted_file_wins_over_divergent_env(tmp_path, monkeypatch):
    kf = tmp_path / ".encryption_key"
    file_key = Fernet.generate_key()
    kf.write_text(file_key.decode())
    monkeypatch.setattr(cfg, "ENCRYPTION_KEY_FILE", kf)
    monkeypatch.setenv("ENCRYPTION_KEY", Fernet.generate_key().decode())  # different
    assert cfg._get_or_create_encryption_key() == file_key   # file wins, env ignored


def test_generates_and_persists_when_neither(tmp_path, monkeypatch):
    kf = tmp_path / ".encryption_key"
    monkeypatch.setattr(cfg, "ENCRYPTION_KEY_FILE", kf)
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    got = cfg._get_or_create_encryption_key()
    assert kf.exists()
    Fernet(got)  # valid key, persisted


def test_password_survives_env_key_change_after_seed(tmp_path, monkeypatch):
    """The core guarantee: once the key is seeded to the volume, a later DIFFERENT
    env key (e.g. a regenerated Secret on redeploy) does NOT break decryption."""
    kf = tmp_path / ".encryption_key"
    monkeypatch.setattr(cfg, "ENCRYPTION_KEY_FILE", kf)
    monkeypatch.setenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
    token = cfg.encrypt_password("s3cr3t")     # seeds the file, encrypts with it
    assert token.startswith("ENC:")
    # Simulate a redeploy that injects a brand-new (rotated/lost-and-regenerated)
    # env key, while the persisted file survives on the config PVC:
    monkeypatch.setenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
    assert cfg.decrypt_password(token) == "s3cr3t"   # still readable via the file key
