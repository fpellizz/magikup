"""Email (SMTP) feature: config layer, admin-gated API, masking, empty-keeps,
and the /test endpoint's clean JSON error path. No live SMTP server is used
anywhere here — the one network-touching test points at an unroutable host with
a short timeout, and the rest either stay in the config layer or monkeypatch the
send path. User.email is also exercised through create/get/list (against a
temp users.json so the real store is never touched)."""
import json

import pytest

import app.config as cfg
from app import auth, email_service


# =============================================================================
# Config layer: round-trip + encryption at rest
# =============================================================================

def test_smtp_config_round_trip():
    cfg.save_smtp_config(cfg.SMTPConfig(
        enabled=True, host="smtp.example.com", port=465, security="ssl",
        username="mailer", password="s3cr3t-pw", from_address="from@example.com",
        from_name="MagikUp Bot", reply_to="reply@example.com", timeout_seconds=30))
    s = cfg.get_smtp_config()
    assert s.enabled is True
    assert s.host == "smtp.example.com"
    assert s.port == 465
    assert s.security == "ssl"
    assert s.username == "mailer"
    assert s.password == "s3cr3t-pw"          # decrypted on read
    assert s.from_address == "from@example.com"
    assert s.from_name == "MagikUp Bot"
    assert s.reply_to == "reply@example.com"
    assert s.timeout_seconds == 30


def test_smtp_password_encrypted_at_rest():
    cfg.save_smtp_config(cfg.SMTPConfig(
        enabled=True, host="h", port=587, security="starttls",
        password="plaintext-secret"))
    raw = cfg.CONFIG_FILE.read_text()
    assert "ENC:" in raw                        # Fernet ciphertext, ENC: prefix
    assert "plaintext-secret" not in raw        # never written in the clear

    # And the on-disk token starts with ENC: for the [smtp] section specifically.
    stored = cfg.read_config().get("smtp", "password")
    assert stored.startswith("ENC:")


def test_smtp_empty_password_keeps_existing():
    cfg.save_smtp_config(cfg.SMTPConfig(
        enabled=True, host="h", port=587, security="starttls", password="keepme"))
    # Re-save with a blank password and a changed host: secret must survive.
    cfg.save_smtp_config(cfg.SMTPConfig(
        enabled=True, host="h2", port=587, security="starttls", password=""))
    s = cfg.get_smtp_config()
    assert s.password == "keepme"
    assert s.host == "h2"


def test_smtp_defaults_when_section_absent():
    # Fresh config template may not carry an [smtp] section; reads must default
    # to a disabled config, not blow up.
    s = cfg.get_smtp_config()
    assert s.enabled is False
    assert s.security == cfg.DEFAULT_SMTP_SECURITY
    assert s.port == 587
    assert s.timeout_seconds == cfg.DEFAULT_SMTP_TIMEOUT


# =============================================================================
# API: GET masks the password + admin gating
# =============================================================================

def test_get_smtp_masks_password(client):
    cfg.save_smtp_config(cfg.SMTPConfig(
        enabled=True, host="smtp.example.com", port=587, security="starttls",
        username="u", password="TopSecretPW", from_address="a@b.com"))
    body = client.get("/api/config/smtp").json()

    assert body["password"] == "***"           # masked, not the plaintext
    assert body["has_password"] is True
    assert body["configured"] is True
    # The plaintext and the ENC: token must never leak through the API.
    serialized = json.dumps(body)
    assert "TopSecretPW" not in serialized
    assert "ENC:" not in serialized
    # Non-secret fields still round-trip through the endpoint.
    assert body["host"] == "smtp.example.com"
    assert body["security"] == "starttls"


def test_get_smtp_blank_when_no_password(client):
    cfg.save_smtp_config(cfg.SMTPConfig(
        enabled=False, host="", port=587, security="starttls", password=""))
    body = client.get("/api/config/smtp").json()
    assert body["password"] == ""
    assert body["has_password"] is False
    assert body["configured"] is False


def test_get_smtp_requires_admin(operator_client):
    # require_admin is denied (403) for an operator; the route must be gated.
    assert operator_client.get("/api/config/smtp").status_code == 403


def test_post_smtp_requires_admin(operator_client):
    r = operator_client.post("/api/config/smtp", json={
        "enabled": True, "host": "h", "port": 587, "security": "starttls",
        "timeout_seconds": 15})
    assert r.status_code == 403


# =============================================================================
# API: POST round-trip + empty-keeps + validation
# =============================================================================

def test_post_smtp_round_trip(client):
    r = client.post("/api/config/smtp", json={
        "enabled": True, "host": "smtp.example.com", "port": 465,
        "security": "ssl", "username": "mailer", "password": "apipw",
        "from_address": "from@example.com", "from_name": "Bot",
        "reply_to": "reply@example.com", "timeout_seconds": 20})
    assert r.status_code == 200 and r.json()["status"] == "ok"

    s = cfg.get_smtp_config()
    assert s.enabled is True
    assert s.host == "smtp.example.com"
    assert s.port == 465
    assert s.security == "ssl"
    assert s.password == "apipw"               # stored + decryptable
    assert s.timeout_seconds == 20


def test_post_smtp_empty_password_keeps_stored(client):
    client.post("/api/config/smtp", json={
        "enabled": True, "host": "h1", "port": 587, "security": "starttls",
        "username": "u", "password": "originalpw", "timeout_seconds": 15})
    # Edit with an empty password: the previously stored secret must be kept.
    r = client.post("/api/config/smtp", json={
        "enabled": True, "host": "h2", "port": 587, "security": "starttls",
        "username": "u", "password": "", "timeout_seconds": 15})
    assert r.status_code == 200
    s = cfg.get_smtp_config()
    assert s.password == "originalpw"
    assert s.host == "h2"


def test_post_smtp_rejects_bad_security(client):
    r = client.post("/api/config/smtp", json={
        "enabled": True, "host": "h", "port": 587, "security": "bogus",
        "timeout_seconds": 15})
    assert r.status_code == 400


def test_post_smtp_rejects_bad_port(client):
    r = client.post("/api/config/smtp", json={
        "enabled": True, "host": "h", "port": 99999, "security": "starttls",
        "timeout_seconds": 15})
    assert r.status_code == 400


# =============================================================================
# API: /api/config/smtp/test — clean JSON error, no traceback, no secret
# =============================================================================

def test_smtp_test_clean_error_when_not_configured(client):
    # Email disabled => EmailNotConfigured => 400 with a clean JSON body.
    cfg.save_smtp_config(cfg.SMTPConfig(enabled=False, host="", port=587))
    r = client.post("/api/config/smtp/test", json={"recipient": "to@example.com"})
    assert r.status_code == 400
    body = r.json()
    assert body["status"] == "error"
    assert body["code"] == "not_configured"
    assert isinstance(body["message"], str) and body["message"]


def test_smtp_test_clean_error_when_unreachable(client):
    # Point at an unroutable host (TEST-NET-1, RFC 5737) with a tiny timeout so the
    # connect fails fast. Must come back as a clean JSON error, never a 500
    # traceback, and the message must not leak the SMTP password.
    cfg.save_smtp_config(cfg.SMTPConfig(
        enabled=True, host="192.0.2.1", port=2525, security="none",
        username="u", password="unreachable-secret", from_address="a@b.com",
        timeout_seconds=cfg.SMTP_TIMEOUT_MIN))
    r = client.post("/api/config/smtp/test", json={"recipient": "to@example.com"})
    assert r.status_code == 502
    body = r.json()
    assert body["status"] == "error"
    assert body["code"] in ("connection", "timeout")
    assert isinstance(body["message"], str) and body["message"]
    assert "unreachable-secret" not in json.dumps(body)
    assert "Traceback" not in body["message"]


def test_smtp_test_maps_monkeypatched_error(client, monkeypatch):
    # Deterministic upstream-failure mapping without any socket at all.
    def boom(recipient):
        raise email_service.EmailAuthError("Authentication failed. Check username/password.")
    monkeypatch.setattr(email_service, "send_test_email", boom)

    cfg.save_smtp_config(cfg.SMTPConfig(
        enabled=True, host="h", port=587, security="starttls",
        password="leak-canary-9x"))
    r = client.post("/api/config/smtp/test", json={"recipient": "to@example.com"})
    assert r.status_code == 502
    body = r.json()
    assert body["code"] == "auth"
    assert body["status"] == "error"
    assert "leak-canary-9x" not in json.dumps(body)


def test_smtp_test_invalid_recipient_is_client_error(client):
    # send_test_email validates the recipient before touching the network, so an
    # invalid address comes back as a clean 400 with no connection attempted.
    cfg.save_smtp_config(cfg.SMTPConfig(
        enabled=True, host="h", port=587, security="starttls", password="pw"))
    r = client.post("/api/config/smtp/test", json={"recipient": "not-an-email"})
    assert r.status_code == 400
    body = r.json()
    assert body["code"] == "invalid_recipient"
    assert body["status"] == "error"


# =============================================================================
# User.email round-trips through create / get / list
# =============================================================================

@pytest.fixture
def temp_users(tmp_path, monkeypatch):
    """Redirect the users store to a throwaway file so the real config/users.json
    is never touched, and start empty."""
    uf = tmp_path / "users.json"
    uf.write_text(json.dumps({"version": 1, "users": {}}))
    monkeypatch.setattr(auth, "USERS_FILE", uf)
    return uf


def test_user_email_round_trip(temp_users):
    res = auth.create_user("alice", "Str0ngPass1", "operator",
                           created_by="tester", email="alice@example.com")
    assert res["success"] is True

    # get
    u = auth.get_user("alice")
    assert u is not None
    assert u.email == "alice@example.com"

    # list
    all_users = auth.get_all_users()
    assert all_users["alice"].email == "alice@example.com"

    # persisted verbatim on disk
    stored = json.loads(temp_users.read_text())
    assert stored["users"]["alice"]["email"] == "alice@example.com"


def test_user_email_defaults_empty(temp_users):
    res = auth.create_user("bob", "Str0ngPass1", "viewer", created_by="tester")
    assert res["success"] is True
    assert auth.get_user("bob").email == ""
    assert auth.get_all_users()["bob"].email == ""
