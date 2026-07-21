"""Self-service password recovery (v4.4.0).

Covers the auth-layer token mechanics and the unauthenticated /forgot-password
+ /reset-password routes. No live SMTP is used: the send primitive is either
left disabled (so nothing is dispatched) or monkeypatched to a recorder. The
users store and audit log are redirected to a throwaway file so the real
config/ is never touched, and the in-memory rate-limit bucket is cleared per
test so IP state can't leak between tests (the TestClient always presents the
same client host)."""
import json
import time

import pytest

import app.config as cfg
from app import auth, email_service


# =============================================================================
# fixtures
# =============================================================================
@pytest.fixture(autouse=True)
def isolate_auth_store(tmp_path, monkeypatch):
    """Redirect users.json + audit.log to a temp dir and start with an empty
    store, and reset the shared per-IP rate-limit bucket."""
    uf = tmp_path / "users.json"
    uf.write_text(json.dumps({"version": 1, "users": {}}))
    monkeypatch.setattr(auth, "USERS_FILE", uf)
    monkeypatch.setattr(auth, "AUDIT_LOG_FILE", tmp_path / "audit.log")
    auth._rate_limit_store.clear()
    yield
    auth._rate_limit_store.clear()


def _mkuser(username="alice", password="Str0ngPass1", role="operator",
            email="alice@example.com", enabled=True):
    res = auth.create_user(username, password, role, created_by="tester", email=email)
    assert res["success"] is True, res
    if not enabled:
        auth.update_user(username, enabled=False)
    return auth.get_user(username)


def _enable_smtp():
    cfg.save_smtp_config(cfg.SMTPConfig(
        enabled=True, host="smtp.example.com", port=587, security="starttls",
        from_address="noreply@example.com",
        # base_url is required for reset links to be built (Host-poisoning fix):
        # without a trusted base and with ALLOWED_HOSTS=* the email is suppressed.
        base_url="https://magikup.example.test"))


# =============================================================================
# find_user_by_identifier
# =============================================================================
def test_find_user_by_username_then_email_case_insensitive():
    _mkuser("alice", email="Alice@Example.com")
    assert auth.find_user_by_identifier("alice").username == "alice"
    # case-insensitive email match
    assert auth.find_user_by_identifier("ALICE@EXAMPLE.COM").username == "alice"
    assert auth.find_user_by_identifier("nobody") is None


def test_find_user_username_wins_over_email_collision():
    # user "bob" whose *email* happens to equal another account's username.
    _mkuser("target", email="", role="viewer")
    _mkuser("bob", email="target@example.com")
    # exact-username lookup for "target" returns the target account, not bob.
    assert auth.find_user_by_identifier("target").username == "target"


# =============================================================================
# request_password_reset — no enumeration signal, no state mutation
# =============================================================================
def test_request_reset_returns_payload_only_for_enabled_user_with_email():
    _mkuser("alice", email="alice@example.com")
    payload = auth.request_password_reset("alice")
    assert payload is not None
    assert payload["username"] == "alice"
    assert payload["email"] == "alice@example.com"
    assert payload["token"]


def test_request_reset_returns_none_for_unknown_disabled_or_no_email():
    _mkuser("hasmail", email="ok@example.com")
    _mkuser("nomail", email="")
    _mkuser("off", email="off@example.com", enabled=False)

    assert auth.request_password_reset("ghost") is None          # unknown
    assert auth.request_password_reset("nomail") is None          # no email
    assert auth.request_password_reset("off") is None             # disabled


def test_request_reset_does_not_mutate_password():
    u = _mkuser("alice", email="alice@example.com")
    before = u.password_hash
    auth.request_password_reset("alice")
    assert auth.get_user("alice").password_hash == before


def test_request_reset_always_audits_submitted_identifier(tmp_path):
    _mkuser("alice", email="alice@example.com")
    auth.request_password_reset("alice")
    auth.request_password_reset("ghost-does-not-exist")
    lines = auth.AUDIT_LOG_FILE.read_text().splitlines()
    events = [json.loads(l) for l in lines if l.strip()]
    requested = [e for e in events if e["event"] == "password_reset_requested"]
    # Both the matching and the non-matching request are audited identically
    # (event name carries no hit/miss signal); the submitted identifier is the
    # username field.
    audited = {e["username"] for e in requested}
    assert "alice" in audited
    assert "ghost-does-not-exist" in audited


# =============================================================================
# token: verify / single-use / expiry / garbage
# =============================================================================
def test_valid_token_verifies_to_user():
    u = _mkuser("alice")
    token = auth.generate_reset_token(u)
    got = auth.verify_reset_token(token)
    assert got is not None and got.username == "alice"


def test_token_is_single_use_after_successful_reset():
    u = _mkuser("alice")
    token = auth.generate_reset_token(u)

    ok, err, cat = auth.reset_password_with_token(token, "BrandNew123")
    assert ok is True and err == "" and cat == ""

    # The pwv fingerprint changed with the new hash -> the same token is now dead.
    assert auth.verify_reset_token(token) is None
    ok2, _, cat2 = auth.reset_password_with_token(token, "AnotherOne123")
    assert ok2 is False and cat2 == "invalid_token"


def test_garbage_token_rejected():
    assert auth.verify_reset_token("") is None
    assert auth.verify_reset_token("not-a-real-token") is None
    ok, _, cat = auth.reset_password_with_token("not-a-real-token", "BrandNew123")
    assert ok is False and cat == "invalid_token"


def test_expired_token_rejected():
    u = _mkuser("alice")
    token = auth.generate_reset_token(u)
    # A negative max_age forces the signer to treat any token as already expired.
    assert auth.verify_reset_token(token, max_age=-1) is None


def test_reset_enforces_password_policy_and_keeps_token_usable():
    u = _mkuser("alice")
    token = auth.generate_reset_token(u)

    ok, err, cat = auth.reset_password_with_token(token, "weak")
    assert ok is False and cat == "policy" and err
    # Policy failure did not rotate the hash, so the token is still valid.
    assert auth.verify_reset_token(token) is not None
    # ...and a compliant password now succeeds with the same token.
    ok2, _, cat2 = auth.reset_password_with_token(token, "BrandNew123")
    assert ok2 is True and cat2 == ""


def test_successful_reset_clears_lock_and_failed_attempts():
    _mkuser("alice")
    # Rack up failures and lock the account.
    for _ in range(auth.ACCOUNT_LOCKOUT_THRESHOLD):
        auth._record_failed_login("alice")
    locked = auth.get_user("alice")
    assert locked.locked is True
    assert locked.failed_attempts >= auth.ACCOUNT_LOCKOUT_THRESHOLD

    token = auth.generate_reset_token(locked)      # pwv unchanged by lockout
    ok, _, _ = auth.reset_password_with_token(token, "BrandNew123")
    assert ok is True

    after = auth.get_user("alice")
    assert after.locked is False
    assert after.failed_attempts == 0


def test_token_rejected_when_user_disabled_after_issue():
    u = _mkuser("alice")
    token = auth.generate_reset_token(u)
    auth.update_user("alice", enabled=False)
    assert auth.verify_reset_token(token) is None
    ok, _, cat = auth.reset_password_with_token(token, "BrandNew123")
    assert ok is False and cat == "invalid_token"


# =============================================================================
# routes: /forgot-password — NO user enumeration
# =============================================================================
def test_forgot_password_get_renders(client):
    r = client.get("/forgot-password")
    assert r.status_code == 200


def test_forgot_password_identical_response_for_known_and_unknown(client, monkeypatch):
    """The response for a real user and a non-existent one must be byte-for-byte
    identical (same status, same body) — the only enumeration-safe behaviour."""
    _mkuser("alice", email="alice@example.com")
    # SMTP disabled (default post-reset_state): no send is attempted for either.
    sent = []
    monkeypatch.setattr(email_service, "send_email",
                        lambda *a, **k: sent.append(a))

    r_known = client.post("/forgot-password", data={"identifier": "alice"})
    r_unknown = client.post("/forgot-password", data={"identifier": "ghost"})

    assert r_known.status_code == 200
    assert r_unknown.status_code == 200
    assert r_known.text == r_unknown.text          # no enumeration signal
    assert sent == []                              # SMTP disabled -> nothing sent


def test_forgot_password_sends_only_for_resolvable_user(client, monkeypatch):
    """With SMTP enabled the email is dispatched for a real user-with-email but
    never for an unknown identifier — yet the client response stays generic."""
    _mkuser("alice", email="alice@example.com")
    _enable_smtp()

    sent = []
    monkeypatch.setattr(email_service, "send_email",
                        lambda to, *a, **k: sent.append(to))

    r_unknown = client.post("/forgot-password", data={"identifier": "ghost"})
    assert r_unknown.status_code == 200
    assert sent == []                              # nothing sent for a miss

    r_known = client.post("/forgot-password", data={"identifier": "alice"})
    assert r_known.status_code == 200
    assert sent == ["alice@example.com"]           # dispatched to the mailbox
    # Response body is the same generic confirmation regardless of the hit.
    assert r_known.text == r_unknown.text


def test_forgot_password_rate_limited(client, monkeypatch):
    """When the per-IP limiter has blocked the client, the route still returns
    the generic confirmation but skips resolution and dispatch entirely."""
    _mkuser("alice", email="alice@example.com")
    _enable_smtp()

    sent = []
    monkeypatch.setattr(email_service, "send_email",
                        lambda *a, **k: sent.append(a))

    # Force the shared limiter into the blocked state for the TestClient IP.
    now = time.time()
    for ip in ("testclient", "unknown"):
        auth._rate_limit_store[ip] = auth._RateLimitRecord(
            count=auth.RATE_LIMIT_MAX_ATTEMPTS,
            first_attempt=now,
            blocked_until=now + auth.RATE_LIMIT_WINDOW_SECONDS,
        )

    r = client.post("/forgot-password", data={"identifier": "alice"})
    assert r.status_code == 200                    # still generic
    assert sent == []                              # blocked -> no send attempted


# =============================================================================
# routes: /reset-password
# =============================================================================
def test_reset_page_valid_token_shows_form(client):
    u = _mkuser("alice")
    token = auth.generate_reset_token(u)
    r = client.get("/reset-password", params={"token": token})
    assert r.status_code == 200
    assert 'name="token"' in r.text
    assert token in r.text
    assert "Link invalid or expired" not in r.text


def test_reset_page_invalid_token_shows_generic_state(client):
    r = client.get("/reset-password", params={"token": "garbage"})
    assert r.status_code == 200
    assert "Link invalid or expired" in r.text


def test_reset_post_success_updates_password(client):
    u = _mkuser("alice")
    token = auth.generate_reset_token(u)
    r = client.post("/reset-password", data={
        "token": token, "password": "BrandNew123", "confirm_password": "BrandNew123"})
    assert r.status_code == 200
    assert "Password updated" in r.text
    # The new password authenticates; the old one no longer does.
    assert auth.authenticate_user("alice", "BrandNew123") is not None
    assert auth.authenticate_user("alice", "Str0ngPass1") is None


def test_reset_post_password_mismatch_re_renders_form(client):
    u = _mkuser("alice")
    token = auth.generate_reset_token(u)
    r = client.post("/reset-password", data={
        "token": token, "password": "BrandNew123", "confirm_password": "Different123"})
    assert r.status_code == 200
    assert "Reset your password" in r.text        # form re-rendered, still valid
    # Password unchanged.
    assert auth.authenticate_user("alice", "Str0ngPass1") is not None


def test_reset_post_policy_failure_re_renders_form(client):
    u = _mkuser("alice")
    token = auth.generate_reset_token(u)
    r = client.post("/reset-password", data={
        "token": token, "password": "weak", "confirm_password": "weak"})
    assert r.status_code == 200
    assert "Reset your password" in r.text        # form with error, token kept
    assert auth.authenticate_user("alice", "Str0ngPass1") is not None


def test_reset_post_reused_token_shows_generic_state(client):
    u = _mkuser("alice")
    token = auth.generate_reset_token(u)
    first = client.post("/reset-password", data={
        "token": token, "password": "BrandNew123", "confirm_password": "BrandNew123"})
    assert "Password updated" in first.text
    # Same token again -> superseded -> generic invalid/expired state.
    again = client.post("/reset-password", data={
        "token": token, "password": "AnotherOne123", "confirm_password": "AnotherOne123"})
    assert again.status_code == 200
    assert "Link invalid or expired" in again.text
