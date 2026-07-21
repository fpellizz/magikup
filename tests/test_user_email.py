"""Regression tests for the user `email` field persisting through the user API.

Before 4.4.1 the create/update user endpoints silently dropped `email` (the
Pydantic models had no such field and the handlers never forwarded it), so no
user ever had an email and self-service password recovery could never send.
"""
import app.auth as auth


def test_create_user_persists_email(client):
    r = client.post("/api/users", json={
        "username": "ue_bob", "password": "Passw0rd!", "role": "operator",
        "email": "ue_bob@example.com"})
    assert r.status_code == 200 and r.json().get("success")
    assert auth.get_user("ue_bob").email == "ue_bob@example.com"


def test_update_user_sets_email(client):
    client.post("/api/users", json={"username": "ue_carol", "password": "Passw0rd!", "role": "viewer"})
    assert auth.get_user("ue_carol").email == ""  # none at creation
    r = client.put("/api/users/ue_carol", json={"role": "viewer", "enabled": True,
                                             "email": "ue_carol@example.com"})
    assert r.status_code == 200 and r.json().get("success")
    assert auth.get_user("ue_carol").email == "ue_carol@example.com"


def test_invalid_email_rejected_on_create(client):
    r = client.post("/api/users", json={
        "username": "ue_dave", "password": "Passw0rd!", "role": "viewer", "email": "not-an-email"})
    assert r.status_code == 400
    assert auth.get_user("ue_dave") is None  # not created


def test_invalid_email_rejected_on_update(client):
    client.post("/api/users", json={"username": "ue_erin", "password": "Passw0rd!", "role": "viewer"})
    r = client.put("/api/users/ue_erin", json={"email": "bad"})
    assert r.status_code == 400
    assert auth.get_user("ue_erin").email == ""  # unchanged


def test_recovery_resolves_user_by_persisted_email(client):
    client.post("/api/users", json={
        "username": "ue_frank", "password": "Passw0rd!", "role": "viewer", "email": "ue_frank@example.com"})
    # request_password_reset returns a payload only when the identifier resolves
    # to an enabled user WITH an email — proving the email round-tripped.
    payload = auth.request_password_reset("ue_frank@example.com")
    assert payload and payload["username"] == "ue_frank"


def test_password_still_persists(client):
    """Sanity: passwords have always saved; keep it that way."""
    client.post("/api/users", json={"username": "ue_gina", "password": "Passw0rd!", "role": "viewer"})
    u = auth.get_user("ue_gina")
    assert u.password_hash and auth.verify_password("Passw0rd!", u.password_hash)
