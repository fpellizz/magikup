"""API integration for the /api/schedules endpoints (FastAPI TestClient).

The default `client` fixture acts as an admin; `operator_client` acts as an
operator (admin routes denied) for role-gating assertions."""
import app.config as cfg


def _mkendpoint(name="prod-aurora"):
    """Register a direct (non-SSM) endpoint so schedule saves resolve it."""
    cfg.save_database_config(cfg.DatabaseConfig(
        name=name, host="127.0.0.1", port=5432, username="postgres", password="pw"))


def _mks3(name="offsite-eu"):
    cfg.save_s3_storage_config(cfg.S3StorageConfig(name=name, bucket="b"))


def _payload(name="nightly-prod", **over):
    p = {
        "name": name,
        "cron": "30 2 * * *",
        "endpoint": "prod-aurora",
        "database": "appdb",
        "enabled": True,
        "dest_kind": "none",
        "keep_last_n": 0,
    }
    p.update(over)
    return p


# --------------------------------------------------------------------------
# POST /api/schedules — happy path + validation 400s
# --------------------------------------------------------------------------
def test_create_schedule_happy_path(client):
    _mkendpoint()
    r = client.post("/api/schedules", json=_payload())
    assert r.status_code == 200, r.text
    assert r.json() == {"success": True, "name": "nightly-prod"}
    assert cfg.get_schedule("nightly-prod") is not None


def test_create_schedule_with_s3_destination(client):
    _mkendpoint()
    _mks3()
    r = client.post("/api/schedules", json=_payload(
        dest_kind="s3", dest_target="offsite-eu", delete_local_after_copy=True, keep_last_n=7))
    assert r.status_code == 200, r.text
    got = cfg.get_schedule("nightly-prod")
    assert got.dest_kind == "s3" and got.dest_target == "offsite-eu"


def test_reject_bad_cron(client):
    _mkendpoint()
    r = client.post("/api/schedules", json=_payload(cron="not a cron"))
    assert r.status_code == 400


def test_reject_too_frequent_cron(client):
    _mkendpoint()
    # every minute -> below the 15-minute floor
    r = client.post("/api/schedules", json=_payload(cron="* * * * *"))
    assert r.status_code == 400
    assert "15 minutes" in r.text


def test_reject_impossible_cron(client):
    _mkendpoint()
    # Feb 30 never occurs -> must be rejected (would otherwise make next_run scan
    # the whole horizon on every list poll).
    r = client.post("/api/schedules", json=_payload(cron="0 0 30 2 *"))
    assert r.status_code == 400
    assert "never fires" in r.text.lower()


def test_reject_missing_endpoint(client):
    # endpoint not registered
    r = client.post("/api/schedules", json=_payload(endpoint="ghost"))
    assert r.status_code == 400
    assert "ghost" in r.text


def test_reject_missing_dest_target(client):
    _mkendpoint()
    r = client.post("/api/schedules", json=_payload(dest_kind="s3", dest_target=""))
    assert r.status_code == 400


def test_reject_delete_with_no_destination(client):
    _mkendpoint()
    r = client.post("/api/schedules",
                    json=_payload(dest_kind="none", delete_local_after_copy=True))
    assert r.status_code == 400


def test_reject_51st_schedule(client, monkeypatch):
    import app.main as main
    _mkendpoint()
    monkeypatch.setattr(main, "_MAX_SCHEDULES", 2)
    assert client.post("/api/schedules", json=_payload("s-one")).status_code == 200
    assert client.post("/api/schedules", json=_payload("s-two")).status_code == 200
    r = client.post("/api/schedules", json=_payload("s-three"))
    assert r.status_code == 400
    assert "Maximum" in r.text
    # updating an existing one is still allowed at the cap
    assert client.post("/api/schedules", json=_payload("s-one", cron="0 4 * * *")).status_code == 200


def test_reject_unknown_field(client):
    _mkendpoint()
    # extra="forbid": no arbitrary option string reaches pg_dump
    body = _payload()
    body["arbitrary_pg_dump_flag"] = "--evil"
    r = client.post("/api/schedules", json=body)
    assert r.status_code == 422


# --------------------------------------------------------------------------
# GET list / GET single
# --------------------------------------------------------------------------
def test_list_computes_next_run(client):
    _mkendpoint()
    client.post("/api/schedules", json=_payload())
    r = client.get("/api/schedules")
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is True
    entry = next(s for s in data["schedules"] if s["name"] == "nightly-prod")
    assert entry["next_run"] is not None
    assert entry["next_run"].endswith("+00:00")  # UTC
    assert entry["cron_human"]  # human description present


def test_get_single_404(client):
    assert client.get("/api/schedules/nope").status_code == 404


def test_get_single_returns_full_config(client):
    _mkendpoint()
    client.post("/api/schedules", json=_payload(schemas=["public", "reporting"]))
    r = client.get("/api/schedules/nightly-prod")
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "nightly-prod"
    assert body["schemas"] == ["public", "reporting"]


# --------------------------------------------------------------------------
# PATCH enabled / DELETE
# --------------------------------------------------------------------------
def test_patch_enabled(client):
    _mkendpoint()
    client.post("/api/schedules", json=_payload(enabled=True))
    r = client.patch("/api/schedules/nightly-prod/enabled", json={"enabled": False})
    assert r.status_code == 200
    assert cfg.get_schedule("nightly-prod").enabled is False
    # and back on
    client.patch("/api/schedules/nightly-prod/enabled", json={"enabled": True})
    assert cfg.get_schedule("nightly-prod").enabled is True


def test_patch_enabled_404(client):
    assert client.patch("/api/schedules/nope/enabled", json={"enabled": True}).status_code == 404


def test_delete_schedule(client):
    _mkendpoint()
    client.post("/api/schedules", json=_payload())
    assert client.delete("/api/schedules/nightly-prod").status_code == 200
    assert cfg.get_schedule("nightly-prod") is None


def test_delete_404(client):
    assert client.delete("/api/schedules/nope").status_code == 404


# --------------------------------------------------------------------------
# cron preview
# --------------------------------------------------------------------------
def test_cron_preview_valid(client):
    r = client.post("/api/schedules/cron/preview", json={"cron": "30 2 * * *", "count": 3})
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert body["human"]
    assert len(body["next_runs"]) == 3
    assert body["min_interval_minutes"] == 24 * 60


def test_cron_preview_invalid(client):
    r = client.post("/api/schedules/cron/preview", json={"cron": "99 * * * *"})
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is False
    assert body["error"]
    assert body["next_runs"] == []


def test_cron_preview_too_frequent_warns(client):
    r = client.post("/api/schedules/cron/preview", json={"cron": "* * * * *"})
    body = r.json()
    assert body["valid"] is True
    assert body["min_interval_minutes"] == 1
    assert body["warning"]


# --------------------------------------------------------------------------
# run-now
# --------------------------------------------------------------------------
def test_run_now_409_when_already_running(client, monkeypatch):
    import app.main as main
    _mkendpoint()
    client.post("/api/schedules", json=_payload())
    # Force the reservation to fail -> the run-now 409 guard fires.
    monkeypatch.setattr(main.sched_engine.get_scheduler(), "reserve", lambda name: False)
    r = client.post("/api/schedules/nightly-prod/run")
    assert r.status_code == 409


def test_run_now_404(client):
    assert client.post("/api/schedules/nope/run").status_code == 404


# --------------------------------------------------------------------------
# role gating
# --------------------------------------------------------------------------
# NOTE: `client` and `operator_client` both mutate the single shared
# app.dependency_overrides, so they must never be used in the same test. These
# seed schedules via `cfg` directly and use only `operator_client`.
def _seed(name="nightly-prod"):
    _mkendpoint()
    cfg.save_schedule(cfg.ScheduleConfig(
        name=name, cron="30 2 * * *", endpoint="prod-aurora", database="appdb"))


def test_operator_cannot_create(operator_client):
    _mkendpoint()
    # POST is require_admin -> denied for operator
    assert operator_client.post("/api/schedules", json=_payload()).status_code == 403


def test_operator_cannot_delete_patch_or_get_single(operator_client):
    _seed()
    assert operator_client.delete("/api/schedules/nightly-prod").status_code == 403
    assert operator_client.patch(
        "/api/schedules/nightly-prod/enabled", json={"enabled": False}).status_code == 403
    assert operator_client.get("/api/schedules/nightly-prod").status_code == 403


def test_operator_can_list_and_preview(operator_client):
    _seed()
    assert operator_client.get("/api/schedules").status_code == 200
    assert operator_client.post(
        "/api/schedules/cron/preview", json={"cron": "30 2 * * *"}).status_code == 200


def test_operator_run_now_reaches_handler(operator_client, monkeypatch):
    import app.main as main
    _seed()
    # run-now is require_operator; a 409 (not 403) proves the operator passed authz.
    monkeypatch.setattr(main.sched_engine.get_scheduler(), "reserve", lambda name: False)
    assert operator_client.post("/api/schedules/nightly-prod/run").status_code == 409
