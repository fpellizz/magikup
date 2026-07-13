"""Unit tests for the [schedule:<name>] config layer (save/get/delete +
validate_schedule_name). Uses the temp-config `reset_state` fixture from
conftest; no TestClient needed."""
import pytest

import app.config as cfg


def _sample(name="nightly-prod", **over):
    base = dict(
        name=name,
        cron="30 2 * * *",
        endpoint="prod-aurora",
        database="appdb",
        enabled=True,
        large_objects=True,
        no_owner=True,
        no_privileges=False,
        no_tablespaces=True,
        no_comments=False,
        data_only=False,
        schema_only=False,
        clean=True,
        create=False,
        schemas="public,reporting",
        exclude_table="audit_*",
        exclude_table_data="logs",
        exclude_schema="tmp",
        dest_kind="s3",
        dest_target="offsite-eu",
        delete_local_after_copy=True,
        keep_last_n=7,
    )
    base.update(over)
    return cfg.ScheduleConfig(**base)


# --------------------------------------------------------------------------
# save / get round-trip
# --------------------------------------------------------------------------
def test_save_get_roundtrip_all_field_types():
    cfg.save_schedule(_sample())
    got = cfg.get_schedule("nightly-prod")
    assert got is not None
    # strings
    assert got.cron == "30 2 * * *"
    assert got.endpoint == "prod-aurora"
    assert got.database == "appdb"
    # CSV strings preserved verbatim
    assert got.schemas == "public,reporting"
    assert got.exclude_table == "audit_*"
    assert got.exclude_schema == "tmp"
    assert got.dest_kind == "s3"
    assert got.dest_target == "offsite-eu"
    # booleans (both truthy and falsy survive the str(x).lower() round-trip)
    assert got.enabled is True
    assert got.large_objects is True
    assert got.no_privileges is False
    assert got.no_comments is False
    assert got.clean is True
    assert got.delete_local_after_copy is True
    # int
    assert got.keep_last_n == 7
    assert isinstance(got.keep_last_n, int)


def test_get_schedules_enumerates_multiple():
    cfg.save_schedule(_sample("one"))
    cfg.save_schedule(_sample("two", cron="0 3 * * *"))
    all_scheds = cfg.get_schedules()
    assert set(all_scheds) == {"one", "two"}
    assert all_scheds["two"].cron == "0 3 * * *"


def test_get_schedule_unknown_returns_none():
    assert cfg.get_schedule("does-not-exist") is None


def test_save_update_overwrites_in_place():
    cfg.save_schedule(_sample("edit-me", enabled=True, keep_last_n=3))
    cfg.save_schedule(_sample("edit-me", enabled=False, keep_last_n=9))
    got = cfg.get_schedule("edit-me")
    assert got.enabled is False
    assert got.keep_last_n == 9
    # still a single section, not duplicated
    assert list(cfg.get_schedules()) == ["edit-me"]


def test_delete_schedule_removes_it():
    cfg.save_schedule(_sample("temp"))
    assert cfg.get_schedule("temp") is not None
    cfg.delete_schedule("temp")
    assert cfg.get_schedule("temp") is None


def test_delete_missing_is_noop():
    # Should not raise even when the section does not exist.
    cfg.delete_schedule("never-existed")


def test_local_only_destination_roundtrip():
    cfg.save_schedule(_sample("local", dest_kind="none", dest_target="",
                              delete_local_after_copy=False, keep_last_n=0))
    got = cfg.get_schedule("local")
    assert got.dest_kind == "none"
    assert got.dest_target == ""
    assert got.delete_local_after_copy is False
    assert got.keep_last_n == 0


# --------------------------------------------------------------------------
# validate_schedule_name
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name", [
    "nightly-prod",
    "ab",
    "a_b-9",
    "A1",
    "x" * 50,
])
def test_validate_name_accepts(name):
    cfg.validate_schedule_name(name)  # must not raise


@pytest.mark.parametrize("name", [
    "a",             # too short (1 char)
    "x" * 51,        # too long
    "bad name",      # space
    "has.dot",       # dot not allowed
    "s3:x",          # reserved prefix
    "schedule:x",    # reserved prefix
    "fileshare:y",   # reserved prefix
    "settings",      # reserved section name
    "auth",          # reserved section name
    "]",             # illegal char / section-injection
    "a=b",           # illegal char
    "a%b",           # illegal char (INI interpolation surface)
    "",              # empty
])
def test_validate_name_rejects(name):
    with pytest.raises(ValueError):
        cfg.validate_schedule_name(name)


def test_save_rejects_invalid_name():
    with pytest.raises(ValueError):
        cfg.save_schedule(_sample("bad name"))


# --------------------------------------------------------------------------
# no secret leakage
# --------------------------------------------------------------------------
def test_no_secret_written_to_schedule_section():
    """A schedule references an endpoint/target by name only — the section on
    disk must contain no encrypted-secret marker or password field."""
    cfg.save_schedule(_sample("secure"))
    config = cfg.read_config()
    section = dict(config["schedule:secure"])
    assert "password" not in section
    assert "secret_access_key" not in section
    assert "access_key_id" not in section
    # No encrypted token marker anywhere in the section values.
    for value in section.values():
        assert "ENC:" not in value
    # Raw file text likewise carries no secret markers for this section.
    raw = cfg.CONFIG_FILE.read_text()
    assert "ENC:" not in raw.split("[schedule:secure]", 1)[1]
