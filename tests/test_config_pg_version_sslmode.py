"""Unit tests for the per-endpoint pg client version + sslmode config layer
(save/get round-trip, defaults, backward-compatible parsing of pre-3.7.0
endpoint lines, and the validate_pg_version / validate_sslmode / pg_tool_path
helpers). Uses the temp-config `reset_state` fixture from conftest."""
import pytest

import app.config as cfg


def _sample(name="prod", **over):
    base = dict(
        name=name,
        host="db.example.com",
        port=5432,
        username="postgres",
        password="secret",
        use_ssm=False,
        jumphost_alias="",
        read_only=False,
        backup_use_replica=False,
        replica_host="",
    )
    base.update(over)
    return cfg.DatabaseConfig(**base)


# --------------------------------------------------------------------------
# defaults
# --------------------------------------------------------------------------

def test_defaults_are_17_and_prefer():
    ep = _sample()
    assert ep.pg_version == "17"
    assert ep.sslmode == "prefer"


def test_save_get_uses_defaults_when_unset():
    cfg.save_database_config(_sample("epdef"))
    got = cfg.get_database_endpoint("epdef")
    assert got is not None
    assert got.pg_version == "17"
    assert got.sslmode == "prefer"


# --------------------------------------------------------------------------
# round-trip with explicit values
# --------------------------------------------------------------------------

@pytest.mark.parametrize("version", ["14", "15", "16", "17"])
def test_round_trip_pg_version(version):
    cfg.save_database_config(_sample("epv", pg_version=version, sslmode="require"))
    got = cfg.get_database_endpoint("epv")
    assert got.pg_version == version
    assert got.sslmode == "require"


@pytest.mark.parametrize("mode", list(cfg.VALID_SSLMODES))
def test_round_trip_sslmode(mode):
    cfg.save_database_config(_sample("eps", sslmode=mode))
    got = cfg.get_database_endpoint("eps")
    assert got.sslmode == mode


# --------------------------------------------------------------------------
# backward compatibility: pre-3.7.0 endpoint lines had no pg_version/sslmode
# --------------------------------------------------------------------------

def test_legacy_line_without_new_fields_parses_with_defaults():
    """An endpoint value written before 3.7.0 (9 pipe-delimited fields) must
    still parse, defaulting pg_version=17 / sslmode=prefer."""
    c = cfg.read_config()
    if not c.has_section("endpoints"):
        c.add_section("endpoints")
    # host|port|username|password|use_ssm|jumphost|read_only|backup_use_replica|replica_host
    enc = cfg.encrypt_password("plaintextpw")
    legacy = f"db.old.example.com|5432|postgres|{enc}|false||false|false|"
    c.set("endpoints", "legacy", legacy)
    cfg.write_config(c)

    got = cfg.get_database_endpoint("legacy")
    assert got is not None
    assert got.host == "db.old.example.com"
    assert got.pg_version == "17"
    assert got.sslmode == "prefer"


# --------------------------------------------------------------------------
# validators
# --------------------------------------------------------------------------

@pytest.mark.parametrize("version", ["14", "15", "16", "17", 17])
def test_validate_pg_version_ok(version):
    assert cfg.validate_pg_version(version) in cfg.SUPPORTED_PG_VERSIONS


@pytest.mark.parametrize("version", ["13", "18", "9.6", "", "abc"])
def test_validate_pg_version_rejects(version):
    with pytest.raises(ValueError):
        cfg.validate_pg_version(version)


def test_validate_sslmode_ok():
    for m in cfg.VALID_SSLMODES:
        assert cfg.validate_sslmode(m) == m


@pytest.mark.parametrize("mode", ["bogus", "verifyfull", "ssl"])
def test_validate_sslmode_rejects(mode):
    with pytest.raises(ValueError):
        cfg.validate_sslmode(mode)


# --------------------------------------------------------------------------
# pg_tool_path
# --------------------------------------------------------------------------

@pytest.mark.parametrize("tool", ["pg_dump", "pg_restore"])
@pytest.mark.parametrize("version", ["14", "15", "16", "17"])
def test_pg_tool_path_resolves(tool, version):
    assert cfg.pg_tool_path(tool, version) == f"/usr/lib/postgresql/{version}/bin/{tool}"


def test_pg_tool_path_rejects_bad_tool():
    with pytest.raises(ValueError):
        cfg.pg_tool_path("rm", "17")


def test_pg_tool_path_rejects_bad_version():
    with pytest.raises(ValueError):
        cfg.pg_tool_path("pg_dump", "13")
