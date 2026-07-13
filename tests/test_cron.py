"""Pure unit tests for the zero-dependency 5-field cron module."""
from datetime import datetime, timezone

import pytest

import app.cron as cron


def _utc(y, mo, d, h, mi):
    return datetime(y, mo, d, h, mi, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# parse: acceptance
# --------------------------------------------------------------------------
@pytest.mark.parametrize("expr", [
    "* * * * *",
    "30 2 * * *",
    "*/15 * * * 1-5",
    "0 0 1,15 * *",
    "5/15 * * * *",
    "0 0 29 2 *",
    "0 0 * * 7",       # Sunday alias
])
def test_parse_accepts_valid(expr):
    fields = cron.parse(expr)
    assert len(fields) == 5
    assert all(isinstance(s, set) and s for s in fields)


def test_parse_folds_dow_7_to_sunday():
    fields = cron.parse("0 0 * * 7")
    assert 0 in fields[4]
    assert 7 not in fields[4]


def test_parse_step_and_range():
    fields = cron.parse("*/15 * * * *")
    assert fields[0] == {0, 15, 30, 45}
    fields = cron.parse("0 0 1,15 * *")
    assert fields[2] == {1, 15}
    fields = cron.parse("0 9-17 * * *")
    assert fields[1] == set(range(9, 18))


# --------------------------------------------------------------------------
# parse: rejection
# --------------------------------------------------------------------------
@pytest.mark.parametrize("expr", [
    "* * * *",          # 4 fields
    "* * * * * *",      # 6 fields
    "abc * * * *",      # letters
    "*/0 * * * *",      # zero step
    "60 * * * *",       # minute out of range
    "* 24 * * *",       # hour out of range
    "0 0 32 * *",       # dom out of range
    "0 0 * 13 *",       # month out of range
    "0 0 * * 8",        # dow out of range
    "@daily",           # macro
    "",                 # empty
    "5-1 * * * *",      # inverted range
])
def test_parse_rejects_invalid(expr):
    with pytest.raises(ValueError):
        cron.parse(expr)


# --------------------------------------------------------------------------
# matches: day-of-week mapping and OR-semantics
# --------------------------------------------------------------------------
def test_matches_dow_sunday_mapping():
    fields = cron.parse("0 0 * * 0")  # Sundays only
    # 2026-07-12 is a Sunday, 2026-07-13 is a Monday.
    assert cron.matches(fields, _utc(2026, 7, 12, 0, 0)) is True
    assert cron.matches(fields, _utc(2026, 7, 13, 0, 0)) is False


def test_matches_dow_monday():
    fields = cron.parse("0 0 * * 1")  # Mondays only
    assert cron.matches(fields, _utc(2026, 7, 13, 0, 0)) is True   # Monday
    assert cron.matches(fields, _utc(2026, 7, 12, 0, 0)) is False  # Sunday


def test_matches_dom_dow_or_semantics():
    # Both dom and dow restricted -> fire if EITHER matches.
    fields = cron.parse("0 0 13 * 5")  # 13th OR Friday
    # 2026-07-13 is a Monday and the 13th -> dom matches.
    assert cron.matches(fields, _utc(2026, 7, 13, 0, 0)) is True
    # 2026-07-17 is a Friday but not the 13th -> dow matches.
    assert cron.matches(fields, _utc(2026, 7, 17, 0, 0)) is True
    # 2026-07-14 is a Tuesday and not the 13th -> neither.
    assert cron.matches(fields, _utc(2026, 7, 14, 0, 0)) is False


def test_matches_dom_only_uses_and():
    # Only dom restricted -> plain match on day-of-month, any weekday.
    fields = cron.parse("0 0 15 * *")
    assert cron.matches(fields, _utc(2026, 7, 15, 0, 0)) is True
    assert cron.matches(fields, _utc(2026, 7, 16, 0, 0)) is False


def test_matches_minute_hour():
    fields = cron.parse("30 2 * * *")
    assert cron.matches(fields, _utc(2026, 7, 13, 2, 30)) is True
    assert cron.matches(fields, _utc(2026, 7, 13, 2, 31)) is False
    assert cron.matches(fields, _utc(2026, 7, 13, 3, 30)) is False


# --------------------------------------------------------------------------
# next_run / next_runs
# --------------------------------------------------------------------------
def test_next_run_daily():
    nxt = cron.next_run("30 2 * * *", _utc(2026, 7, 13, 1, 0))
    assert nxt == _utc(2026, 7, 13, 2, 30)


def test_next_run_is_strictly_after():
    # Called exactly at a fire minute -> returns the NEXT one, not now.
    nxt = cron.next_run("30 2 * * *", _utc(2026, 7, 13, 2, 30))
    assert nxt == _utc(2026, 7, 14, 2, 30)


def test_next_runs_sequence():
    runs = cron.next_runs("0 0 * * *", _utc(2026, 7, 13, 12, 0), 3)
    assert runs == [
        _utc(2026, 7, 14, 0, 0),
        _utc(2026, 7, 15, 0, 0),
        _utc(2026, 7, 16, 0, 0),
    ]


def test_next_run_feb_29_bounded_search():
    # From mid-2026 the next Feb 29 is 2028-02-29 (a leap year).
    nxt = cron.next_run("0 0 29 2 *", _utc(2026, 7, 13, 0, 0))
    assert nxt == _utc(2028, 2, 29, 0, 0)


def test_next_run_impossible_returns_none():
    # Feb 31 never happens.
    assert cron.next_run("0 0 31 2 *", _utc(2026, 7, 13, 0, 0)) is None


# --------------------------------------------------------------------------
# min_interval_minutes
# --------------------------------------------------------------------------
def test_min_interval_every_15():
    assert cron.min_interval_minutes("*/15 * * * *") == 15


def test_min_interval_every_minute():
    assert cron.min_interval_minutes("* * * * *") == 1


def test_min_interval_daily():
    assert cron.min_interval_minutes("30 2 * * *") == 24 * 60


def test_min_interval_hourly():
    assert cron.min_interval_minutes("0 * * * *") == 60


# --------------------------------------------------------------------------
# is_due (no back-fill floor)
# --------------------------------------------------------------------------
def test_is_due_true_when_matching_and_after_start():
    now = _utc(2026, 7, 13, 2, 30)
    started = _utc(2026, 7, 13, 0, 0).timestamp()
    assert cron.is_due("30 2 * * *", now, started) is True


def test_is_due_false_before_start():
    now = _utc(2026, 7, 13, 2, 30)
    started = _utc(2026, 7, 13, 3, 0).timestamp()  # scheduler started later
    assert cron.is_due("30 2 * * *", now, started) is False


def test_is_due_false_when_not_matching():
    now = _utc(2026, 7, 13, 2, 31)
    started = _utc(2026, 7, 13, 0, 0).timestamp()
    assert cron.is_due("30 2 * * *", now, started) is False
