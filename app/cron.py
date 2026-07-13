"""
Zero-dependency standard 5-field cron support for scheduled backups.

Fields (in order): minute hour day-of-month month day-of-week
Supported tokens per field: ``*``, ``,`` (lists), ``-`` (ranges), ``*/n`` and
``a-b/s`` (steps). Day-of-week is 0-6 with Sunday=0 (``7`` is also accepted and
folded to Sunday). Day-of-month / day-of-week follow cron OR-semantics: when
BOTH are restricted a day matches if EITHER matches; otherwise they AND.

All evaluation is done in UTC. Callers pass timezone-aware UTC datetimes.
No ``@macros`` and no seconds field are supported (both raise ``ValueError``).
"""

import re
from datetime import datetime, timedelta, timezone

# Field bounds: (low, high) inclusive.
_MINUTE = (0, 59)
_HOUR = (0, 23)
_DOM = (1, 31)
_MONTH = (1, 12)
_DOW = (0, 7)  # 7 accepted as Sunday, folded to 0 after parsing

_FIELD_BOUNDS = (_MINUTE, _HOUR, _DOM, _MONTH, _DOW)

_FIELD_RE = re.compile(r"[0-9*/,\-]+")

# How far ahead next_run() will search before giving up. Generous enough to
# resolve sparse expressions such as "Feb 29" (leap-year only) across the
# century leap-year gap.
_HORIZON_MINUTES = 366 * 8 * 24 * 60


def _parse_field(field: str, lo: int, hi: int) -> set:
    """Parse a single cron field into the set of matching integers."""
    if not field or not _FIELD_RE.fullmatch(field):
        raise ValueError(f"invalid cron field: {field!r}")

    result: set = set()
    for part in field.split(","):
        if not part:
            raise ValueError(f"invalid cron field: {field!r}")

        if "/" in part:
            base, _, step_s = part.partition("/")
            if not step_s.isdigit():
                raise ValueError(f"invalid step in cron field: {part!r}")
            step = int(step_s)
            if step <= 0:
                raise ValueError(f"step must be > 0 in cron field: {part!r}")
        else:
            base = part
            step = 1

        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            a_s, _, b_s = base.partition("-")
            if not a_s.isdigit() or not b_s.isdigit():
                raise ValueError(f"invalid range in cron field: {part!r}")
            start, end = int(a_s), int(b_s)
        else:
            if not base.isdigit():
                raise ValueError(f"invalid value in cron field: {part!r}")
            start = int(base)
            # "a/step" means a, a+step, ... up to the field maximum.
            end = start if step == 1 else hi

        if start < lo or end > hi or start > end:
            raise ValueError(f"cron field {part!r} out of range [{lo}-{hi}]")

        for value in range(start, end + 1, step):
            result.add(value)

    if not result:
        raise ValueError(f"empty cron field: {field!r}")
    return result


def parse(expr: str) -> list:
    """Parse a 5-field cron expression into ``[minute, hour, dom, month, dow]``
    sets of matching integers. Raises ``ValueError`` on malformed input."""
    if not isinstance(expr, str):
        raise ValueError("cron expression must be a string")
    fields = expr.split()
    if len(fields) != 5:
        raise ValueError(
            f"cron expression must have exactly 5 fields, got {len(fields)}"
        )

    parsed = [
        _parse_field(field, lo, hi)
        for field, (lo, hi) in zip(fields, _FIELD_BOUNDS)
    ]

    # Fold day-of-week 7 (Sunday alias) into 0.
    dow = parsed[4]
    if 7 in dow:
        dow.discard(7)
        dow.add(0)

    return parsed


def matches(fields: list, dt: datetime) -> bool:
    """Return True if ``dt`` (UTC) satisfies the parsed cron ``fields``."""
    minute, hour, dom, month, dow = fields

    if dt.minute not in minute:
        return False
    if dt.hour not in hour:
        return False
    if dt.month not in month:
        return False

    # cron day-of-week: Sunday=0..Saturday=6. Python weekday(): Monday=0.
    cron_dow = (dt.weekday() + 1) % 7

    dom_restricted = dom != set(range(_DOM[0], _DOM[1] + 1))
    dow_restricted = dow != set(range(0, 7))

    dom_ok = dt.day in dom
    dow_ok = cron_dow in dow

    if dom_restricted and dow_restricted:
        return dom_ok or dow_ok
    return dom_ok and dow_ok


def next_run(expr: str, after: datetime):
    """Return the first fire time strictly after ``after`` (UTC), or None if
    none is found within the search horizon."""
    fields = parse(expr)
    if after.tzinfo is None:
        after = after.replace(tzinfo=timezone.utc)
    else:
        after = after.astimezone(timezone.utc)

    candidate = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(_HORIZON_MINUTES):
        if matches(fields, candidate):
            return candidate
        candidate += timedelta(minutes=1)
    return None


def next_runs(expr: str, after: datetime, n: int) -> list:
    """Return up to ``n`` successive fire times after ``after`` (UTC)."""
    runs = []
    cursor = after
    for _ in range(max(0, n)):
        nxt = next_run(expr, cursor)
        if nxt is None:
            break
        runs.append(nxt)
        cursor = nxt
    return runs


def is_due(expr: str, now: datetime, started_at_epoch: float) -> bool:
    """Return True if ``now`` (UTC) matches ``expr`` and is not before the
    scheduler's start time (no back-fill of missed runs)."""
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)
    if not matches(parse(expr), now):
        return False
    return now.timestamp() >= started_at_epoch


def min_interval_minutes(expr: str) -> int:
    """Smallest gap in minutes between consecutive fires, probed over a bounded
    window. Used to enforce the minimum-interval guardrail at save time.

    Expressions that fire at most once within the probe window (e.g. yearly)
    return the window length in minutes (a large value that always passes the
    guardrail)."""
    fields = parse(expr)
    # 2020 is a leap year (covers a Feb-29 fire); a 366-day window covers every
    # day-of-week and any month/day-of-month gap up to monthly.
    window_days = 366
    limit = window_days * 24 * 60
    cursor = datetime(2020, 1, 1, tzinfo=timezone.utc)
    step = timedelta(minutes=1)

    prev = None
    best = None
    for _ in range(limit):
        if matches(fields, cursor):
            if prev is not None:
                diff = int((cursor - prev).total_seconds() // 60)
                best = diff if best is None else min(best, diff)
                if best <= 1:
                    break
            prev = cursor
        cursor += step

    return best if best is not None else limit


def describe(expr: str) -> str:
    """Return a plain-language description of a cron expression. Mirrors the
    JS ``humanizeCron`` shape; best-effort with a safe fallback."""
    try:
        fields = parse(expr)
    except ValueError:
        return "Invalid schedule"

    raw = expr.split()
    minute_f, hour_f, dom_f, month_f, dow_f = raw

    def _clock(minute_set, hour_set) -> str:
        if len(minute_set) == 1 and len(hour_set) == 1:
            h = next(iter(hour_set))
            m = next(iter(minute_set))
            return f"{h:02d}:{m:02d}"
        return ""

    minute, hour, dom, month, dow = fields

    day_names = {
        0: "Sunday", 1: "Monday", 2: "Tuesday", 3: "Wednesday",
        4: "Thursday", 5: "Friday", 6: "Saturday",
    }

    # Every minute.
    if raw == ["*", "*", "*", "*", "*"]:
        return "Every minute"

    # Every N minutes.
    m = re.fullmatch(r"\*/(\d+)", minute_f)
    if m and (hour_f, dom_f, month_f, dow_f) == ("*", "*", "*", "*"):
        n = int(m.group(1))
        return "Every minute" if n == 1 else f"Every {n} minutes"

    # Hourly at a fixed minute.
    if (len(minute) == 1 and hour_f == "*"
            and (dom_f, month_f, dow_f) == ("*", "*", "*")):
        return f"Every hour at minute {next(iter(minute)):02d}"

    clock = _clock(minute, hour)

    # Weekly on specific days.
    if (clock and dom_f == "*" and month_f == "*" and dow_f != "*"):
        days = ", ".join(day_names[d] for d in sorted(dow))
        return f"Every week on {days} at {clock}"

    # Monthly on a fixed day-of-month.
    if (clock and len(dom) == 1 and month_f == "*" and dow_f == "*"):
        return f"Every month on day {next(iter(dom))} at {clock}"

    # Daily at a fixed time.
    if (clock and (dom_f, month_f, dow_f) == ("*", "*", "*")):
        return f"Every day at {clock}"

    return f"Cron schedule: {expr}"
