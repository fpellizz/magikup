"""
Mutable run-state for scheduled backups.

Definitions live in ``config.ini`` under ``[schedule:<name>]`` sections; this
module owns the separate ``config/schedule_state.json`` file (a sibling of
``config.ini``) that holds only mutable, per-run state — ``last_run``,
``last_status``, ``consecutive_failures`` and friends. Keeping run-state out of
the exportable INI prevents export from leaking run history and prevents import
from forging it.

Writes are atomic (temp file + ``os.replace``). A missing or corrupt state file
is treated as empty.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict

from .config import CONFIG_FILE

# Sibling of config.ini. Referenced through the module global so tests can
# monkeypatch it (matching how the suite redirects cfg.CONFIG_FILE).
STATE_FILE = Path(CONFIG_FILE).parent / "schedule_state.json"


def load() -> Dict[str, Any]:
    """Load the schedule-state map. Missing/corrupt file returns ``{}``."""
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _save(state: Dict[str, Any]) -> None:
    """Atomically write the full state map (temp file + os.replace)."""
    path = Path(STATE_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".schedule_state-", suffix=".tmp",
                               dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def mark(name: str, **fields: Any) -> None:
    """Merge ``fields`` into ``state[name]`` and persist atomically."""
    state = load()
    entry = state.get(name, {})
    if not isinstance(entry, dict):
        entry = {}
    entry.update(fields)
    state[name] = entry
    _save(state)


def drop(name: str) -> None:
    """Remove a schedule's run-state entry, if present."""
    state = load()
    if name in state:
        del state[name]
        _save(state)
