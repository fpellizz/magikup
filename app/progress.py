"""In-memory registry of in-flight remote-storage transfers.

Push/pull operations run server-side (MagikUp -> remote target), so the browser
can't observe byte progress directly. Each transfer registers here and updates
its byte count as it streams; the frontend polls a snapshot to render one
progress bar per active operation.

Thread-safe: transfers run in the FastAPI threadpool (sync `def` endpoints), so
updates and snapshots are guarded by a lock.
"""

import threading
import time
import uuid
from typing import Any, Dict, List, Optional

_lock = threading.Lock()
_ops: Dict[str, Dict[str, Any]] = {}

# Keep finished operations around briefly so the UI can render their final
# state (100% / error) before they disappear.
_RETAIN_DONE_SECONDS = 4.0
# Hard cap so a pathological loop can never grow the registry without bound.
_MAX_OPS = 200


def start(direction: str, kind: str, target: str, label: str, total: int = 0) -> str:
    """Register a new operation. Returns its id.

    direction: 'upload' | 'download'
    kind:      's3' | 'fileshare' | 'filebrowser' | 'link'
    target:    configured target name (or host for a link)
    label:     filename / object shown to the user
    """
    op_id = uuid.uuid4().hex[:12]
    with _lock:
        if len(_ops) >= _MAX_OPS:
            _prune_locked(force=True)
        _ops[op_id] = {
            "id": op_id,
            "direction": direction,
            "kind": kind,
            "target": target,
            "label": label,
            "total": int(total or 0),
            "done": 0,
            "status": "running",
            "error": "",
            "ended_at": None,
        }
    return op_id


def update(op_id: str, done: Optional[int] = None, total: Optional[int] = None) -> None:
    """Update byte counters for an operation (no-op if unknown/finished)."""
    with _lock:
        op = _ops.get(op_id)
        if not op or op["status"] != "running":
            return
        if total is not None:
            op["total"] = int(total)
        if done is not None:
            op["done"] = int(done)


def finish(op_id: str, status: str = "done", error: str = "") -> None:
    """Mark an operation done/error; it lingers briefly then is pruned."""
    with _lock:
        op = _ops.get(op_id)
        if not op:
            return
        op["status"] = status
        op["error"] = error or ""
        if status == "done" and op["total"]:
            op["done"] = op["total"]
        op["ended_at"] = time.monotonic()


def _prune_locked(force: bool = False) -> None:
    now = time.monotonic()
    for oid in list(_ops):
        op = _ops[oid]
        if op["ended_at"] is not None and (force or now - op["ended_at"] > _RETAIN_DONE_SECONDS):
            del _ops[oid]


def snapshot() -> List[Dict[str, Any]]:
    """Return current operations (running + recently finished), pruning stale ones."""
    with _lock:
        _prune_locked()
        out = []
        for op in _ops.values():
            total = op["total"]
            percent = int(op["done"] * 100 / total) if total else None
            if percent is not None:
                percent = max(0, min(100, percent))
            out.append({
                "id": op["id"],
                "direction": op["direction"],
                "kind": op["kind"],
                "target": op["target"],
                "label": op["label"],
                "done": op["done"],
                "total": total,
                "percent": percent,
                "status": op["status"],
                "error": op["error"],
            })
        return out


def clear() -> None:
    """Remove all operations (used by tests)."""
    with _lock:
        _ops.clear()
