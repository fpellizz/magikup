"""
In-process scheduler engine for unattended (scheduled) backups.

A single asyncio task ticks every ``_TICK_SECONDS`` and, on each tick, reads the
current schedule definitions from ``config`` and evaluates each enabled one
against its cron expression (UTC). Due schedules are launched through the
injected ``run_one`` coroutine.

Design guarantees:
* No back-fill: a ``_started_at`` floor means runs whose matched minute is
  before the scheduler started are never executed (see ``cron.is_due``).
* Per-schedule non-overlap: a name in flight (tracked in ``_running``) is not
  launched again — the 30 s tick observes each minute roughly twice.
* Global concurrency cap: at most ``_MAX_CONCURRENT`` scheduled backups run at
  once (heavy ``pg_dump`` load control); extra due schedules are skipped this
  tick (skip, not queue).
* The tick loop is wrapped so a failure evaluating one tick never kills the
  loop — the scheduler keeps ticking for the life of the process.

This module owns no HTTP surface; the internal tick is not a request.
"""

import asyncio
import logging
import time

from . import config as cfg
from . import cron

logger = logging.getLogger(__name__)

_TICK_SECONDS = 30
_MAX_CONCURRENT = 1          # tunable; a single heavy pg_dump at a time


class Scheduler:
    """Owns the tick loop and enforces non-overlap + global concurrency."""

    def __init__(self, run_one):
        # run_one: async (name, ScheduleConfig, *, trigger) -> None
        self._run_one = run_one
        self._task = None
        self._stop = asyncio.Event()
        self._running = set()        # schedule names currently in flight
        self._sem = asyncio.Semaphore(_MAX_CONCURRENT)
        self._started_at = time.time()   # no-back-fill floor (epoch seconds, UTC)

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Start the tick loop (idempotent)."""
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._started_at = time.time()
        self._task = asyncio.create_task(self._loop())
        logger.info("Scheduler started (tick=%ss, max_concurrent=%s)", _TICK_SECONDS, _MAX_CONCURRENT)

    async def stop(self) -> None:
        """Signal the loop to stop and wait briefly for it to finish."""
        self._stop.set()
        if self._task is None:
            return
        try:
            await asyncio.wait_for(self._task, timeout=5)
        except asyncio.TimeoutError:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning("Scheduler stop encountered error: %s", exc)
        finally:
            self._task = None
        logger.info("Scheduler stopped")

    # -- tick loop -----------------------------------------------------------

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self._evaluate(self._now())
            except Exception as exc:
                # Never let an evaluation error kill the loop.
                logger.exception("Scheduler tick failed: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=_TICK_SECONDS)
            except asyncio.TimeoutError:
                pass

    @staticmethod
    def _now():
        from datetime import datetime, timezone
        return datetime.now(timezone.utc)

    async def _evaluate(self, now) -> None:
        """Launch every enabled, due schedule that isn't already running."""
        schedules = cfg.get_schedules()
        for name, sched in schedules.items():
            if not sched.enabled:
                continue
            if name in self._running:
                continue
            try:
                due = cron.is_due(sched.cron, now, self._started_at)
            except ValueError:
                # A malformed cron on a stored schedule: skip, don't crash.
                logger.warning("Schedule '%s' has an invalid cron '%s'; skipping", name, sched.cron)
                continue
            if due:
                asyncio.create_task(self._launch(name, sched))

    def reserve(self, name) -> bool:
        """Atomically mark a schedule in-flight. Returns False if it is already
        running. The check-and-add is atomic because everything runs on the one
        event-loop thread (no await between test and add)."""
        if name in self._running:
            return False
        self._running.add(name)
        return True

    def release(self, name) -> None:
        self._running.discard(name)

    async def run_reserved(self, name, sched, *, trigger, **kwargs) -> None:
        """Run a schedule that is ALREADY reserved via reserve(); hold the global
        concurrency semaphore for the whole run, and always release the
        reservation at the end. Used by run-now (which queues on the semaphore)
        and by the tick path below."""
        try:
            async with self._sem:
                await self._run_one(name, sched, trigger=trigger, **kwargs)
        except Exception as exc:
            logger.exception("Run of '%s' (%s) failed: %s", name, trigger, exc)
        finally:
            self.release(name)

    async def _launch(self, name, sched) -> None:
        """Tick-path launch: reserve, SKIP (not queue) if the single global slot
        is busy, else run through the shared guard."""
        if not self.reserve(name):
            return
        # Global concurrency cap: skip (do not queue) if we can't acquire now.
        if self._sem.locked():
            logger.info("Schedule '%s' due but max concurrency reached; skipping this tick", name)
            self.release(name)
            return
        await self.run_reserved(name, sched, trigger="schedule")


# =============================================================================
# Module singletons
# =============================================================================

_scheduler = None


def init_scheduler(run_one) -> None:
    """Create the module-level Scheduler singleton bound to ``run_one``."""
    global _scheduler
    _scheduler = Scheduler(run_one)


def get_scheduler() -> Scheduler:
    """Return the Scheduler singleton (must call init_scheduler first)."""
    if _scheduler is None:
        raise RuntimeError("Scheduler not initialized; call init_scheduler() first")
    return _scheduler


def is_running(name: str) -> bool:
    """Return True if the named schedule is currently in flight (run-now 409)."""
    if _scheduler is None:
        return False
    return name in _scheduler._running
