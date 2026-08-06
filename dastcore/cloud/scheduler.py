"""Recurring-job scheduler for the control-plane.

Unlike the local dashboard's scheduler (which *runs* scans in-process), this one
only **enqueues** jobs: when a project's schedule is due it creates a queued job,
which a self-hosted runner then claims and executes. `tick` is separated from the
poll loop so tests can drive it deterministically.
"""

from __future__ import annotations

import asyncio
import logging
import time

from dastcore.cloud.models import ScheduleCreate
from dastcore.cloud.store import Store

_log = logging.getLogger(__name__)


class Scheduler:
    def __init__(self, store: Store, *, poll_seconds: float = 30.0) -> None:
        self._store = store
        self._poll_seconds = poll_seconds

    async def tick(self, now: float | None = None) -> int:
        """Enqueue a job for every due, enabled schedule. Returns how many fired."""
        now = time.time() if now is None else now
        enqueued = 0
        for sched in self._store.due_schedules(now):
            self._store.enqueue_job(sched.project_id, sched.spec())
            self._store.mark_schedule_ran(sched.id, now, now + sched.interval_minutes * 60)
            enqueued += 1
        return enqueued

    async def run_forever(self) -> None:
        while True:
            await asyncio.sleep(self._poll_seconds)
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — keep the loop alive across transient errors
                _log.exception("cloud scheduler tick failed")


# Re-exported for convenience so callers can build schedules without importing models.
__all__ = ["Scheduler", "ScheduleCreate"]
