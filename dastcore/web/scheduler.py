"""Recurring-scan scheduler for the dashboard.

A tiny interval scheduler: each `ScheduleRow` fires every ``interval_minutes``. A
background loop wakes periodically and launches whatever is due through the same
`ScanManager` a manual run uses; `tick` is separated out so it can be driven
deterministically from tests without waiting on wall-clock time.
"""

from __future__ import annotations

import asyncio
import logging
import time

from dastcore.web.jobs import ScanManager, ScanRequest
from dastcore.web.store import Store

_log = logging.getLogger(__name__)


class Scheduler:
    """Launches due scheduled scans; advances each schedule to its next run."""

    def __init__(self, store: Store, manager: ScanManager, *, poll_seconds: float = 30.0) -> None:
        self._store = store
        self._manager = manager
        self._poll_seconds = poll_seconds

    async def tick(self, now: float | None = None) -> int:
        """Launch every enabled schedule whose time has come. Returns how many fired."""
        now = time.time() if now is None else now
        launched = 0
        for sched in self._store.due_schedules(now):
            request = ScanRequest(
                target=sched.target,
                engine=sched.engine,
                profile=sched.profile or "",
                rps=sched.rps,
                auth_bearer=sched.auth_bearer or "",
                auth_cookie=sched.auth_cookie or "",
            )
            try:
                self._manager.start(request)
                launched += 1
            except Exception as exc:  # noqa: BLE001 — a bad schedule must not wedge the loop
                _log.warning("scheduled scan for %s failed to start: %s", sched.target, exc)
            # Advance regardless, so a persistently-bad schedule doesn't fire every tick.
            self._store.mark_ran(sched.id, now, now + sched.interval_minutes * 60)
        return launched

    async def run_forever(self) -> None:
        """Poll for due schedules until cancelled. Started from the app lifespan."""
        while True:
            await asyncio.sleep(self._poll_seconds)
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — keep the loop alive across transient errors
                _log.exception("scheduler tick failed")
