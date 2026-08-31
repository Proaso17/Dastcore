"""Per-host / per-endpoint rate governance for bug-bounty RoE compliance.

The global ``TokenBucket`` in ``HttpClient`` caps the *overall* request rate. Some programs also cap
requests **per host** and **per endpoint per day** (e.g. "≤ 1000 requests/day/endpoint"). This governor
adds those two limits on top, without touching the global path:

* **Per-host token bucket** — each host gets its own bucket, so no single host is hit faster than the
  program allows even when the global budget would let it.
* **Persistent per-endpoint daily cap** — a SQLite-backed counter keyed by (endpoint, UTC day) that
  survives across runs, so a scheduled/resumed campaign can't exceed a daily quota an endpoint already
  spent earlier. When an endpoint is out of quota the request is skipped (``EndpointCapReachedError``,
  a subclass of ``OutOfScopeError`` so every existing caller already treats it as "skip this request",
  never as a fatal abort).

Wired as one optional ``HttpClient(governor=…)`` param — absent means identical behaviour to before.
"""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from dastcore.core.http_client import OutOfScopeError, TokenBucket

_DEFAULT_CAP_DB = ".dastcore-endpoint-caps.sqlite"


class EndpointCapReachedError(OutOfScopeError):
    """An endpoint hit its per-day request cap. Subclasses OutOfScopeError so callers skip the request
    (they already handle OutOfScopeError as 'skip'), rather than aborting the whole scan."""


def _endpoint_key(url: str) -> str:
    parts = urlsplit(url)
    return f"{(parts.hostname or '').lower()}{parts.path or '/'}"  # method-agnostic: host + path


class RateGovernor:
    """Per-host pacing + a persistent per-endpoint daily cap, layered over the global rate limit."""

    def __init__(
        self,
        *,
        per_host_rps: float | None = None,
        per_endpoint_daily_cap: int | None = None,
        daily_cap_db: str | None = None,
    ) -> None:
        self._per_host_rps = per_host_rps if (per_host_rps and per_host_rps > 0) else None
        self._host_buckets: dict[str, TokenBucket] = {}
        self._cap = per_endpoint_daily_cap if (per_endpoint_daily_cap and per_endpoint_daily_cap > 0) else None
        self._db: sqlite3.Connection | None = None
        self._db_lock: asyncio.Lock | None = None
        if self._cap is not None:
            path = daily_cap_db or _DEFAULT_CAP_DB
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(path, check_same_thread=False)
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS endpoint_caps "
                "(endpoint TEXT, day TEXT, count INTEGER, PRIMARY KEY (endpoint, day))"
            )
            self._db.commit()
            self._db_lock = asyncio.Lock()

    @property
    def active(self) -> bool:
        """True if the governor actually enforces anything (else it's a no-op)."""
        return self._per_host_rps is not None or self._cap is not None

    async def gate(self, url: str) -> None:
        """Pace this request per-host and charge it against the endpoint's daily quota.

        Raises ``EndpointCapReachedError`` (skip) when the endpoint is out of quota — checked and
        charged *before* the per-host wait, so a capped endpoint doesn't hold a host-bucket slot."""
        if self._cap is not None:
            assert self._db is not None and self._db_lock is not None
            async with self._db_lock:
                if not self._charge_endpoint(url):
                    raise EndpointCapReachedError(f"Per-endpoint daily cap reached ({self._cap}): {url}")
        if self._per_host_rps is not None:
            host = (urlsplit(url).hostname or "").lower()
            bucket = self._host_buckets.get(host)
            if bucket is None:
                bucket = self._host_buckets[host] = TokenBucket(self._per_host_rps)
            await bucket.acquire()

    def _charge_endpoint(self, url: str) -> bool:
        """Increment the endpoint's counter for today; return False if it was already at the cap."""
        assert self._db is not None
        endpoint = _endpoint_key(url)
        day = datetime.now(UTC).strftime("%Y-%m-%d")
        row = self._db.execute(
            "SELECT count FROM endpoint_caps WHERE endpoint = ? AND day = ?", (endpoint, day)
        ).fetchone()
        if (row[0] if row else 0) >= self._cap:  # type: ignore[operator]
            return False
        self._db.execute(
            "INSERT INTO endpoint_caps (endpoint, day, count) VALUES (?, ?, 1) "
            "ON CONFLICT (endpoint, day) DO UPDATE SET count = count + 1",
            (endpoint, day),
        )
        self._db.commit()
        return True

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None
