"""Budget reservation: discovery (crawl/dirbust) must not spend the whole --time-budget / --max-requests
and starve the active scan. During the discovery phase the effective budget is tightened by the reserved
fraction; once discovery ends, the active scan gets the full remaining budget."""

from __future__ import annotations

import time

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient


def _client(**budget) -> HttpClient:
    return HttpClient(ScopeConfig(allow_domains=["127.0.0.1"]), **budget)


def test_request_budget_is_reserved_for_the_active_scan() -> None:
    c = _client(max_requests=100)
    c._account_for_budget()  # starts the accounting
    c.begin_discovery_phase(0.4)  # reserve 40% -> discovery may use 60 requests
    c._request_count = 59
    assert not c.budget_exceeded()
    c._request_count = 60
    assert c.budget_exceeded()  # discovery is stopped, holding 40 requests back
    c.end_discovery_phase()
    assert not c.budget_exceeded()  # the active scan can now use the reserved slice
    c._request_count = 100
    assert c.budget_exceeded()


def test_time_budget_is_reserved_for_the_active_scan() -> None:
    c = _client(time_budget_s=100.0)
    c._account_for_budget()          # sets the real deadline; discovery cutoff = deadline - 30s (30% reserved)
    c.begin_discovery_phase(0.3)
    now = time.monotonic()
    c._deadline = now + 100.0        # plenty of time left -> discovery keeps going
    assert not c.budget_exceeded()
    c._deadline = now + 20.0         # only 20s left (< the 30s reserved) -> past the discovery cutoff
    assert c.budget_exceeded()       # discovery stops, holding the reserved slice back
    c.end_discovery_phase()
    assert not c.budget_exceeded()   # the real deadline is still 20s away -> the active scan runs


def test_no_reservation_without_a_budget() -> None:
    c = _client()  # no max_requests, no time_budget
    c.begin_discovery_phase(0.4)
    c._request_count = 10_000
    assert not c.budget_exceeded()  # nothing to run out of
