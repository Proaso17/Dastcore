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


def test_discovery_reserve_raises_the_non_terminal_variant() -> None:
    """#10 regression: hitting the *discovery* reserve must raise DiscoveryBudgetExceededError (the CLI
    ends discovery and runs the audit on the reserved slice), NOT the terminal BudgetExceededError that
    would end the whole scan and leave the audit unrun."""
    import pytest

    from dastcore.core.http_client import DiscoveryBudgetExceededError

    c = _client(max_requests=100)
    c._account_for_budget()  # start accounting
    c.begin_discovery_phase(0.4)  # discovery may use 60 of 100
    c._request_count = 60  # tightened limit reached, hard limit (100) not
    with pytest.raises(DiscoveryBudgetExceededError):
        c._account_for_budget()


def test_hard_budget_raises_the_terminal_error_even_during_discovery() -> None:
    """When the REAL budget is exhausted (not just the reserve), the terminal BudgetExceededError is raised
    even mid-discovery — the scan must actually stop, not just end discovery."""
    import pytest

    from dastcore.core.http_client import BudgetExceededError, DiscoveryBudgetExceededError

    c = _client(max_requests=100)
    c._account_for_budget()
    c.begin_discovery_phase(0.4)
    c._request_count = 100  # the hard limit itself is reached
    with pytest.raises(BudgetExceededError) as excinfo:
        c._account_for_budget()
    assert not isinstance(excinfo.value, DiscoveryBudgetExceededError)  # terminal, not the discovery variant


def test_after_discovery_ends_the_reserved_slice_raises_only_the_terminal_error() -> None:
    import pytest

    from dastcore.core.http_client import BudgetExceededError, DiscoveryBudgetExceededError

    c = _client(max_requests=100)
    c._account_for_budget()
    c.begin_discovery_phase(0.4)
    c.end_discovery_phase()  # reserve lifted: the active scan may spend up to the hard limit
    c._request_count = 80
    assert not c.budget_exceeded()  # the reserved slice is now spendable
    c._request_count = 100
    with pytest.raises(BudgetExceededError) as excinfo:
        c._account_for_budget()
    assert not isinstance(excinfo.value, DiscoveryBudgetExceededError)
