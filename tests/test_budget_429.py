"""Robustness: global scan budget (max requests / time) and HTTP 429 backoff."""

from __future__ import annotations

import asyncio

import pytest

from dastcore.config import ScopeConfig
from dastcore.core.http_client import BudgetExceededError, HttpClient

_SCOPE = ScopeConfig(allow_domains=["127.0.0.1"])


async def test_max_requests_budget_stops_after_limit(vuln_app_url: str) -> None:
    async with HttpClient(_SCOPE, max_requests=3) as client:
        for _ in range(3):
            await client.get(f"{vuln_app_url}/health")
        assert client.request_count == 3
        assert client.budget_exceeded() is True
        with pytest.raises(BudgetExceededError):
            await client.get(f"{vuln_app_url}/health")


async def test_time_budget_stops_after_deadline(vuln_app_url: str) -> None:
    async with HttpClient(_SCOPE, time_budget_s=0.05) as client:
        await client.get(f"{vuln_app_url}/health")  # starts the clock
        await asyncio.sleep(0.1)
        with pytest.raises(BudgetExceededError):
            await client.get(f"{vuln_app_url}/health")


async def test_no_budget_is_unbounded(vuln_app_url: str) -> None:
    async with HttpClient(_SCOPE) as client:
        for _ in range(6):
            resp = await client.get(f"{vuln_app_url}/health")
            assert resp.status_code == 200
        assert client.budget_exceeded() is False


async def test_429_is_retried_with_backoff(vuln_app_url: str) -> None:
    # The endpoint 429s on odd hits, 200 on even; with a retry the client should reach 200.
    async with HttpClient(_SCOPE, max_retries=2) as client:
        response = await client.get(f"{vuln_app_url}/ratelimited")
    assert response.status_code == 200


async def test_429_surfaced_when_retries_exhausted(vuln_app_url: str) -> None:
    async with HttpClient(_SCOPE, max_retries=0) as client:
        # First hit is always a 429; with no retries the client returns it as-is.
        response = await client.get(f"{vuln_app_url}/ratelimited")
    assert response.status_code == 429
