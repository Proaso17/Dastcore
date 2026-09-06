from __future__ import annotations

import socket
import time

import httpx
import pytest

from dastcore.config import RateLimitConfig, ScopeConfig
from dastcore.core.http_client import HttpClient, OutOfScopeError


def _closed_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def test_get_returns_response_with_timing(vuln_app_url: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        response = await client.get(f"{vuln_app_url}/health")
        assert response.status_code == 200
        assert response.elapsed_ms >= 0
        assert '"status":"ok"' in response.text.replace(" ", "")


async def test_post_json(vuln_app_url: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        response = await client.post(f"{vuln_app_url}/login", json={"username": "bob", "password": "bob123"})
        assert response.status_code == 200
        assert '"user_id":2' in response.text.replace(" ", "")


async def test_out_of_scope_request_is_refused(vuln_app_url: str) -> None:
    scope = ScopeConfig(allow_domains=["only-this-host.invalid"])
    async with HttpClient(scope) as client:
        with pytest.raises(OutOfScopeError):
            await client.get(f"{vuln_app_url}/health")


async def test_rate_limit_enforced(vuln_app_url: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    rate_limit = RateLimitConfig(requests_per_second=5, max_concurrency=5)
    async with HttpClient(scope, rate_limit=rate_limit) as client:
        start = time.monotonic()
        for _ in range(10):
            await client.get(f"{vuln_app_url}/health")
        elapsed = time.monotonic() - start
    # capacity == rate == 5 tokens up front, the remaining 5 of 10 requests must each
    # wait ~1/5s for a fresh token, so the whole batch cannot finish in well under ~0.6s.
    assert elapsed >= 0.6


async def test_connection_error_raises_after_retries() -> None:
    # A bound-then-closed local port: Linux/macOS refuse it immediately (ConnectError),
    # Windows can leave it filtered and just time out (ConnectTimeout) — both are the
    # retryable transport failures this test cares about.
    port = _closed_port()
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope, max_retries=1, timeout=1.0) as client:
        with pytest.raises(httpx.TransportError):
            await client.get(f"http://127.0.0.1:{port}/")


async def test_live_response_resets_the_relogin_budget(vuln_app_url: str) -> None:
    """Wiring guard: a request that comes back with a live session must reset the session's re-login
    budget (note_success). Without this, an app that periodically drops and recovers its session burns
    the total budget and then silently scans the login page. Complements the SessionManager-level test."""
    from dastcore.config import AuthConfig, FormLoginConfig
    from dastcore.core.session import SessionManager

    auth = AuthConfig(
        type="form",
        form=FormLoginConfig(login_url=f"{vuln_app_url}/login", credentials={"u": "a"}),
    )
    sm = SessionManager(auth)
    sm._established = True
    sm._relogin_count = 5  # pretend several re-logins already happened during the scan

    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope, session=sm) as client:
        resp = await client.get(f"{vuln_app_url}/health")  # a normal 200 -> the session is alive
    assert resp.status_code == 200
    assert sm._relogin_count == 0  # the live response reset the consecutive-re-login counter
