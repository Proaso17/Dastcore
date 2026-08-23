"""Scope-enforced async HTTP client.

Every request the engine ever makes — crawler, active scanner, OAST
correlation — must go through `HttpClient.request` (or the `get`/`post`
helpers). Scope is checked here, at the network boundary, not left to
callers to remember: this is what makes the "no request ever leaves scope"
guarantee actually true.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

import httpx

from dastcore.config import RateLimitConfig, ScopeConfig
from dastcore.core.models import HttpResponse
from dastcore.core.scope import ScopeChecker

if TYPE_CHECKING:
    from dastcore.core.session import SessionManager

logger = logging.getLogger("dastcore.http")

_RETRYABLE_EXCEPTIONS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
)


class OutOfScopeError(RuntimeError):
    """Raised when a request would leave the declared scan scope."""


class BudgetExceededError(RuntimeError):
    """Raised when the scan's request or time budget has been reached."""


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a Retry-After header (delta-seconds form) into seconds."""
    if not value:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    return max(0.0, seconds)


class TokenBucket:
    """Async token bucket for requests-per-second limiting."""

    def __init__(self, rate: float, burst: float | None = None) -> None:
        self._rate = rate
        self._capacity = burst if burst is not None else max(rate, 1.0)
        self._tokens = self._capacity
        self._updated_at = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._updated_at
                self._updated_at = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait_for = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait_for)


class HttpClient:
    """Rate-limited, scope-enforced wrapper around `httpx.AsyncClient`."""

    def __init__(
        self,
        scope: ScopeConfig,
        rate_limit: RateLimitConfig | None = None,
        timeout: float = 10.0,
        max_retries: int = 2,
        proxy: str | None = None,
        follow_redirects: bool = False,
        session: SessionManager | None = None,
        max_requests: int | None = None,
        time_budget_s: float | None = None,
        auth_urls: list[str] | None = None,
    ) -> None:
        # Auth/IdP endpoints (from the auth config) are reachable for (re)login even off the attack scope.
        self._scope_checker = ScopeChecker(scope, auth_urls=auth_urls)
        rate_limit = rate_limit or RateLimitConfig()
        self._bucket = TokenBucket(rate_limit.requests_per_second)
        self._semaphore = asyncio.Semaphore(rate_limit.max_concurrency)
        self._max_retries = max_retries
        self._session = session
        self._max_requests = max_requests
        self._time_budget_s = time_budget_s
        self._request_count = 0
        self._deadline: float | None = None
        self._client = httpx.AsyncClient(
            timeout=timeout,
            proxy=proxy,
            follow_redirects=follow_redirects,
        )
        # Seed the jar with any static session cookies. Dynamically-obtained cookies
        # (form-login) are persisted into this same jar automatically by httpx.
        if session is not None and session.cookies:
            self._client.cookies.update(session.cookies)

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def is_in_scope(self, url: str) -> bool:
        return self._scope_checker.is_in_scope(url)

    def is_asset_in_scope(self, host_or_ip: str) -> bool:
        """Scope check for a bare host/IP (a discovered subdomain before it has a URL)."""
        return self._scope_checker.is_asset_in_scope(host_or_ip)

    @property
    def request_count(self) -> int:
        return self._request_count

    def budget_exceeded(self) -> bool:
        """True once the request count or the time budget has been reached."""
        if self._max_requests is not None and self._request_count >= self._max_requests:
            return True
        if self._deadline is not None and time.monotonic() >= self._deadline:
            return True
        return False

    def _account_for_budget(self) -> None:
        # Start the time-budget clock on the first real request, not at construction.
        if self._deadline is None and self._time_budget_s is not None:
            self._deadline = time.monotonic() + self._time_budget_s
        if self.budget_exceeded():
            raise BudgetExceededError("Scan budget exhausted (max-requests / time-budget).")
        self._request_count += 1

    def cookie_pairs(self) -> dict[str, str]:
        """Current cookies in the jar — used to share an authenticated session with the browser."""
        return {cookie.name: cookie.value or "" for cookie in self._client.cookies.jar}

    def set_cookies(self, cookies: dict[str, str]) -> None:
        """Push cookies into the jar (e.g. a browser login macro's session cookies), so every
        subsequent request carries them like any Set-Cookie the client received itself."""
        self._client.cookies.update(cookies)

    def session_headers(self) -> dict[str, str]:
        """Header material the session injects (bearer/oauth2 tokens, custom headers)."""
        if self._session is None:
            return {}
        return self._session.apply(None)

    async def _send_once(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json: dict | list | None = None,
        files: dict | None = None,
        timeout: float | None = None,
        retries: int | None = None,
    ) -> HttpResponse:
        """The single choke point: scope enforcement + rate limit + transport retries.

        ``timeout`` / ``retries`` override the client defaults for this one request — discovery uses a
        short timeout and no retries so a slow/dead host resolves in seconds, not tens of seconds.

        No session injection or re-login happens here, so login requests made by the
        session manager can reuse it without recursion.
        """
        if not self._scope_checker.is_in_scope(url):
            raise OutOfScopeError(f"Refusing to request out-of-scope URL: {url}")

        # Enforce the scan budget before spending a request (raises BudgetExceededError).
        self._account_for_budget()

        # Cookies live on the client's jar (httpx persists Set-Cookie there and resends it),
        # so any explicit per-request cookies are merged into the jar rather than passed
        # per-request — which httpx deprecates due to ambiguous per-domain semantics.
        if cookies:
            self._client.cookies.update(cookies)

        max_retries = self._max_retries if retries is None else max(0, retries)
        extra = {"timeout": timeout} if timeout is not None else {}  # else use the client default
        await self._bucket.acquire()
        async with self._semaphore:
            attempt = 0
            while True:
                try:
                    start = time.monotonic()
                    response = await self._client.request(
                        method,
                        url,
                        params=params,
                        headers=headers,
                        data=data,
                        json=json,
                        files=files,
                        **extra,
                    )
                    elapsed_ms = (time.monotonic() - start) * 1000
                except _RETRYABLE_EXCEPTIONS:
                    attempt += 1
                    if attempt > max_retries:
                        raise
                    await asyncio.sleep(0.2 * attempt)
                    continue

                # Honor server-side rate limiting: back off on 429 and retry.
                if response.status_code == 429 and attempt < max_retries:
                    attempt += 1
                    retry_after = _parse_retry_after(response.headers.get("retry-after"))
                    await asyncio.sleep(retry_after if retry_after is not None else 0.5 * attempt)
                    continue

                logger.debug("%s %s -> %s (%.0f ms)", method, url, response.status_code, elapsed_ms)
                return HttpResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    cookies=dict(response.cookies),
                    text=response.text,
                    elapsed_ms=elapsed_ms,
                    url=str(response.url),
                )

    async def send_raw(self, method: str, url: str, **kwargs) -> HttpResponse:
        """Send bypassing session injection/re-login (used by the session manager to log in)."""
        return await self._send_once(method, url, **kwargs)

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json: dict | list | None = None,
        files: dict | None = None,
        timeout: float | None = None,
        retries: int | None = None,
        _allow_relogin: bool = True,
    ) -> HttpResponse:
        send_headers = headers
        epoch: int | None = None
        if self._session is not None:
            send_headers = self._session.apply(headers)
            epoch = self._session.epoch

        response = await self._send_once(
            method, url, params=params, headers=send_headers, cookies=cookies, data=data, json=json, files=files,
            timeout=timeout, retries=retries,
        )

        if (
            self._session is not None
            and _allow_relogin
            and self._session.can_relogin
            and self._session.is_expired(response)
        ):
            if await self._session.ensure_logged_in(self, seen_epoch=epoch):
                # Retry once with the freshly re-established session (pass the *original*
                # per-request headers/cookies so the new session material is re-applied).
                return await self.request(
                    method,
                    url,
                    params=params,
                    headers=headers,
                    cookies=cookies,
                    data=data,
                    json=json,
                    files=files,
                    timeout=timeout,
                    retries=retries,
                    _allow_relogin=False,
                )

        return response

    async def get(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("POST", url, **kwargs)
