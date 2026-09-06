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
from urllib.parse import urlsplit, urlunsplit

import httpx

from dastcore.config import RateLimitConfig, ScopeConfig
from dastcore.core.models import HttpResponse
from dastcore.core.scope import ScopeChecker

if TYPE_CHECKING:
    from dastcore.core.rate_governor import RateGovernor
    from dastcore.core.session import SessionManager

logger = logging.getLogger("dastcore.http")

# Default request headers that make the scanner look like a real browser. httpx's own default UA
# (``python-httpx/x.y``) is an instant tell that a WAF/CDN (Cloudflare, Akamai…) blocks — sending a
# normal browser UA + Accept/Sec-Fetch headers gets past the lighter WAF rules that gate on that alone.
# Per-request headers still override these (e.g. a shellshock check that injects into User-Agent).
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
_BROWSER_HEADERS = {
    "User-Agent": _BROWSER_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Upgrade-Insecure-Requests": "1",
}

_RETRYABLE_EXCEPTIONS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    # A third-party server that closes the connection without a response — common on fragile targets
    # under scan load. Transient, so retry it (bounded by max_retries) before giving up.
    httpx.RemoteProtocolError,
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
        host_overrides: dict[str, str] | None = None,
        user_agent: str | None = None,
        attribution: dict[str, str] | None = None,
        governor: RateGovernor | None = None,
    ) -> None:
        # Auth/IdP endpoints (from the auth config) are reachable for (re)login even off the attack scope.
        self._scope_checker = ScopeChecker(scope, auth_urls=auth_urls)
        # Virtual-host scanning: hostname -> IP to connect to. A request for an overridden host is scope-
        # checked on its real name (unchanged), then the socket is pointed at the IP while the Host header
        # and TLS SNI keep the real name — so a vhost that doesn't resolve in DNS is still fully scannable.
        self._host_overrides = {h.lower().rstrip("."): ip for h, ip in (host_overrides or {}).items()}
        rate_limit = rate_limit or RateLimitConfig()
        self._bucket = TokenBucket(rate_limit.requests_per_second)
        # Optional per-host / per-endpoint-daily governance layered on top of the global bucket (RoE).
        self._governor = governor
        self._semaphore = asyncio.Semaphore(rate_limit.max_concurrency)
        self._max_retries = max_retries
        self._session = session
        self._max_requests = max_requests
        self._time_budget_s = time_budget_s
        self._request_count = 0
        # Effective-rate telemetry: actual network attempts sent (retries included) and when the first
        # went out — so the operator can *verify* the configured RPS ceiling held (RoE compliance).
        self._sent_count = 0
        self._first_send_at: float | None = None
        # WAF-block telemetry: how many responses came back as a block (403/429/503). A high ratio means
        # the target's WAF is refusing the scan, so its findings are unreliable — the CLI surfaces that.
        self._response_count = 0
        self._blocked_count = 0
        self._deadline: float | None = None
        # Browser-like default headers so the scanner isn't blocked on its User-Agent alone. A caller can
        # pass ``user_agent`` (e.g. their real browser's, to pair with a cf_clearance cookie) to match it.
        default_headers = dict(_BROWSER_HEADERS)
        if user_agent:
            default_headers["User-Agent"] = user_agent
        # Bug-bounty attribution (e.g. X-Bug-Bounty: HackerOne-<handle>): sent on every request this
        # client makes — which is only in-scope target traffic (third-party OSINT uses its own client),
        # so a program can identify the researcher's requests as required by many policies.
        if attribution:
            default_headers.update(attribution)
        self._client = httpx.AsyncClient(
            timeout=timeout,
            proxy=proxy,
            follow_redirects=follow_redirects,
            headers=default_headers,
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
        if self._governor is not None:
            self._governor.close()
        await self._client.aclose()

    def is_in_scope(self, url: str) -> bool:
        return self._scope_checker.is_in_scope(url)

    def is_asset_in_scope(self, host_or_ip: str) -> bool:
        """Scope check for a bare host/IP (a discovered subdomain before it has a URL)."""
        return self._scope_checker.is_asset_in_scope(host_or_ip)

    def add_host_override(self, host: str, ip: str) -> None:
        """Route future requests for ``host`` to ``ip`` (keeping Host/SNI = ``host``) — for scanning a
        virtual host that isn't in DNS. The scope gate still runs on ``host``, so this cannot widen scope."""
        self._host_overrides[host.lower().rstrip(".")] = ip

    def _apply_host_override(self, url: str, headers: dict[str, str] | None) -> tuple[str, dict[str, str] | None, dict | None]:
        """If ``url``'s host is overridden, rewrite the connect URL to the IP and pin Host + SNI to the
        real host. Returns (send_url, send_headers, extensions). Scope is already checked on the real url."""
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        ip = self._host_overrides.get(host)
        if not ip:
            return url, headers, None
        netloc = f"[{ip}]" if ":" in ip else ip
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        send_url = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
        send_headers = dict(headers or {})
        send_headers["Host"] = parts.netloc  # real vhost name (with port if any)
        return send_url, send_headers, {"sni_hostname": parts.hostname}

    @property
    def request_count(self) -> int:
        return self._request_count

    @property
    def blocked_count(self) -> int:
        return self._blocked_count

    @property
    def response_count(self) -> int:
        return self._response_count

    def waf_block_ratio(self) -> float:
        """Fraction of responses that came back as a WAF block (403/429/503). 0.0 if nothing was sent."""
        return self._blocked_count / self._response_count if self._response_count else 0.0

    def effective_rps(self) -> float:
        """Measured request rate over the whole run: actual network attempts (retries included) per
        elapsed second. Informational — lets a bug-bounty operator verify the RoE rate held. (A short
        burst can read above the steady rate because the token bucket permits a burst up to its capacity;
        it's the *steady-state* rate, enforced per-attempt by the bucket, that stays within the ceiling.)"""
        if self._first_send_at is None or self._sent_count == 0:
            return 0.0
        elapsed = time.monotonic() - self._first_send_at
        return self._sent_count / elapsed if elapsed > 0 else 0.0

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

        # Per-endpoint daily cap (RoE), charged once per logical request (not per retry). Raises
        # EndpointCapReachedError (a skip, like out-of-scope) when the endpoint is out of daily quota.
        if self._governor is not None:
            await self._governor.charge(url)

        # Enforce the scan budget before spending a request (raises BudgetExceededError).
        self._account_for_budget()

        # Cookies live on the client's jar (httpx persists Set-Cookie there and resends it),
        # so any explicit per-request cookies are merged into the jar rather than passed
        # per-request — which httpx deprecates due to ambiguous per-domain semantics.
        if cookies:
            self._client.cookies.update(cookies)

        max_retries = self._max_retries if retries is None else max(0, retries)
        extra: dict = {"timeout": timeout} if timeout is not None else {}  # else use the client default
        # Virtual-host override: point the socket at the IP while Host/SNI keep the real name. Scope was
        # already enforced above on the real ``url``; only the connection target changes.
        send_url, send_headers, extensions = self._apply_host_override(url, headers)
        if extensions is not None:
            extra["extensions"] = extensions
        async with self._semaphore:
            attempt = 0
            while True:
                # Take a rate-limit token before EVERY attempt (not just the first), so retries can't
                # push the effective request rate above the configured RPS — the RoE ceiling holds even
                # under a flapping host. Per-host pacing/jitter (the governor) is charged per attempt too.
                await self._bucket.acquire()
                if self._governor is not None:
                    await self._governor.pace(url)
                self._sent_count += 1
                if self._first_send_at is None:
                    self._first_send_at = time.monotonic()
                try:
                    start = time.monotonic()
                    response = await self._client.request(
                        method,
                        send_url,
                        params=params,
                        headers=send_headers,
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
                # On a host override, report the real (vhost) URL, not the IP we connected to, so the
                # scanner keeps the vhost's identity for dedup/evidence.
                self._response_count += 1
                if response.status_code in (403, 429, 503):  # WAF block / rate limit / challenge
                    self._blocked_count += 1
                reported_url = url if send_url != url else str(response.url)
                return HttpResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    cookies=dict(response.cookies),
                    text=response.text,
                    elapsed_ms=elapsed_ms,
                    url=reported_url,
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
            # Don't fire with stale session material while a re-login is mid-flight — that is what turns a
            # single dropped session into a re-login cascade under concurrency. Wait for it, then apply the
            # fresh material and read the fresh epoch.
            if _allow_relogin and self._session.can_relogin:
                await self._session.wait_until_ready()
            send_headers = self._session.apply(headers)
            epoch = self._session.epoch

        response = await self._send_once(
            method, url, params=params, headers=send_headers, cookies=cookies, data=data, json=json, files=files,
            timeout=timeout, retries=retries,
        )

        if self._session is not None and self._session.can_relogin:
            if self._session.is_expired(response):
                if _allow_relogin and await self._session.ensure_logged_in(self, seen_epoch=epoch):
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
            else:
                # The session is alive (this request wasn't bounced to login). Reset the re-login
                # budget so a fragile-but-recoverable session (drops under load, re-logs in, works,
                # drops again) never exhausts it — only auth that never recovers trips max_relogin.
                self._session.note_success()

        return response

    async def get(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("POST", url, **kwargs)
