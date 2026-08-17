"""Native content discovery (dirbusting): finds unlinked paths, with zero false positives via
not-found autocalibration (soft-404 / catch-all aware), and never leaves scope."""

from __future__ import annotations

from urllib.parse import urlsplit

from dastcore.config import RateLimitConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpResponse
from dastcore.discovery.content import ContentDiscoverer, _Baseline, load_content_wordlist

_FAST = RateLimitConfig(requests_per_second=100, max_concurrency=20)


async def test_content_discovery_finds_unlinked_paths_without_false_positives(vuln_app_url: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope, rate_limit=_FAST) as client:
        wordlist = load_content_wordlist("balanced")
        found = await ContentDiscoverer(client, wordlist=wordlist).discover(vuln_app_url + "/")

    paths = {urlsplit(e.url).path.rstrip("/") for e in found}
    # real, unlinked endpoints are discovered by brute force...
    for expected in ("/account", "/dashboard", "/health", "/guestbook"):
        assert expected in paths, f"expected to discover {expected}; got {sorted(paths)}"
    # ...but non-existent words from the very same list are not reported (calibration killed them)
    assert "/phpmyadmin" not in paths
    assert "/wp-admin" not in paths


async def test_content_discovery_stays_in_scope(vuln_app_url: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope, rate_limit=_FAST) as client:
        # a base URL outside the allowed host yields nothing (and sends no requests to it)
        found = await ContentDiscoverer(client, wordlist=["admin"]).discover("http://not-authorized.invalid/")
    assert found == []


def _resp(status: int, length: int, location: str = "") -> HttpResponse:
    headers = {"location": location} if location else {}
    return HttpResponse(method="GET", status_code=status, headers=headers, text="x" * length, url="http://t/")


def test_calibration_treats_soft_404_as_not_found() -> None:
    # server answers 200 with a ~500-byte page for everything
    baseline = _Baseline(statuses={200}, lengths_by_status={200: [500, 505, 498]}, redirect_paths=set())
    assert baseline.explains(_resp(200, 502))  # same soft-404 page -> not a hit
    assert not baseline.explains(_resp(200, 4000))  # a clearly different page -> a real hit
    assert not baseline.explains(_resp(401, 30))  # protected resource exists -> a hit


def test_calibration_with_standard_404() -> None:
    baseline = _Baseline(statuses={404}, lengths_by_status={404: [120]}, redirect_paths=set())
    assert baseline.explains(_resp(404, 120))  # garbage -> not found
    assert not baseline.explains(_resp(200, 2000))  # real page -> hit


def test_calibration_ignores_catch_all_redirects() -> None:
    baseline = _Baseline(statuses={302}, lengths_by_status={302: [0]}, redirect_paths={"/login"})
    assert baseline.explains(_resp(302, 0, location="https://app/login"))  # everything 302s to /login
    assert not baseline.explains(_resp(302, 0, location="https://app/admin"))  # a different target -> hit
