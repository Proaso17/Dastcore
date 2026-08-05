"""Phase 5: headless (Playwright) crawler + DOM-based XSS.

These tests require Playwright and its Chromium browser. If either is missing
they skip cleanly rather than fail, so the rest of the suite stays green on
machines without a browser installed (`python -m playwright install chromium`).
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
import pytest

pytest.importorskip("playwright.async_api")

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.discovery.crawler_headless import HeadlessEngine, HeadlessUnavailableError
from dastcore.discovery.crawler_http import HttpCrawler
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner

_SCOPE = ScopeConfig(allow_domains=["127.0.0.1"])


@asynccontextmanager
async def headless_engine(**kwargs):
    try:
        async with HeadlessEngine(_SCOPE, **kwargs) as engine:
            yield engine
    except HeadlessUnavailableError as exc:
        pytest.skip(str(exc))


async def test_headless_discovers_js_rendered_links_and_xhr(vuln_app_url: str) -> None:
    async with headless_engine(max_pages=10) as engine:
        discovered = await engine.crawl(f"{vuln_app_url}/spa")

    urls = {req.url for req in discovered}
    # JS-generated link, invisible to a static crawler
    assert any(u.endswith("/spa/item") for u in urls), urls
    # captured fetch() XHR call
    assert any(u.endswith("/api/spa-data") for u in urls), urls

    item = next(req for req in discovered if req.url.endswith("/spa/item"))
    assert item.params.get("id") in {"1", "2"}


async def test_static_crawler_is_blind_to_spa_content(vuln_app_url: str) -> None:
    """Contrast: the static crawler only sees the empty shell — this is the differentiator."""
    async with HttpClient(_SCOPE) as client:
        discovered = await HttpCrawler(client).crawl(f"{vuln_app_url}/spa")
    urls = {req.url for req in discovered}
    assert any(u.endswith("/spa") for u in urls)
    assert not any(u.endswith("/spa/item") for u in urls)
    assert not any(u.endswith("/api/spa-data") for u in urls)


async def test_headless_detects_dom_based_xss(vuln_app_url: str) -> None:
    async with headless_engine() as engine:
        findings = await engine.scan_dom_xss([f"{vuln_app_url}/spa"])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "dom-xss"
    assert finding.severity == "high"
    assert finding.injection_point.location == "fragment"
    assert finding.evidence[0].type == "dom_execution"


async def test_headless_no_dom_xss_false_positive_on_clean_page(vuln_app_url: str) -> None:
    """/greet reflects a query param server-side but has no client-side fragment sink."""
    async with headless_engine() as engine:
        findings = await engine.scan_dom_xss([f"{vuln_app_url}/greet", f"{vuln_app_url}/health"])
    assert findings == []


async def test_headless_reuses_authenticated_session(vuln_app_url: str) -> None:
    login = httpx.post(f"{vuln_app_url}/auth/form-login", json={"username": "carol", "password": "carol-pw"})
    sid = login.cookies["sid"]

    async with headless_engine(cookies={"sid": sid}, cookie_url=vuln_app_url) as engine:
        discovered = await engine.crawl(f"{vuln_app_url}/dashboard")
    urls = {req.url for req in discovered}
    assert any(u.endswith("/dashboard/secret") for u in urls), urls


async def test_headless_without_session_cannot_see_authenticated_links(vuln_app_url: str) -> None:
    async with headless_engine() as engine:
        discovered = await engine.crawl(f"{vuln_app_url}/dashboard")
    urls = {req.url for req in discovered}
    assert not any(u.endswith("/dashboard/secret") for u in urls)


async def test_headless_discovered_endpoint_is_scannable(vuln_app_url: str) -> None:
    """Full value: headless finds /spa/item, then the normal active scanner confirms its reflected XSS."""
    async with headless_engine(max_pages=10) as engine:
        discovered = await engine.crawl(f"{vuln_app_url}/spa")

    rules = load_rules()
    async with HttpClient(_SCOPE) as client:
        findings = await Scanner(client, rules).scan(discovered)
    assert any(f.id.startswith("xss-reflected:") and "/spa/item" in f.request.url for f in findings), [
        f.id for f in findings
    ]
