"""Stored / second-order XSS via re-crawled canaries (opt-in stored scan)."""

from __future__ import annotations

from dastcore.config import RateLimitConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.discovery.crawler_http import HttpCrawler
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner


async def _crawl_and_scan(vuln_app_url: str, *, stored: bool):
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    rate_limit = RateLimitConfig(requests_per_second=80, max_concurrency=20)
    async with HttpClient(scope, rate_limit=rate_limit) as client:
        discovered = await HttpCrawler(client).crawl(f"{vuln_app_url}/")
        scanner = Scanner(client, load_rules(), stored_scan=stored)
        return await scanner.scan(discovered)


async def test_stored_xss_is_found_with_stored_scan(vuln_app_url: str) -> None:
    findings = await _crawl_and_scan(vuln_app_url, stored=True)
    stored = [f for f in findings if f.rule_id == "stored-xss"]
    assert stored, findings
    # injected at the comment form, surfaced on the comments page
    assert any("/comment" in f.request.url and "/comments" in f.evidence[0].data for f in stored)
    assert stored[0].confidence == "high"


async def test_stored_scan_is_off_by_default(vuln_app_url: str) -> None:
    findings = await _crawl_and_scan(vuln_app_url, stored=False)
    assert not any(f.rule_id == "stored-xss" for f in findings)  # no canary probing without the flag
