"""Phase 2 acceptance test: full pipeline (crawl -> rule engine -> oracles)
against the local vulnerable target.

Acceptance bar from the project spec: every planted vulnerability must be
found, and clean routes/parameters must produce zero active-rule findings.
"""

from __future__ import annotations

from dastcore.config import RateLimitConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import Finding
from dastcore.discovery.crawler_http import HttpCrawler
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner

_ACTIVE_RULE_PREFIXES = ("sqli-injection:", "xss-reflected:", "open-redirect:", "path-traversal-lfi:")


def _by_rule_prefix(findings: list[Finding], prefix: str) -> list[Finding]:
    return [f for f in findings if f.id.startswith(prefix)]


async def _run_full_scan(vuln_app_url: str) -> list[Finding]:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    # High rps: this is localhost, no reason to throttle the test suite.
    rate_limit = RateLimitConfig(requests_per_second=50, max_concurrency=20)
    rules = load_rules()
    async with HttpClient(scope, rate_limit=rate_limit) as client:
        discovered = await HttpCrawler(client).crawl(f"{vuln_app_url}/")
        return await Scanner(client, rules).scan(discovered)


async def test_all_planted_vulnerabilities_are_detected(vuln_app_url: str) -> None:
    findings = await _run_full_scan(vuln_app_url)

    sqli = _by_rule_prefix(findings, "sqli-injection:")
    assert any(f.injection_point.name == "q" and "/search" in f.request.url for f in sqli), sqli

    xss = _by_rule_prefix(findings, "xss-reflected:")
    assert any(f.injection_point.name == "name" and "/greet" in f.request.url for f in xss), xss

    open_redirect = _by_rule_prefix(findings, "open-redirect:")
    assert any(f.injection_point.name == "url" and "/go" in f.request.url for f in open_redirect), open_redirect

    lfi = _by_rule_prefix(findings, "path-traversal-lfi:")
    assert any(f.injection_point.name == "name" and "/file" in f.request.url for f in lfi), lfi

    # Additional classes discovered via the sitemap and scanned end to end.
    rule_ids = {f.rule_id for f in findings}
    assert "ssti-inband" in rule_ids, rule_ids  # SSTI at /render
    assert "nosqli-error" in rule_ids, rule_ids  # NoSQLi at /api/nosql
    assert "host-header-injection" in rule_ids, rule_ids  # Host header at /reset
    assert "active-cors-reflected-origin" in rule_ids, rule_ids  # CORS at /api/cors

    # every finding carries reproducible evidence, remediation, CWE and an OWASP/WSTG reference
    for finding in findings:
        assert finding.evidence, finding.id
        assert finding.remediation
        assert finding.cwe
        assert finding.owasp


async def test_no_active_findings_on_clean_login_parameters(vuln_app_url: str) -> None:
    """/login's username & password aren't part of any planted injection vuln."""
    findings = await _run_full_scan(vuln_app_url)

    login_active_findings = [
        f
        for f in findings
        if f.id.startswith(_ACTIVE_RULE_PREFIXES) and f.injection_point.name in {"username", "password"}
    ]
    assert login_active_findings == []


async def test_findings_are_deterministic_across_runs(vuln_app_url: str) -> None:
    """Same target, same rules -> same set of finding ids both times (no flaky oracle noise)."""
    first = {f.id for f in await _run_full_scan(vuln_app_url)}
    second = {f.id for f in await _run_full_scan(vuln_app_url)}
    assert first == second
    assert first  # sanity: we did find something
