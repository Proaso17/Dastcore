"""Retest mode: unit tests for classification + an end-to-end retest of the vuln app."""

from __future__ import annotations

import pytest

from dastcore.config import RateLimitConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.discovery.crawler_http import HttpCrawler
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner
from dastcore.retest import (
    base_requests_for,
    classify,
    load_prior_findings,
    open_findings,
    summarize,
)


def _finding(fid: str, *, url: str = "http://t.test/a", oob: bool = False) -> Finding:
    request = HttpRequest(method="GET", url=url, params={"x": "1"})
    point = InjectionPoint(location="query", name="x", request_template=request)
    ev = Evidence(type="oob", data="callback") if oob else Evidence(type="response_match", data="err")
    return Finding(
        id=fid,
        rule_id=fid.split(":")[0],
        name="Issue",
        severity="high",
        cwe="CWE-1",
        owasp="WSTG-1",
        injection_point=point,
        evidence=[ev],
        request=request,
        response=HttpResponse(status_code=200),
        remediation="fix it",
    )


# --- load_prior_findings -----------------------------------------------------------------


def test_load_prior_findings_accepts_bare_array(sample_finding: Finding) -> None:
    data = [sample_finding.model_dump(mode="json")]
    loaded = load_prior_findings(data)
    assert [f.id for f in loaded] == [sample_finding.id]


def test_load_prior_findings_accepts_findings_object(sample_finding: Finding) -> None:
    data = {"findings": [sample_finding.model_dump(mode="json")]}
    loaded = load_prior_findings(data)
    assert [f.id for f in loaded] == [sample_finding.id]


def test_load_prior_findings_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        load_prior_findings("not a report")


# --- base_requests_for -------------------------------------------------------------------


def test_base_requests_for_dedups_by_signature() -> None:
    # Two findings on the same endpoint/param shape -> one request to re-issue.
    findings = [_finding("sqli:GET:/a:query:x"), _finding("xss:GET:/a:query:x")]
    requests = base_requests_for(findings)
    assert len(requests) == 1
    assert requests[0].signature() == findings[0].injection_point.request_template.signature()


# --- classify ----------------------------------------------------------------------------


def test_classify_open_carries_fresh_finding() -> None:
    prior = _finding("sqli:GET:/a:query:x")
    fresh = _finding("sqli:GET:/a:query:x")
    outcomes = classify([prior], [fresh], oast_attempted=False)
    assert outcomes[0].status == "open"
    assert outcomes[0].current is fresh


def test_classify_absent_inband_is_fixed() -> None:
    prior = _finding("sqli:GET:/a:query:x")
    outcomes = classify([prior], [], oast_attempted=False)
    assert outcomes[0].status == "fixed"


def test_classify_oob_without_oast_is_unverified() -> None:
    prior = _finding("ssrf:GET:/a:query:x", oob=True)
    outcomes = classify([prior], [], oast_attempted=False)
    assert outcomes[0].status == "unverified"


def test_classify_oob_with_oast_attempted_is_fixed() -> None:
    prior = _finding("ssrf:GET:/a:query:x", oob=True)
    outcomes = classify([prior], [], oast_attempted=True)
    assert outcomes[0].status == "fixed"


def test_open_findings_and_summarize() -> None:
    prior_open = _finding("sqli:GET:/a:query:x")
    prior_fixed = _finding("xss:GET:/b:query:x", url="http://t.test/b")
    prior_oob = _finding("ssrf:GET:/c:query:x", url="http://t.test/c", oob=True)
    outcomes = classify(
        [prior_open, prior_fixed, prior_oob],
        [_finding("sqli:GET:/a:query:x")],
        oast_attempted=False,
    )
    assert summarize(outcomes) == {"open": 1, "fixed": 1, "unverified": 1}
    still_open = open_findings(outcomes)
    assert [f.id for f in still_open] == ["sqli:GET:/a:query:x"]


# --- end-to-end against the vulnerable target --------------------------------------------


async def _scan(vuln_app_url: str, requests=None) -> list[Finding]:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    rate_limit = RateLimitConfig(requests_per_second=50, max_concurrency=20)
    async with HttpClient(scope, rate_limit=rate_limit) as client:
        scanner = Scanner(client, load_rules())
        if requests is None:
            requests = await HttpCrawler(client).crawl(f"{vuln_app_url}/")
        return await scanner.scan(requests)


async def test_retest_unchanged_target_marks_everything_open(vuln_app_url: str) -> None:
    prior = await _scan(vuln_app_url)
    assert prior  # sanity: the scan found the planted vulns

    fresh = await _scan(vuln_app_url, base_requests_for(prior))
    outcomes = classify(prior, fresh, oast_attempted=False)

    counts = summarize(outcomes)
    # Target is untouched between runs, so every prior finding must reappear as open.
    assert counts == {"open": len(prior), "fixed": 0, "unverified": 0}
    assert {o.prior.id for o in outcomes} == {f.id for f in prior}
