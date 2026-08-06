"""Unit tests for the scan-to-scan diff (pure, no network)."""

from __future__ import annotations

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.web.diff import diff_findings, location_label


def _finding(fid: str) -> Finding:
    request = HttpRequest(method="GET", url="http://t.test/a", params={"x": "1"})
    point = InjectionPoint(location="query", name="x", request_template=request)
    return Finding(
        id=fid,
        rule_id=fid.split(":")[0],
        name="Issue",
        severity="high",
        cwe="CWE-1",
        owasp="WSTG-1",
        injection_point=point,
        evidence=[Evidence(type="response_match", data="e")],
        request=request,
        response=HttpResponse(status_code=200),
        remediation="fix",
    )


def test_diff_partitions_new_fixed_persistent() -> None:
    base = [_finding("a:1"), _finding("b:1")]
    head = [_finding("b:1"), _finding("c:1")]
    result = diff_findings(base, head)
    assert [f.id for f in result.new] == ["c:1"]
    assert [f.id for f in result.fixed] == ["a:1"]
    assert [f.id for f in result.persistent] == ["b:1"]
    assert result.counts == {"new": 1, "fixed": 1, "persistent": 1}


def test_diff_identical_sets_are_all_persistent() -> None:
    findings = [_finding("a:1"), _finding("b:1")]
    result = diff_findings(findings, list(findings))
    assert result.counts == {"new": 0, "fixed": 0, "persistent": 2}


def test_location_label_is_compact() -> None:
    assert location_label(_finding("a:1")) == "GET /a (query:x)"
