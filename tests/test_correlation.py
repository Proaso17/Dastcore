"""Deduplication and correlation of findings into issues."""

from __future__ import annotations

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.report.correlation import correlate, deduplicate
from dastcore.report.html import render_html


def _finding(rule_id: str, url: str, name_param: str, severity: str = "high") -> Finding:
    request = HttpRequest(method="GET", url=url, params={name_param: "x"})
    point = InjectionPoint(location="query", name=name_param, request_template=request)
    return Finding(
        id=f"{rule_id}:GET:{url}:query:{name_param}",
        rule_id=rule_id,
        name=rule_id.upper(),
        severity=severity,  # type: ignore[arg-type]
        cwe="CWE-1",
        owasp="OWASP",
        injection_point=point,
        evidence=[Evidence(type="reflected", data="e")],
        request=request,
        response=HttpResponse(status_code=200),
        remediation="fix",
    )


def test_deduplicate_removes_exact_repeats() -> None:
    a = _finding("xss", "http://t/a", "q")
    dup = _finding("xss", "http://t/a", "q")  # identical id
    b = _finding("sqli", "http://t/b", "id")
    result = deduplicate([a, dup, b])
    assert [f.id for f in result] == [a.id, b.id]


def test_correlate_groups_by_rule_with_counts_and_locations() -> None:
    findings = [
        _finding("xss", "http://t/a", "q"),
        _finding("xss", "http://t/b", "name"),
        _finding("sqli", "http://t/c", "id", severity="critical"),
        _finding("xss", "http://t/a", "q"),  # duplicate — ignored
    ]
    issues = correlate(findings)
    by_rule = {i.rule_id: i for i in issues}
    assert by_rule["xss"].count == 2
    assert len(by_rule["xss"].locations) == 2
    assert by_rule["sqli"].count == 1
    # sorted most-severe first
    assert issues[0].rule_id == "sqli"  # critical outranks high


def test_correlate_empty() -> None:
    assert correlate([]) == []


def test_html_report_shows_issue_overview_table() -> None:
    findings = [_finding("xss", "http://t/a", "q"), _finding("xss", "http://t/b", "name")]
    html = render_html(findings)
    assert 'class="issues"' in html
    assert "Instancias" in html
    # the xss issue shows a count of 2
    assert '<td class="num">2</td>' in html
