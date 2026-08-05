"""Phase 4: report renderers (JSON / SARIF 2.1.0 / HTML) and severity mapping."""

from __future__ import annotations

import json

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.report import render_html, render_json
from dastcore.report.sarif import build_sarif
from dastcore.severity import meets_threshold, sarif_level, severity_rank

_VALID_SARIF_LEVELS = {"none", "note", "warning", "error"}
XSS_PAYLOAD = "<script>alert(1)</script>"


def _xss_finding() -> Finding:
    request = HttpRequest(method="GET", url="http://target.test/greet", params={"name": XSS_PAYLOAD})
    point = InjectionPoint(location="query", name="name", base_value="", request_template=request)
    response = HttpResponse(status_code=200, text=f"<h1>Hello {XSS_PAYLOAD}</h1>", elapsed_ms=5.0)
    return Finding(
        id="xss-reflected:GET:/greet:query:name",
        rule_id="xss-reflected",
        name="Reflected Cross-Site Scripting (XSS)",
        severity="high",
        cwe="CWE-79",
        owasp="WSTG-INPV-01",
        injection_point=point,
        evidence=[Evidence(type="reflected", data=XSS_PAYLOAD, confidence="medium")],
        request=request,
        response=response,
        remediation="HTML-encode all user input before rendering.",
    )


def _second_xss_finding() -> Finding:
    """Same rule_id as _xss_finding, different location — for SARIF rule dedup."""
    request = HttpRequest(method="GET", url="http://target.test/search", params={"q": XSS_PAYLOAD})
    point = InjectionPoint(location="query", name="q", base_value="", request_template=request)
    response = HttpResponse(status_code=200, text=f"results {XSS_PAYLOAD}", elapsed_ms=4.0)
    return Finding(
        id="xss-reflected:GET:/search:query:q",
        rule_id="xss-reflected",
        name="Reflected Cross-Site Scripting (XSS)",
        severity="high",
        cwe="CWE-79",
        owasp="WSTG-INPV-01",
        injection_point=point,
        evidence=[Evidence(type="reflected", data=XSS_PAYLOAD, confidence="medium")],
        request=request,
        response=response,
        remediation="HTML-encode all user input before rendering.",
    )


def _passive_finding() -> Finding:
    request = HttpRequest(method="GET", url="http://target.test/")
    point = InjectionPoint(location="header", name="X-Frame-Options", base_value="", request_template=request)
    response = HttpResponse(status_code=200, elapsed_ms=2.0)
    return Finding(
        id="passive-missing-x-frame-options",
        rule_id="passive-missing-x-frame-options",
        name="Missing clickjacking protection",
        severity="medium",
        cwe="CWE-1021",
        owasp="WSTG-CLNT-09",
        injection_point=point,
        evidence=[Evidence(type="status", data="No X-Frame-Options", confidence="high")],
        request=request,
        response=response,
        remediation="Set X-Frame-Options: DENY.",
    )


def _sample_findings() -> list[Finding]:
    return [_xss_finding(), _second_xss_finding(), _passive_finding()]


# --- severity mapping -----------------------------------------------------------------


def test_severity_rank_orders_low_to_high() -> None:
    assert severity_rank("info") < severity_rank("low") < severity_rank("medium")
    assert severity_rank("medium") < severity_rank("high") < severity_rank("critical")


def test_meets_threshold() -> None:
    assert meets_threshold("high", "high") is True
    assert meets_threshold("critical", "high") is True
    assert meets_threshold("medium", "high") is False


def test_sarif_level_mapping() -> None:
    assert sarif_level("critical") == "error"
    assert sarif_level("high") == "error"
    assert sarif_level("medium") == "warning"
    assert sarif_level("low") == "note"
    assert sarif_level("info") == "none"


# --- JSON -----------------------------------------------------------------------------


def test_render_json_roundtrips_all_findings() -> None:
    data = json.loads(render_json(_sample_findings()))
    assert len(data) == 3
    assert {f["rule_id"] for f in data} == {"xss-reflected", "passive-missing-x-frame-options"}
    assert data[0]["evidence"][0]["type"] == "reflected"


def test_render_json_empty() -> None:
    assert json.loads(render_json([])) == []


# --- SARIF 2.1.0 ----------------------------------------------------------------------


def _assert_valid_sarif(doc: dict) -> None:
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert isinstance(doc["runs"], list) and doc["runs"]
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "dastcore"
    rule_ids = {rule["id"] for rule in driver["rules"]}
    assert rule_ids  # at least one rule when there are results
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        assert result["level"] in _VALID_SARIF_LEVELS
        assert isinstance(result["message"]["text"], str) and result["message"]["text"]
        locations = result["locations"]
        assert locations
        assert locations[0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_is_structurally_valid() -> None:
    _assert_valid_sarif(build_sarif(_sample_findings()))


def test_sarif_empty_is_valid_with_no_results() -> None:
    doc = build_sarif([])
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_dedups_rules_by_rule_id() -> None:
    doc = build_sarif(_sample_findings())
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    # two xss findings share one rule; the passive one is its own rule -> 2 rules, 3 results
    assert len(rules) == 2
    assert len(doc["runs"][0]["results"]) == 3


def test_sarif_result_carries_level_cwe_and_security_severity() -> None:
    doc = build_sarif([_xss_finding()])
    result = doc["runs"][0]["results"][0]
    assert result["level"] == "error"  # high -> error
    assert result["properties"]["cwe"] == "CWE-79"
    assert result["properties"]["security-severity"] == "8.0"


def test_sarif_rule_help_uri_points_to_cwe() -> None:
    doc = build_sarif([_xss_finding()])
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"] == "https://cwe.mitre.org/data/definitions/79.html"


# --- HTML -----------------------------------------------------------------------------


def test_html_contains_finding_details() -> None:
    html = render_html(_sample_findings(), target="http://target.test")
    assert "Reflected Cross-Site Scripting" in html
    assert "CWE-79" in html
    assert "HTML-encode all user input" in html
    assert "http://target.test" in html


def test_html_escapes_attacker_controlled_payloads() -> None:
    """A security tool must not let a captured XSS payload execute inside its own report."""
    html = render_html([_xss_finding()])
    # the raw executable payload must NOT appear verbatim...
    assert XSS_PAYLOAD not in html
    # ...it must be HTML-escaped instead.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_is_self_contained() -> None:
    html = render_html(_sample_findings())
    # no external assets: no remote scripts or stylesheets
    assert "<script src=" not in html
    assert 'rel="stylesheet"' not in html
    assert "cdn" not in html.lower()
    assert "<style>" in html  # styles are inlined


def test_html_empty_state() -> None:
    html = render_html([])
    assert "No findings" in html


def test_html_custom_title() -> None:
    html = render_html(_sample_findings(), title="LLM Security Report")
    assert "<title>LLM Security Report" in html
    assert "<h1>LLM Security Report</h1>" in html


def test_html_grouped_by_category() -> None:
    # two findings share OWASP category (xss), one is different (passive) -> 2 groups.
    html = render_html(_sample_findings(), group_by_category=True)
    assert 'class="category"' in html
    assert "WSTG-INPV-01" in html  # the XSS category header
    assert 'class="count">2<' in html  # the two XSS findings grouped
