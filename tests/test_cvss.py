"""CVSS 3.1 base-score calculation and its exposure on findings and reports."""

from __future__ import annotations

import json

import pytest

from dastcore.cvss import base_score, default_vector, parse_vector, severity_from_score
from dastcore.engine.rule_engine import load_rules


@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),  # full impact, unchanged scope
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),  # read-only high
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # canonical reflected XSS
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # scope changed, full impact
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    ],
)
def test_base_score_matches_official(vector: str, expected: float) -> None:
    assert base_score(vector) == expected


def test_base_score_zero_impact_is_zero() -> None:
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_invalid_vector_is_zero() -> None:
    assert base_score("garbage") == 0.0
    assert parse_vector("CVSS:3.1/AV:N")["AV"] == "N"


def test_severity_from_score_bands() -> None:
    assert severity_from_score(0.0) == "info"
    assert severity_from_score(3.9) == "low"
    assert severity_from_score(6.9) == "medium"
    assert severity_from_score(8.9) == "high"
    assert severity_from_score(9.0) == "critical"


def test_default_vectors_land_in_band() -> None:
    assert base_score(default_vector("critical")) == 10.0
    assert base_score(default_vector("high")) == 7.5
    assert base_score(default_vector("medium")) == 6.1
    assert base_score(default_vector("info")) == 0.0


def test_all_web_rules_have_valid_cvss_vectors() -> None:
    for rule in load_rules():
        assert rule.cvss, f"{rule.id} missing cvss vector"
        assert base_score(rule.cvss) > 0.0, f"{rule.id} vector scores 0"


def test_finding_exposes_cvss(sample_finding) -> None:
    # sample_finding has no explicit cvss -> severity default (high -> 7.5)
    assert sample_finding.cvss_score == 7.5
    data = json.loads(sample_finding.model_dump_json())
    assert data["cvss_score"] == 7.5
    assert data["cvss_vector"].startswith("CVSS:3.1/")


def test_finding_uses_explicit_rule_vector() -> None:
    sqli = next(r for r in load_rules() if r.id == "sqli-injection")
    from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

    request = HttpRequest(method="GET", url="http://t/s", params={"q": "'"})
    finding = Finding(
        id="sqli:x",
        rule_id="sqli-injection",
        name="SQL Injection",
        severity="high",
        cwe="CWE-89",
        owasp="WSTG-INPV-05",
        injection_point=InjectionPoint(location="query", name="q", request_template=request),
        evidence=[Evidence(type="response_match", data="SQL syntax")],
        request=request,
        response=HttpResponse(status_code=500),
        remediation="fix",
        cvss=sqli.cvss,
    )
    assert finding.cvss_score == 9.8  # explicit vector, not the severity default


def test_sarif_and_html_expose_cvss(sample_finding) -> None:
    from dastcore.report.html import render_html
    from dastcore.report.sarif import build_sarif

    result = build_sarif([sample_finding])["runs"][0]["results"][0]
    assert result["properties"]["cvss_score"] == 7.5
    assert result["properties"]["security-severity"] == "7.5"

    html = render_html([sample_finding])
    assert "7.5" in html
    assert "CVSS" in html
