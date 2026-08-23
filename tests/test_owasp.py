"""OWASP Top 10 (2021) classification + coverage rollup: family-keyword first, CWE fallback, and a
summary that always lists all ten categories in order."""

from __future__ import annotations

from dastcore.core.models import Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.owasp import OWASP_2021, category_for, summarize


def _f(*, rule_id: str = "", name: str = "", cwe: str = "", severity: str = "high", fid: str = "1") -> Finding:
    req = HttpRequest(method="GET", url="http://t/")
    return Finding(
        id=fid, rule_id=rule_id, name=name, severity=severity, cwe=cwe, owasp="",
        injection_point=InjectionPoint(location="query", name="x", base_value="", request_template=req),
        request=req, response=HttpResponse(status_code=200), remediation="",
    )


def test_classifies_by_rule_family() -> None:
    assert category_for(_f(rule_id="sqli-injection")) == "A03"
    assert category_for(_f(rule_id="jwt-none-accepted")) == "A07"
    assert category_for(_f(rule_id="ssrf-oob")) == "A10"
    assert category_for(_f(rule_id="idor-cross-account")) == "A01"
    assert category_for(_f(rule_id="deserialization-rce")) == "A08"
    assert category_for(_f(name="Missing security header: CSP")) == "A05"


def test_falls_back_to_cwe() -> None:
    assert category_for(_f(name="weird thing", cwe="CWE-89")) == "A03"      # SQLi CWE
    assert category_for(_f(name="weird thing", cwe="CWE-918")) == "A10"     # SSRF CWE
    assert category_for(_f(name="weird thing", cwe="CWE-502")) == "A08"     # deserialization CWE
    assert category_for(_f(name="weird thing", cwe="CWE-319")) == "A02"     # cleartext transmission


def test_unclassified_defaults_to_misconfig() -> None:
    assert category_for(_f(name="totally novel", cwe="")) == "A05"


def test_tech_fingerprint_maps_to_components_not_access_control() -> None:
    # a tech/version disclosure carries a generic CWE-200; it must not land in A01 via the CWE fallback
    assert category_for(_f(rule_id="tech-fingerprint", name="Technology fingerprint", cwe="CWE-200")) == "A06"


def test_advisories_are_excluded_from_the_rollup() -> None:
    findings = [
        _f(rule_id="spa-detected", name="SPA detected", cwe="CWE-200", severity="info", fid="s"),
        _f(rule_id="scan-coverage", name="Cobertura parcial", cwe="CWE-200", severity="info", fid="c"),
        _f(rule_id="user-enumeration", name="User enumeration", cwe="CWE-204", severity="medium", fid="u"),
    ]
    by_code = {row["code"]: row for row in summarize(findings)}
    assert by_code["A01"]["count"] == 0  # the CWE-200 advisories no longer pollute Broken Access Control
    assert by_code["A07"]["count"] == 1  # only the real finding is counted


def test_summarize_lists_all_ten_in_order_with_counts() -> None:
    findings = [
        _f(rule_id="sqli-injection", severity="critical", fid="a"),
        _f(rule_id="xss-reflected", severity="medium", fid="b"),
        _f(rule_id="jwt-alg-confusion", severity="high", fid="c"),
    ]
    summary = summarize(findings)
    assert [row["code"] for row in summary] == [code for code, _ in OWASP_2021]  # all 10, canonical order
    by_code = {row["code"]: row for row in summary}
    assert by_code["A03"]["count"] == 2 and by_code["A03"]["worst_severity"] == "critical"
    assert by_code["A07"]["count"] == 1
    assert by_code["A10"]["count"] == 0 and by_code["A10"]["worst_severity"] is None
    assert by_code["A03"]["capability"] == "full"
    assert set(by_code["A03"]["finding_ids"]) == {"a", "b"}  # type: ignore[arg-type]
