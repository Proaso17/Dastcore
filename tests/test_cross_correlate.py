"""Cross-technique correlation: one scenario confirmed by several rules."""

from __future__ import annotations

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.report.correlation import cross_correlate


def _finding(rule_id: str, family: str, *, url: str = "http://t/api/user", name: str = "id") -> Finding:
    request = HttpRequest(method="GET", url=url, params={name: "1"})
    point = InjectionPoint(location="query", name=name, request_template=request)
    return Finding(
        id=f"{rule_id}:GET:/api/user:query:{name}",
        rule_id=rule_id,
        name=rule_id,
        severity="high",
        cwe="CWE-89",
        owasp="X",
        family=family,
        injection_point=point,
        evidence=[Evidence(type="differential", data="e", confidence="medium")],
        request=request,
        response=HttpResponse(status_code=200),
        remediation="x",
    )


def test_same_point_different_rules_cross_confirm() -> None:
    a = _finding("sqli-injection", "sqli")
    b = _finding("sqli-boolean-blind", "sqli")
    out = cross_correlate([a, b])
    by_rule = {f.rule_id: f for f in out}
    assert by_rule["sqli-injection"].corroborated_by == ["sqli-boolean-blind"]
    assert by_rule["sqli-boolean-blind"].corroborated_by == ["sqli-injection"]


def test_cross_confirmation_raises_confidence() -> None:
    single = _finding("sqli-boolean-blind", "sqli")
    assert single.confidence == "medium"  # one medium differential alone
    corroborated = cross_correlate([single, _finding("sqli-injection", "sqli")])
    boolean = next(f for f in corroborated if f.rule_id == "sqli-boolean-blind")
    assert boolean.confidence == "high"  # a second technique pushed it over the line


def test_different_families_or_points_do_not_correlate() -> None:
    a = _finding("sqli-injection", "sqli")
    b = _finding("xss-reflected", "xss")  # different family
    c = _finding("sqli-injection", "sqli", name="q")  # different param
    out = cross_correlate([a, b, c])
    assert all(f.corroborated_by == [] for f in out)


def test_findings_without_family_are_untouched() -> None:
    a = _finding("passive-x", "")  # no family (passive/authz/etc.)
    assert cross_correlate([a, a.model_copy()])[0].corroborated_by == []
