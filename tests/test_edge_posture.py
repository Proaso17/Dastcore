"""Edge-posture correlator: folds WAF detection + WAF audit + ACL bypasses (path/method/header) into one
advisory. Summarizes confirmed findings only (no new FP surface) and is None when there is nothing edge."""

from __future__ import annotations

from dastcore.analysis.edge_posture import summarize_edge_posture
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.owasp import is_advisory


def _f(rule_id: str, url: str, severity: str = "high") -> Finding:
    req = HttpRequest(method="GET", url=url)
    return Finding(
        id=f"{rule_id}:{url}",
        rule_id=rule_id,
        name=rule_id,
        severity=severity,  # type: ignore[arg-type]
        cwe="CWE-284",
        owasp="A01:2021",
        injection_point=InjectionPoint(location="path", name="-", base_value="", request_template=req),
        evidence=[Evidence(type="status", data="x", confidence="high")],
        request=req,
        response=HttpResponse(status_code=200, text=""),
        remediation="x",
    )


def test_no_edge_findings_returns_none() -> None:
    assert summarize_edge_posture([_f("sqli", "http://t.test/a")], "http://t.test") is None


def test_summarizes_waf_and_bypasses_as_low_advisory() -> None:
    findings = [
        _f("waf-detected", "http://t.test/"),
        _f("waf-audit", "http://t.test/", severity="low"),
        _f("path-normalization-bypass", "http://t.test/admin"),
        _f("verb-tampering", "http://t.test/api/item/1"),
    ]
    edge = summarize_edge_posture(findings, "http://t.test")
    assert edge is not None
    assert edge.rule_id == "edge-posture" and edge.severity == "low"
    data = edge.evidence[0].data
    assert "WAF/CDN detectado" in data
    assert "normalización de ruta" in data and "manipulación de método" in data
    assert "/admin" in data
    assert is_advisory(edge)  # excluded from the OWASP rollup to avoid double-counting


def test_waf_present_without_bypasses_is_info() -> None:
    findings = [_f("waf-detected", "http://t.test/"), _f("waf-audit", "http://t.test/", severity="info")]
    edge = summarize_edge_posture(findings, "http://t.test")
    assert edge is not None
    assert edge.severity == "info"
    assert "no se hallaron bypasses" in edge.evidence[0].data
