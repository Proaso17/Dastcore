"""Bug-bounty mode: suppress the hardening/disclosure/no-impact findings a program closes as N/A
(HackerOne Core ineligible list), never the impactful ones — and never delete anything."""

from __future__ import annotations

from dastcore.bugbounty.eligibility import is_ineligible, mark_ineligible
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint


def _finding(rule_id: str, family: str = "", *, severity: str = "medium", suppressed: bool = False) -> Finding:
    request = HttpRequest(method="GET", url="http://x/y")
    point = InjectionPoint(location="query", name="q", base_value="", request_template=request)
    return Finding(
        id=f"f:{rule_id}", rule_id=rule_id, name=rule_id, severity=severity, cwe="CWE-0", owasp="",
        family=family, injection_point=point, evidence=[Evidence(type="response_match", data="d")],
        request=request, response=HttpResponse(status_code=200, url="http://x/y"),
        remediation="", suppressed=suppressed,
    )


def test_ineligible_classes_are_flagged() -> None:
    for rid in ("passive-missing-csp", "passive-reverse-tabnabbing", "tech-fingerprint",
                "host-header-injection", "waf-detected", "csrf-token-not-enforced"):
        assert is_ineligible(_finding(rid)) is True
    assert is_ineligible(_finding("tls-cert-expired", family="tls")) is True
    assert is_ineligible(_finding("open-redirect", family="open_redirect")) is True


def test_impactful_findings_are_never_flagged() -> None:
    for rid, fam in (("sqli-injection", "sqli"), ("xss-reflected", "xss"), ("idor", "authz"),
                     ("lfi-php-filter", "lfi"), ("ssrf-cloud-metadata", "ssrf")):
        assert is_ineligible(_finding(rid, family=fam)) is False


def test_mark_ineligible_suppresses_only_ineligible_and_reports_count() -> None:
    findings = [
        _finding("sqli-injection", "sqli"),          # eligible -> untouched
        _finding("passive-missing-csp"),             # ineligible -> suppressed
        _finding("tech-fingerprint", severity="info"),  # ineligible -> suppressed
    ]
    n = mark_ineligible(findings)
    assert n == 2
    assert findings[0].suppressed is False  # the SQLi stays active/reportable
    assert findings[1].suppressed is True and "Inelegible" in (findings[1].suppression_reason or "")
    assert findings[2].suppressed is True


def test_existing_suppression_is_not_overridden() -> None:
    f = _finding("passive-missing-csp", suppressed=True)
    f.suppression_reason = "already triaged via .dastcore-ignore"
    mark_ineligible([f])
    assert f.suppression_reason == "already triaged via .dastcore-ignore"  # kept
