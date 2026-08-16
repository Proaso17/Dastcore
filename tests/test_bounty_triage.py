"""Phase 12: bug-bounty triage — VRT mapping, cross-asset dedupe, the FP gate, and payout-aware
prioritization. Deterministic, no network."""

from __future__ import annotations

from dastcore.bugbounty import Program
from dastcore.bugbounty.triage import dedupe_signature, fp_checklist, triage_for_bounty, vrt_for
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _finding(
    rule_id: str,
    *,
    family: str = "",
    severity: str = "high",
    host: str = "a.acme.com",
    param: str = "q",
    ev_type: str = "differential",
    ev_conf: str = "high",
    cvss: str | None = _CVSS,
    fid: str | None = None,
) -> Finding:
    req = HttpRequest(method="GET", url=f"http://{host}/x", params={param: "1"})
    point = InjectionPoint(location="query", name=param, base_value="1", request_template=req)
    return Finding(
        id=fid or f"{rule_id}:{host}:{param}",
        rule_id=rule_id,
        name=rule_id,
        severity=severity,
        cwe="CWE-0",
        owasp="x",  # type: ignore[arg-type]
        injection_point=point,
        evidence=[Evidence(type=ev_type, data="e", confidence=ev_conf)],  # type: ignore[arg-type]
        request=req,
        response=HttpResponse(status_code=200),
        remediation="x",
        family=family,
        cvss=cvss,
    )


def test_vrt_mapping_by_family_rule_and_severity_fallback() -> None:
    assert vrt_for(_finding("sqli-injection", family="sqli"))[1] == "P1"
    assert vrt_for(_finding("xss-reflected", family="xss"))[1] == "P3"
    assert vrt_for(_finding("authz-bola", family="authz"))[1] == "P2"  # rule override
    assert vrt_for(_finding("mystery-rule", family="", severity="medium"))[1] == "P3"  # severity fallback


def test_informational_noise_is_dropped() -> None:
    assert triage_for_bounty([_finding("passive-missing-hsts", severity="medium")]) == []


def test_fp_gate_drops_unconfirmed_findings() -> None:
    weak = _finding("xss-reflected", family="xss", ev_type="reflected", ev_conf="low")
    assert not fp_checklist(weak).passes  # low confidence + no deterministic oracle
    assert triage_for_bounty([weak]) == []


def test_dedupe_collapses_recurrences_across_scans() -> None:
    f1 = _finding("sqli-injection", family="sqli", host="a.acme.com", param="q", fid="s1")
    f2 = _finding("sqli-injection", family="sqli", host="a.acme.com", param="q", fid="s2")  # same signature
    other = _finding("sqli-injection", family="sqli", host="b.acme.com", param="q", fid="s3")  # different host
    result = triage_for_bounty([f1, f2, other])
    by_sig = {b.signature: b for b in result}
    assert by_sig[dedupe_signature(f1)].variants == 2  # a.acme.com collapsed
    assert by_sig[dedupe_signature(other)].variants == 1  # b.acme.com is a distinct submission


def test_prioritization_by_band_then_payout() -> None:
    program = Program(handle="acme", payouts={"sqli": 5000, "cmdi": 100})
    findings = [
        _finding("xss-reflected", family="xss", severity="high"),  # P3
        _finding("cmdi-inband", family="cmdi", severity="critical"),  # P1, small payout
        _finding("sqli-injection", family="sqli", severity="critical"),  # P1, big payout
    ]
    ranked = triage_for_bounty(findings, program)
    assert [b.finding.family for b in ranked] == ["sqli", "cmdi", "xss"]  # P1 (payout) > P1 > P3
    top = ranked[0]
    assert top.vrt_priority == "P1" and top.expected_payout == 5000 and top.cvss_vector == _CVSS
    assert top.checklist.passes
