"""Evidence pack: the review-ready bundle. A strong, oracle-backed finding is ready to submit with a
full draft; a weak one is flagged NOT ready with concrete blockers and the anti-N/A banner in the draft —
so the human never hands over something that would be closed N/A."""

from __future__ import annotations

from dastcore.bugbounty.evidence import build_evidence_pack
from dastcore.bugbounty.queue import QueuedCandidate
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint


def _candidate(evidence: list[Evidence], *, vrt="Server-Side Injection - SQL Injection", pri="P1") -> QueuedCandidate:
    req = HttpRequest(method="GET", url="https://a.example.com/p?id=1", params={"id": "1"})
    point = InjectionPoint(location="query", name="id", base_value="1", request_template=req)
    finding = Finding(
        id="f1", rule_id="sqli-injection", name="SQL Injection", severity="high", cwe="CWE-89",
        owasp="WSTG-INPV-05", injection_point=point, evidence=evidence, request=req,
        response=HttpResponse(status_code=500, url=req.url), remediation="parameterize", family="sqli",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    return QueuedCandidate(
        program="acme", signature="sqli|a.example.com|query:id", finding=finding, vrt_category=vrt,
        vrt_priority=pri, priority_score=55.0, variants=2, checklist_passes=True, status="pending",
        first_seen=1.0, last_seen=1.0,
    )


def test_ready_candidate_yields_a_submittable_draft() -> None:
    pack = build_evidence_pack(
        _candidate([Evidence(type="differential", data="oracle confirmed", confidence="high")]),
        platform="hackerone",
    )
    assert pack.ready_to_submit is True and pack.blockers == []
    assert "Steps To Reproduce" in pack.draft and "curl" in pack.draft  # HackerOne layout + PoC
    assert "NO LISTO PARA ENVIAR" not in pack.draft


def test_weak_candidate_is_flagged_not_ready_with_blockers() -> None:
    # A single low-confidence reflection: not exploitable-now, no deterministic oracle → would be N/A.
    pack = build_evidence_pack(_candidate([Evidence(type="reflected", data="echoed", confidence="low")]))
    assert pack.ready_to_submit is False
    assert any("Explotabilidad" in b for b in pack.blockers)
    assert any("determinista" in b for b in pack.blockers)
    assert "NO LISTO PARA ENVIAR" in pack.draft  # the anti-N/A banner leads the draft
