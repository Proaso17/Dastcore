"""Triage (Module 15): deterministic exploitability scoring, and the FP-safe AI layer.

The AI tests use a fake client (no network): they verify that the layer degrades gracefully
without a key, sends only confirmed findings, refuses to overturn the oracle, and structurally
drops any finding ID the model invents — the "IA never confirms/creates a finding" contract.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from dastcore.core.models import ChainStep, Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.triage import (
    AiTriageResult,
    build_triage_input,
    exploitability_score,
    family_weight,
    prioritize,
    triage_findings,
)


def _finding(
    rule_id: str,
    *,
    family: str = "sqli",
    severity: str = "high",
    cvss: str | None = None,
    suppressed: bool = False,
    with_evidence: bool = True,
) -> Finding:
    request = HttpRequest(method="POST", url=f"http://t/{rule_id}", params={"id": "1"})
    point = InjectionPoint(location="query", name="id", request_template=request)
    return Finding(
        id=f"{rule_id}:POST:/{rule_id}:query:id",
        rule_id=rule_id,
        name=rule_id.upper(),
        severity=severity,  # type: ignore[arg-type]
        cwe="CWE-89",
        owasp="WSTG-INPV-05",
        cvss=cvss,
        family=family,
        suppressed=suppressed,
        injection_point=point,
        evidence=[Evidence(type="differential", data="baseline≠mutated", confidence="high")] if with_evidence else [],
        request=request,
        response=HttpResponse(status_code=200),
        remediation="parametrise the query",
    )


# --- deterministic scoring -------------------------------------------------------------


def test_family_weight_known_and_unknown() -> None:
    assert family_weight("cmdi") > family_weight("open_redirect")
    assert family_weight("does-not-exist") == 1.0


def test_exploitability_is_clamped_and_family_scaled() -> None:
    sqli = _finding("sqli", family="sqli", cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
    redir = _finding("redir", family="open_redirect", cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
    assert 0.0 <= exploitability_score(sqli) <= 10.0
    # same CVSS, but the higher-weight family scores at least as high
    assert exploitability_score(sqli) >= exploitability_score(redir)


def test_prioritize_orders_most_urgent_first() -> None:
    low = _finding("low", family="open_redirect", severity="low", cvss="CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N")
    high = _finding("crit", family="cmdi", severity="critical", cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    ranked = prioritize([low, high])
    assert [t.finding.rule_id for t in ranked] == ["crit", "low"]
    assert ranked[0].band == "P1" and ranked[0].exploitability >= ranked[1].exploitability


# --- AI layer: graceful degradation ----------------------------------------------------


def test_triage_without_key_degrades_gracefully(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = triage_findings([_finding("sqli")])
    assert isinstance(result, AiTriageResult)
    assert result.generated is False
    assert result.error and "no Anthropic API key" in result.error


def test_triage_with_no_confirmed_findings_is_empty() -> None:
    # A suppressed finding and an evidence-less one are both ineligible → nothing to triage.
    findings = [_finding("sqli", suppressed=True), _finding("xss", with_evidence=False)]
    result = triage_findings(findings, client=_FakeClient({}))
    assert result.generated is False
    assert result.root_cause_groups == []


# --- AI layer: input construction ------------------------------------------------------


def test_build_triage_input_includes_only_confirmed_metadata_and_evidence() -> None:
    f = _finding("sqli")
    f.attack_chain = [ChainStep(actor="Attacker", action="Inject", detail="union select")]
    payload = json.loads(build_triage_input([f]))
    assert payload[0]["id"] == f.id
    assert payload[0]["evidence"][0]["type"] == "differential"
    assert payload[0]["attack_chain"][0]["action"] == "Inject"
    # no scanner internals leak in — just public finding metadata
    assert set(payload[0]) == {
        "id",
        "rule_id",
        "name",
        "family",
        "technical_severity",
        "cwe",
        "owasp",
        "cvss_score",
        "confidence",
        "location",
        "evidence",
        "attack_chain",
    }


# --- AI layer: FP-safety (fake client, no network) -------------------------------------


class _FakeClient:
    """Minimal Anthropic-shaped stub: records the request and returns a canned JSON body."""

    def __init__(self, body: dict, *, stop_reason: str = "end_turn") -> None:
        self._body = body
        self._stop_reason = stop_reason
        self.messages = SimpleNamespace(create=self._create)
        self.last_kwargs: dict = {}

    def _create(self, **kwargs):
        self.last_kwargs = kwargs
        text = json.dumps(self._body)
        return SimpleNamespace(
            stop_reason=self._stop_reason,
            content=[SimpleNamespace(type="text", text=text)],
        )


def test_triage_parses_and_marks_ai_generated() -> None:
    f = _finding("sqli")
    client = _FakeClient(
        {
            "executive_summary": "One SQL injection confirmed by a differential oracle.",
            "root_cause_groups": [
                {
                    "title": "Unparametrised queries",
                    "root_cause": "String-concatenated SQL",
                    "finding_ids": [f.id],
                    "remediation": "Use parametrised queries",
                }
            ],
            "business_severity": [{"finding_id": f.id, "level": "critical", "rationale": "Customer PII at risk"}],
        }
    )
    result = triage_findings([f], client=client)
    assert result.generated is True
    assert result.executive_summary.startswith("One SQL injection")
    assert result.root_cause_groups[0].ai_generated is True
    assert result.business_severity[0].level == "critical"
    assert result.business_severity[0].ai_generated is True
    # the model was given structured-output constraints, not free text
    assert "output_config" in client.last_kwargs


def test_triage_drops_hallucinated_finding_ids() -> None:
    f = _finding("sqli")
    client = _FakeClient(
        {
            "executive_summary": "summary",
            "root_cause_groups": [
                {"title": "real", "root_cause": "x", "finding_ids": [f.id], "remediation": "fix"},
                {"title": "ghost", "root_cause": "y", "finding_ids": ["does-not-exist"], "remediation": "fix"},
            ],
            "business_severity": [
                {"finding_id": f.id, "level": "high", "rationale": "ok"},
                {"finding_id": "phantom-finding", "level": "critical", "rationale": "invented"},
            ],
        }
    )
    result = triage_findings([f], client=client)
    # a group referencing only an invented ID is discarded; only the real finding survives
    assert [g.title for g in result.root_cause_groups] == ["real"]
    assert [b.finding_id for b in result.business_severity] == [f.id]


def test_triage_does_not_mutate_findings_or_overturn_oracle() -> None:
    f = _finding("sqli", severity="high")
    client = _FakeClient(
        {
            "executive_summary": "s",
            "root_cause_groups": [],
            "business_severity": [{"finding_id": f.id, "level": "low", "rationale": "advisory"}],
        }
    )
    result = triage_findings([f], client=client)
    # the AI's advisory business severity is separate; the finding's technical severity is untouched
    assert f.severity == "high"
    assert result.business_severity[0].level == "low"
    assert result.business_severity[0].ai_generated is True


def test_triage_handles_model_refusal() -> None:
    client = _FakeClient({}, stop_reason="refusal")
    result = triage_findings([_finding("sqli")], client=client)
    assert result.generated is False
    assert result.error and "unavailable" in result.error
