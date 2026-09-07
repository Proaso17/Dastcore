"""--min-confidence gate: a finding below the confidence bar stays in the report but must NOT trip the
--fail-on CI gate (Burp-style confidence filter). Confidence tiers: low=Tentative, medium=Firm, high=Certain."""

from __future__ import annotations

import pytest
import typer

from dastcore import cli
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint


def _finding(evidence: list[Evidence]) -> Finding:
    req = HttpRequest(method="GET", url="http://t/x", params={"q": "1"})
    point = InjectionPoint(location="query", name="q", base_value="1", request_template=req)
    return Finding(
        id="f1", rule_id="sqli-injection", name="SQL Injection", severity="high", cwe="CWE-89",
        owasp="WSTG-INPV-05", injection_point=point, evidence=evidence, request=req,
        response=HttpResponse(status_code=200), remediation="n/a",
    )


def _gate(finding: Finding, min_confidence: str) -> None:
    cli._emit_report_and_gate(
        [finding], output_format="json", output_path="", fail_on="high",
        min_confidence=min_confidence, quiet=True, target="http://t", duration_s=0.1,
    )


def test_tentative_finding_does_not_trip_gate_at_high_bar() -> None:
    tentative = _finding([])  # no corroborating evidence -> confidence "low"
    assert tentative.confidence == "low"
    # Default bar (low): the high-severity finding trips --fail-on high.
    with pytest.raises(typer.Exit) as exc:
        _gate(tentative, "low")
    assert exc.value.exit_code == cli.EXIT_FINDINGS_OVER_THRESHOLD
    # Raised bar (high): the tentative finding is filtered out of the gate -> no failure.
    _gate(tentative, "high")  # must not raise


def test_certain_finding_still_trips_gate_at_high_bar() -> None:
    certain = _finding([Evidence(type="oob", data="x", confidence="high")])  # OOB -> confidence "high"
    assert certain.confidence == "high"
    with pytest.raises(typer.Exit) as exc:
        _gate(certain, "high")
    assert exc.value.exit_code == cli.EXIT_FINDINGS_OVER_THRESHOLD
