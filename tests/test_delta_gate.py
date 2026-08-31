"""Delta gating for CI: --fail-on counts only findings NEW versus a baseline, so a PR breaks the build
only when it *introduces* a vulnerability — not because of the pre-existing backlog."""

from __future__ import annotations

import pytest
import typer

from dastcore.cli import _delta_gate_findings, _emit_report_and_gate
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint


def _finding(fid: str, severity: str = "high") -> Finding:
    req = HttpRequest(method="GET", url="http://t.test/x", params={"q": "1"})
    pt = InjectionPoint(location="query", name="q", base_value="1", request_template=req)
    return Finding(id=fid, rule_id="sqli-injection", name="SQLi", severity=severity, cwe="CWE-89", owasp="",
                   family="sqli", injection_point=pt,
                   evidence=[Evidence(type="differential", data="x", confidence="high")],
                   request=req, response=HttpResponse(status_code=500), remediation="x")


def test_delta_gate_findings_returns_none_without_the_flag() -> None:
    assert _delta_gate_findings([_finding("a")], "", gate_on_new=False) is None


def test_delta_gate_findings_returns_only_the_new_ones(tmp_path) -> None:
    import json

    baseline = tmp_path / "base.json"
    baseline.write_text(json.dumps([_finding("a").model_dump(mode="json")]), encoding="utf-8")
    new = _delta_gate_findings([_finding("a"), _finding("b")], str(baseline), gate_on_new=True)
    assert new is not None and {f.id for f in new} == {"b"}  # 'a' is in the baseline, only 'b' is new


def test_delta_gate_findings_treats_all_as_new_when_no_baseline() -> None:
    new = _delta_gate_findings([_finding("a"), _finding("b")], "", gate_on_new=True)
    assert new is not None and {f.id for f in new} == {"a", "b"}  # no baseline -> everything is new


def _gate(findings, gate_findings, fail_on="high") -> None:
    _emit_report_and_gate(
        findings, output_format="json", output_path="", fail_on=fail_on, quiet=True,
        target="http://t.test", duration_s=0.0, gate_findings=gate_findings,
    )


def test_gate_passes_when_no_new_findings_even_if_backlog_is_high() -> None:
    # A high finding exists, but it's not NEW (gate_findings empty) -> the build must NOT fail.
    _gate([_finding("a", "critical")], gate_findings=[])  # no exception


def test_gate_fails_on_a_new_high_finding() -> None:
    with pytest.raises(typer.Exit) as exc:
        _gate([_finding("a", "high")], gate_findings=[_finding("a", "high")])
    assert exc.value.exit_code == 2


def test_gate_without_delta_fails_on_the_backlog_by_default() -> None:
    # gate_findings=None keeps the original behaviour: any active high finding trips the gate.
    with pytest.raises(typer.Exit) as exc:
        _gate([_finding("a", "high")], gate_findings=None)
    assert exc.value.exit_code == 2
