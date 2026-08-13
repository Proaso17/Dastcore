"""Report export: DefectDojo Generic Findings Import JSON, and PDF (optional fpdf2 extra)."""

from __future__ import annotations

import json
import sys

from typer.testing import CliRunner

from dastcore.cli import app
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.report import render_defectdojo
from dastcore.report.pdf import render_pdf

runner = CliRunner()


def _finding(rule_id: str, *, severity: str = "high", cwe: str = "CWE-89") -> Finding:
    request = HttpRequest(method="POST", url="http://t.test/api", params={"id": "1"})
    point = InjectionPoint(location="query", name="id", request_template=request)
    return Finding(
        id=f"{rule_id}:POST:/api:query:id",
        rule_id=rule_id,
        name=rule_id.upper(),
        severity=severity,  # type: ignore[arg-type]
        cwe=cwe,
        owasp="WSTG-INPV-05",
        injection_point=point,
        evidence=[Evidence(type="differential", data="baseline!=mutated " + "x" * 200)],  # long unbroken token
        request=request,
        response=HttpResponse(status_code=200),
        remediation="parametrise the query",
    )


# --- DefectDojo ------------------------------------------------------------------------


def test_defectdojo_maps_fields() -> None:
    payload = json.loads(render_defectdojo([_finding("sqli", severity="critical", cwe="CWE-89")]))
    f = payload["findings"][0]
    assert f["severity"] == "Critical"  # Title-case for DefectDojo
    assert f["cwe"] == 89  # integer, not "CWE-89"
    assert f["unique_id_from_tool"] == "sqli:POST:/api:query:id"  # stable id → dedup on re-import
    assert f["vuln_id_from_tool"] == "sqli"
    assert f["endpoints"] == ["http://t.test/api"]
    assert f["verified"] is True and f["false_p"] is False


def test_defectdojo_severity_and_missing_cwe() -> None:
    payload = json.loads(render_defectdojo([_finding("x", severity="low", cwe="")]))
    assert payload["findings"][0]["severity"] == "Low"
    assert payload["findings"][0]["cwe"] == 0  # no CWE number → 0


def test_defectdojo_empty() -> None:
    assert json.loads(render_defectdojo([])) == {"findings": []}


# --- PDF -------------------------------------------------------------------------------


def test_pdf_renders_bytes_for_both_audiences() -> None:
    findings = [_finding("sqli", severity="critical"), _finding("xss", severity="medium")]
    dev = render_pdf(findings, target="http://t.test", audience="developer")
    exe = render_pdf(findings, target="http://t.test", audience="executive")
    assert dev.startswith(b"%PDF") and exe.startswith(b"%PDF")
    assert len(dev) > len(exe)  # developer adds the reproduction curl detail


def test_pdf_empty_findings_still_renders() -> None:
    assert render_pdf([]).startswith(b"%PDF")


def test_pdf_missing_dependency_raises_actionable_error(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "fpdf", None)  # simulate fpdf2 not installed
    try:
        render_pdf([_finding("sqli")])
        raise AssertionError("expected RuntimeError")
    except RuntimeError as exc:
        assert "dastcore[pdf]" in str(exc)


# --- CLI ------------------------------------------------------------------------------


def test_cli_pdf_requires_output() -> None:
    result = runner.invoke(app, ["scan", "http://127.0.0.1:9", "--i-have-authorization", "-f", "pdf"])
    assert result.exit_code == 1
    assert "requiere --output" in result.stdout


def test_cli_rejects_unknown_format() -> None:
    result = runner.invoke(app, ["scan", "http://127.0.0.1:9", "--i-have-authorization", "-f", "xlsx"])
    assert result.exit_code == 1
    assert "Formato inválido" in result.stdout
