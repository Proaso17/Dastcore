"""`dastcore baseline promote/status`: adopt a scan JSON as the CI baseline for `dastcore diff`."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from dastcore.cli import app
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.report import render_json

runner = CliRunner()


def _finding(fid: str, *, severity: str = "high") -> Finding:
    request = HttpRequest(method="GET", url="http://t.test/a", params={"x": "1"})
    point = InjectionPoint(location="query", name="x", request_template=request)
    return Finding(
        id=fid,
        rule_id=fid.split(":")[0],
        name=fid.split(":")[0].upper(),
        severity=severity,  # type: ignore[arg-type]
        cwe="CWE-1",
        owasp="WSTG-1",
        injection_point=point,
        evidence=[Evidence(type="response_match", data="e")],
        request=request,
        response=HttpResponse(status_code=200),
        remediation="fix",
    )


def _scan_json(tmp_path, name: str, findings: list[Finding]) -> str:
    path = tmp_path / name
    path.write_text(render_json(findings), encoding="utf-8")
    return str(path)


def test_promote_writes_baseline_and_creates_dirs(tmp_path) -> None:
    current = _scan_json(tmp_path, "current.json", [_finding("sqli:1"), _finding("xss:1", severity="low")])
    baseline = tmp_path / ".dastcore" / "baseline.json"  # nested dir does not exist yet
    result = runner.invoke(app, ["baseline", "promote", current, "--baseline", str(baseline)])
    assert result.exit_code == 0
    assert baseline.exists()
    ids = {f["id"] for f in json.loads(baseline.read_text(encoding="utf-8"))}
    assert ids == {"sqli:1", "xss:1"}
    assert "2 hallazgos" in result.stdout


def test_promoted_baseline_feeds_diff(tmp_path) -> None:
    # promote a baseline, then a scan with a new finding should be a regression via `diff`
    base_src = _scan_json(tmp_path, "base_src.json", [_finding("sqli:1")])
    baseline = tmp_path / "baseline.json"
    runner.invoke(app, ["baseline", "promote", base_src, "--baseline", str(baseline), "--quiet"])
    head = _scan_json(tmp_path, "head.json", [_finding("sqli:1"), _finding("cmdi:1", severity="critical")])
    result = runner.invoke(app, ["diff", str(baseline), head, "--quiet", "-f", "json", "--fail-on", "high"])
    assert result.exit_code == 2  # the new critical is a regression vs the promoted baseline
    assert '"rule_id": "cmdi"' in result.stdout and '"rule_id": "sqli"' not in result.stdout


def test_status_reports_summary_and_absence(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    absent = runner.invoke(app, ["baseline", "status", "--baseline", str(baseline)])
    assert absent.exit_code == 0 and "No hay línea base" in absent.stdout

    current = _scan_json(tmp_path, "current.json", [_finding("sqli:1")])
    runner.invoke(app, ["baseline", "promote", current, "--baseline", str(baseline), "--quiet"])
    present = runner.invoke(app, ["baseline", "status", "--baseline", str(baseline)])
    assert present.exit_code == 0 and "1 hallazgos" in present.stdout


def test_promote_rejects_invalid_json(tmp_path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["baseline", "promote", str(bad)])
    assert result.exit_code == 1 and "inválido" in result.stdout
