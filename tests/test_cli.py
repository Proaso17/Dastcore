from __future__ import annotations

import json

from typer.testing import CliRunner

from dastcore.cli import app

runner = CliRunner()


def test_version_prints_banner_and_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "AVISO LEGAL" in result.stdout
    assert "dastcore" in result.stdout


def test_scan_aborts_without_authorization_flag() -> None:
    result = runner.invoke(app, ["scan", "http://localhost:5000"])
    assert result.exit_code == 1
    assert "ABORTADO" in result.stdout
    assert "--i-have-authorization" in result.stdout


def test_scan_proceeds_with_authorization_flag(vuln_app_url: str) -> None:
    # --fail-on none so the presence of findings doesn't turn the run into exit code 2
    result = runner.invoke(app, ["scan", vuln_app_url, "--i-have-authorization", "--rps", "50", "--fail-on", "none"])
    assert result.exit_code == 0
    assert "Autorización confirmada" in result.stdout
    assert "127.0.0.1" in result.stdout
    # the real pipeline ran end-to-end and actually found the planted vulnerabilities
    assert "hallazgo" in result.stdout.lower()
    assert "SQL Injection" in result.stdout


def test_scan_rejects_invalid_target() -> None:
    result = runner.invoke(app, ["scan", "not-a-url", "--i-have-authorization"])
    assert result.exit_code == 1
    assert "configuraci" in result.stdout.lower()


def test_scan_fail_on_high_exits_2_when_high_findings_present(vuln_app_url: str) -> None:
    result = runner.invoke(app, ["scan", vuln_app_url, "--i-have-authorization", "--rps", "50", "--fail-on", "high"])
    assert result.exit_code == 2  # SQLi (high) is present in the target
    assert ">= high" in result.stdout


def test_scan_writes_sarif_file(vuln_app_url: str, tmp_path) -> None:
    out = tmp_path / "report.sarif"
    result = runner.invoke(
        app,
        ["scan", vuln_app_url, "--i-have-authorization", "--rps", "50", "--format", "sarif", "-o", str(out), "--fail-on", "none"],
    )
    assert result.exit_code == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "dastcore"
    assert doc["runs"][0]["results"]


def test_scan_writes_html_file(vuln_app_url: str, tmp_path) -> None:
    out = tmp_path / "report.html"
    result = runner.invoke(
        app,
        ["scan", vuln_app_url, "--i-have-authorization", "--rps", "50", "--format", "html", "-o", str(out), "--fail-on", "none"],
    )
    assert result.exit_code == 0
    html = out.read_text(encoding="utf-8")
    assert "<title>" in html
    assert "dastcore" in html


def test_scan_rejects_invalid_format(vuln_app_url: str) -> None:
    result = runner.invoke(app, ["scan", vuln_app_url, "--i-have-authorization", "--format", "pdf"])
    assert result.exit_code == 1
    assert "Formato inválido" in result.stdout
