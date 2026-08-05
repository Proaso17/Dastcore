"""Polish: unified YAML/JSON config file (`--config`) with CLI-flag override."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from dastcore.cli import app
from dastcore.config import ScanFile

runner = CliRunner()


def test_scan_file_model_accepts_full_config(vuln_app_url: str) -> None:
    sf = ScanFile.model_validate(
        {
            "target": vuln_app_url,
            "allow_domains": ["127.0.0.1"],
            "engine": "http",
            "rps": 50,
            "concurrency": 4,
            "fail_on": "none",
        }
    )
    assert sf.target == vuln_app_url
    assert sf.concurrency == 4


def test_scan_file_rejects_unknown_keys() -> None:
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ScanFile.model_validate({"targett": "http://x"})  # typo'd key


def test_config_file_drives_scan(vuln_app_url: str, tmp_path) -> None:
    cfg = tmp_path / "scan.yaml"
    cfg.write_text(
        json.dumps({"target": vuln_app_url, "engine": "http", "rps": 60, "fail_on": "none"}),
        encoding="utf-8",
    )
    # No target argument on the CLI — it comes from the file.
    result = runner.invoke(app, ["scan", "--config", str(cfg), "--i-have-authorization"])
    assert result.exit_code == 0, result.stdout
    assert "SQL Injection" in result.stdout


def test_cli_flag_overrides_config_file(vuln_app_url: str, tmp_path) -> None:
    cfg = tmp_path / "scan.yaml"
    cfg.write_text(json.dumps({"target": vuln_app_url, "engine": "both", "fail_on": "none"}), encoding="utf-8")
    # File says engine=both (would need a browser); explicit --engine http must win.
    result = runner.invoke(
        app, ["scan", "--config", str(cfg), "--i-have-authorization", "--engine", "http", "--rps", "60"]
    )
    assert result.exit_code == 0
    assert "Motor de descubrimiento: http" in result.stdout


def test_missing_target_without_config_errors() -> None:
    result = runner.invoke(app, ["scan", "--i-have-authorization"])
    assert result.exit_code == 1
    assert "Falta el target" in result.stdout


def test_quiet_mode_emits_only_report(vuln_app_url: str) -> None:
    result = runner.invoke(
        app, ["scan", vuln_app_url, "--i-have-authorization", "--rps", "60", "--quiet", "--fail-on", "none"]
    )
    assert result.exit_code == 0
    assert "AVISO LEGAL" not in result.stdout  # banner suppressed
    assert "Resumen del escaneo" not in result.stdout  # summary suppressed
    # the JSON report is still emitted and parses
    data = json.loads(result.stdout)
    assert isinstance(data, list)
