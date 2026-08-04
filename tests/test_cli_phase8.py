"""Phase 8: scan profiles, resumption, and the rich summary."""
from __future__ import annotations

import json

from typer.testing import CliRunner

from dastcore.cli import _PROFILES, app

runner = CliRunner()


def test_profiles_exist() -> None:
    assert set(_PROFILES) == {"quick", "full", "api"}
    assert _PROFILES["quick"]["engine"] == "http"
    assert _PROFILES["full"]["engine"] == "both"


def test_invalid_profile_rejected(vuln_app_url: str) -> None:
    result = runner.invoke(app, ["scan", vuln_app_url, "--i-have-authorization", "--profile", "turbo"])
    assert result.exit_code == 1
    assert "--profile inválido" in result.stdout


def test_quick_profile_scans_and_shows_summary(vuln_app_url: str) -> None:
    result = runner.invoke(
        app, ["scan", vuln_app_url, "--i-have-authorization", "--profile", "quick", "--rps", "50", "--fail-on", "none"]
    )
    assert result.exit_code == 0
    assert "Perfil:" in result.stdout
    assert "Resumen del escaneo" in result.stdout


def test_explicit_engine_overrides_profile(vuln_app_url: str) -> None:
    """--profile full implies engine=both, but an explicit --engine http must win (no browser)."""
    result = runner.invoke(
        app,
        [
            "scan", vuln_app_url, "--i-have-authorization", "--profile", "full",
            "--engine", "http", "--rps", "50", "--fail-on", "none",
        ],
    )
    assert result.exit_code == 0
    assert "Motor de descubrimiento: http" in result.stdout


def test_resume_skips_completed_requests_and_keeps_prior_findings(vuln_app_url: str, tmp_path) -> None:
    state_path = tmp_path / "resume.json"
    # Seed a state file: pretend every discoverable request is already done, with one prior finding.
    prior_finding = {
        "id": "seed-finding",
        "rule_id": "seed",
        "name": "Seeded prior finding",
        "severity": "medium",
        "cwe": "CWE-0",
        "owasp": "TEST",
        "injection_point": {
            "location": "query",
            "name": "q",
            "base_value": "",
            "request_template": {"method": "GET", "url": f"{vuln_app_url}/search", "params": {"q": ""}},
        },
        "evidence": [],
        "request": {"method": "GET", "url": f"{vuln_app_url}/search", "params": {"q": ""}},
        "response": {"status_code": 200},
        "remediation": "n/a",
    }
    # Precompute the signatures the crawl will produce, so we can mark them completed.
    import asyncio

    from dastcore.config import ScopeConfig
    from dastcore.core.http_client import HttpClient
    from dastcore.discovery.crawler_http import HttpCrawler

    async def _sigs() -> list[str]:
        async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"])) as client:
            reqs = await HttpCrawler(client).crawl(f"{vuln_app_url}/")
        return [r.signature() for r in reqs]

    signatures = asyncio.run(_sigs())
    state_path.write_text(
        json.dumps({"completed": signatures, "findings": [prior_finding]}), encoding="utf-8"
    )

    result = runner.invoke(
        app,
        ["scan", f"{vuln_app_url}/", "--i-have-authorization", "--rps", "50", "--resume", str(state_path), "--fail-on", "none"],
    )
    assert result.exit_code == 0
    assert "Reanudando:" in result.stdout
    # The prior seeded finding is carried through into the report.
    assert "Seeded prior finding" in result.stdout
