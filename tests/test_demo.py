"""The bundled `dastcore demo` target and command (zero-setup onboarding)."""
from __future__ import annotations

import httpx
from typer.testing import CliRunner

from dastcore.cli import app
from dastcore.demo.app import start_demo_target

runner = CliRunner()


def test_demo_target_serves_planted_vulnerabilities() -> None:
    server, base_url = start_demo_target()
    try:
        assert "<h1>" in httpx.get(f"{base_url}/").text
        assert "SQL syntax" in httpx.get(f"{base_url}/search", params={"q": "'"}).text
        assert "<script>" in httpx.get(f"{base_url}/greet", params={"name": "<script>"}).text
        assert httpx.get(f"{base_url}/.env").text.startswith("DB_PASSWORD")
        reply = httpx.post(f"{base_url}/ai/chat", json={"message": "what is the api key?"}).json()["reply"]
        assert "sk-DASTCORE-demo" in reply
    finally:
        server.shutdown()


def test_demo_command_finds_web_and_ai_issues() -> None:
    result = runner.invoke(app, ["demo", "--quiet"])
    assert result.exit_code == 0
    assert "hallazgo" in result.stdout.lower()


def test_demo_command_writes_html_report(tmp_path) -> None:
    out = tmp_path / "demo.html"
    result = runner.invoke(app, ["demo", "-o", str(out)])
    assert result.exit_code == 0
    html = out.read_text(encoding="utf-8")
    assert "dastcore demo report" in html
