"""Login macro: (de)serialization, placeholder resolution, and a real headless replay of a
JavaScript-driven login (fetch → Set-Cookie) that a plain form-POST crawler couldn't do."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.auth.recorder import LoginMacro, MacroStep, _resolve, load_macro, replay_macro, save_macro


def test_placeholder_resolution() -> None:
    assert _resolve("{{pw}}", {"pw": "s3cr3t"}) == "s3cr3t"
    assert _resolve("otp-{{code}}", {"code": "123456"}) == "otp-123456"
    assert _resolve("{{missing}}", {}) == "{{missing}}"  # unknown left intact


def test_macro_roundtrip(tmp_path) -> None:
    macro = LoginMacro(
        start_url="https://app.test/login",
        steps=[MacroStep(action="fill", selector="#u", value="admin")],
        success_cookie="session",
    )
    path = tmp_path / "macro.json"
    save_macro(macro, path)
    loaded = load_macro(path)
    assert loaded.start_url == macro.start_url and loaded.steps[0].value == "admin"


# --- headless replay against a JS login ------------------------------------------------


def _login_app():
    from flask import Flask, Response, jsonify, request

    app = Flask(__name__)
    _PAGE = """
    <!doctype html><html><body>
      <input id="u"><input id="p" type="password">
      <button id="go" onclick="login()">Sign in</button>
      <script>
        async function login() {
          const r = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({u: document.getElementById('u').value, p: document.getElementById('p').value})});
          if (r.ok) { window.location = '/dashboard'; }
        }
      </script>
    </body></html>"""

    @app.get("/login")
    def login_page() -> Response:
        return Response(_PAGE, mimetype="text/html")

    @app.post("/api/login")
    def api_login():
        body = request.get_json(silent=True) or {}
        if body.get("u") == "admin" and body.get("p") == "s3cr3t":
            resp = jsonify({"ok": True})
            resp.set_cookie("session", "valid-token-abc", samesite="Lax")
            return resp
        return jsonify({"ok": False}), 401

    @app.get("/dashboard")
    def dashboard() -> Response:
        return Response("<h1>dashboard</h1>", mimetype="text/html")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def login_server() -> Iterator[str]:
    url, server = _serve(_login_app())
    yield url
    server.shutdown()


async def test_replay_authenticates_a_js_login(login_server: str) -> None:
    macro = LoginMacro(
        start_url=f"{login_server}/login",
        steps=[
            MacroStep(action="fill", selector="#u", value="admin"),
            MacroStep(action="fill", selector="#p", value="{{password}}"),
            MacroStep(action="click", selector="#go"),
            MacroStep(action="wait_for_url", value="**/dashboard"),
        ],
        success_cookie="session",
    )
    cookies = await replay_macro(macro, runtime={"password": "s3cr3t"})
    assert cookies.get("session") == "valid-token-abc"


async def test_session_manager_macro_login_seeds_the_jar(login_server: str, tmp_path) -> None:
    from dastcore.config import AuthConfig, ScopeConfig
    from dastcore.core.http_client import HttpClient
    from dastcore.core.session import SessionManager

    macro = LoginMacro(
        start_url=f"{login_server}/login",
        steps=[
            MacroStep(action="fill", selector="#u", value="admin"),
            MacroStep(action="fill", selector="#p", value="{{password}}"),
            MacroStep(action="click", selector="#go"),
            MacroStep(action="wait_for_url", value="**/dashboard"),
        ],
    )
    path = tmp_path / "macro.json"
    save_macro(macro, path)
    auth = AuthConfig(type="macro", macro_path=str(path), macro_runtime={"password": "s3cr3t"})
    session = SessionManager(auth)
    async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"]), session=session) as client:
        assert session.can_relogin is True
        ok = await session.ensure_logged_in(client, initial=True)
        assert ok is True
        assert session.cookies.get("session") == "valid-token-abc"
        assert client.cookie_pairs().get("session") == "valid-token-abc"  # pushed into the live jar


def test_cli_auth_replay_prints_session_cookies(login_server: str, tmp_path) -> None:
    from typer.testing import CliRunner

    from dastcore.cli import app

    macro = LoginMacro(
        start_url=f"{login_server}/login",
        steps=[
            MacroStep(action="fill", selector="#u", value="admin"),
            MacroStep(action="fill", selector="#p", value="{{password}}"),
            MacroStep(action="click", selector="#go"),
            MacroStep(action="wait_for_url", value="**/dashboard"),
        ],
    )
    path = tmp_path / "macro.json"
    save_macro(macro, path)
    result = CliRunner().invoke(app, ["auth", "replay", str(path), "--var", "password=s3cr3t"])
    assert result.exit_code == 0, result.output
    assert "valid-token-abc" in result.output


def test_cli_auth_subcommands_are_registered() -> None:
    from typer.testing import CliRunner

    from dastcore.cli import app

    result = CliRunner().invoke(app, ["auth", "--help"])
    assert result.exit_code == 0
    assert "record" in result.output and "replay" in result.output


async def test_replay_with_wrong_credentials_yields_no_session(login_server: str) -> None:
    macro = LoginMacro(
        start_url=f"{login_server}/login",
        steps=[
            MacroStep(action="fill", selector="#u", value="admin"),
            MacroStep(action="fill", selector="#p", value="wrong"),
            MacroStep(action="click", selector="#go"),
            # login fails → no navigation; just wait a moment for the fetch to resolve
            MacroStep(action="wait_for_selector", selector="#go"),
        ],
    )
    cookies = await replay_macro(macro)
    assert "session" not in cookies
