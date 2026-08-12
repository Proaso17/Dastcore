"""Multi-role browser-macro authentication for authz testing.

One recorded login macro is reused across roles: each identity in the roles file supplies its
own `macro_runtime` (`{{username}}`/`{{password}}`), so a single macro drives two independent
browser logins. This is what lets BOLA/BFLA run against JS/SPA apps where every role logs in
through the browser. Two checks: the roles-file config plumbing (no browser), and a real
Playwright replay that a shared macro yields a distinct session per role.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import Identity
from dastcore.core.session import SessionManager

# --- config plumbing (no browser) ------------------------------------------------------


def test_roles_file_supports_per_role_macro_identities() -> None:
    roles = [
        {
            "name": "alice",
            "role": "user",
            "auth": {
                "type": "macro",
                "macro_path": "login.json",
                "macro_runtime": {"username": "alice", "password": "pw-alice"},
            },
        },
        {
            "name": "bob",
            "role": "user",
            "auth": {
                "type": "macro",
                "macro_path": "login.json",  # the SAME recorded macro, reused
                "macro_runtime": {"username": "bob", "password": "pw-bob"},
            },
        },
    ]
    identities = [Identity.model_validate(r) for r in roles]
    assert [i.auth.type for i in identities] == ["macro", "macro"]
    # a single macro, parameterised per role via runtime
    assert identities[0].auth.macro_runtime["username"] == "alice"
    assert identities[1].auth.macro_runtime["username"] == "bob"
    # each identity's session can (re)login via its own macro
    assert all(SessionManager(i.auth).can_relogin for i in identities)


def test_macro_identity_requires_a_macro_path() -> None:
    with pytest.raises(ValueError, match="requires auth.macro_path"):
        Identity.model_validate({"name": "x", "auth": {"type": "macro"}})


# --- real per-role browser replay (Playwright) -----------------------------------------

_USERS = {"alice": ("pw-alice", "sess-alice"), "bob": ("pw-bob", "sess-bob")}


def _multi_login_app():
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
        creds = _USERS.get(body.get("u", ""))
        if creds and body.get("p") == creds[0]:
            resp = jsonify({"ok": True})
            resp.set_cookie("session", creds[1], samesite="Lax")
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
def multi_login_server() -> Iterator[str]:
    url, server = _serve(_multi_login_app())
    yield url
    server.shutdown()


async def test_shared_macro_yields_a_distinct_session_per_role(multi_login_server: str) -> None:
    from dastcore.auth.recorder import LoginMacro, MacroStep, replay_macro

    macro = LoginMacro(
        start_url=f"{multi_login_server}/login",
        steps=[
            MacroStep(action="fill", selector="#u", value="{{username}}"),
            MacroStep(action="fill", selector="#p", value="{{password}}"),
            MacroStep(action="click", selector="#go"),
            MacroStep(action="wait_for_url", value="**/dashboard"),
        ],
        success_cookie="session",
    )
    alice = await replay_macro(macro, runtime={"username": "alice", "password": "pw-alice"})
    bob = await replay_macro(macro, runtime={"username": "bob", "password": "pw-bob"})
    assert alice.get("session") == "sess-alice"
    assert bob.get("session") == "sess-bob"
    assert alice["session"] != bob["session"]  # independent per-role sessions from one macro
