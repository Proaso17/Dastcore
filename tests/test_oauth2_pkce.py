"""OAuth2 authorization-code + PKCE (RFC 7636) headless login.

A fake IdP validates the PKCE challenge/verifier: the scanner logs in, gets a code from the
authorize redirect, and exchanges it with the matching verifier for a bearer token — which then
unlocks a protected endpoint. If the PKCE machinery were wrong the token endpoint would reject
the exchange, so the happy path passing *is* the correctness check; wrong IdP credentials fail
the login cleanly."""

from __future__ import annotations

import base64
import hashlib
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import AuthConfig, OAuth2PkceConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.session import SessionManager, _pkce_pair

_ACCESS_TOKEN = "at-pkce-123"
_CODES: dict[str, str] = {}  # code → code_challenge, populated by /authorize


def _s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def _idp_app():
    import secrets as _secrets

    from flask import Flask, Response, redirect, request

    app = Flask(__name__)

    @app.post("/login")
    def login() -> Response:
        if request.form.get("username") == "alice" and request.form.get("password") == "pw":
            resp = Response("ok", status=200)
            resp.set_cookie("idp_session", "alice")
            return resp
        return Response("bad credentials", status=401)

    @app.get("/authorize")
    def authorize() -> Response:
        if request.cookies.get("idp_session") != "alice":
            return Response("login required", status=403)
        code = _secrets.token_hex(8)
        _CODES[code] = request.args.get("code_challenge", "")
        location = f"{request.args['redirect_uri']}?code={code}&state={request.args.get('state', '')}"
        return redirect(location, code=302)

    @app.post("/token")
    def token() -> Response:
        code = request.form.get("code", "")
        verifier = request.form.get("code_verifier", "")
        challenge = _CODES.get(code)
        if challenge is None or challenge != _s256(verifier):  # PKCE verification
            return Response('{"error":"invalid_grant"}', status=400, mimetype="application/json")
        return Response(f'{{"access_token":"{_ACCESS_TOKEN}","token_type":"Bearer"}}', mimetype="application/json")

    @app.get("/api")
    def api() -> Response:
        if request.headers.get("Authorization") == f"Bearer {_ACCESS_TOKEN}":
            return Response("secret data", status=200)
        return Response("unauthorized", status=401)

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def idp() -> Iterator[str]:
    url, server = _serve(_idp_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _auth(idp: str, *, password: str = "pw") -> AuthConfig:
    return AuthConfig(
        type="oauth2_pkce",
        oauth2_pkce=OAuth2PkceConfig(
            authorize_url=f"{idp}/authorize",
            token_url=f"{idp}/token",
            login_url=f"{idp}/login",
            login_credentials={"username": "alice", "password": password},
            client_id="spa-client",
            redirect_uri="https://app.example/callback",  # never actually requested
        ),
    )


def test_pkce_pair_is_rfc7636() -> None:
    verifier, challenge = _pkce_pair()
    assert 43 <= len(verifier) <= 128
    assert challenge == _s256(verifier)  # challenge is S256(verifier), base64url no padding


async def test_pkce_flow_obtains_bearer_and_unlocks_api(idp: str) -> None:
    session = SessionManager(_auth(idp))
    async with HttpClient(_scope(), session=session) as client:
        assert await session.ensure_logged_in(client, initial=True) is True
        assert session.headers["Authorization"] == f"Bearer {_ACCESS_TOKEN}"
        response = await client.get(f"{idp}/api")  # bearer is injected by the session
    assert response.status_code == 200 and "secret data" in response.text


async def test_wrong_idp_credentials_fail_login(idp: str) -> None:
    session = SessionManager(_auth(idp, password="wrong"))
    async with HttpClient(_scope(), session=session) as client:
        assert await session.ensure_logged_in(client, initial=True) is False
    assert "Authorization" not in session.headers
