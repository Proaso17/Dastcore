"""Session fixation: a login that keeps the pre-auth session id is flagged; one that rotates it,
or one we can't prove authenticates, is not."""

from __future__ import annotations

import secrets
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import FormLoginConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.detectors.session_fixation import check_session_fixation


def _app(*, rotates: bool, authenticates: bool = True):
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/login")
    def form() -> Response:
        resp = Response("<form>login</form>", mimetype="text/html")
        if not request.cookies.get("sessionid"):
            resp.set_cookie("sessionid", secrets.token_hex(8))  # assign a pre-auth session
        return resp

    @app.post("/login")
    def do_login() -> Response:
        ok = request.form.get("username") == "admin" and request.form.get("password") == "admin"
        if not authenticates:
            return Response("ok", mimetype="text/html")  # ignores creds -> can't confirm auth
        if not ok:
            return Response("invalid credentials", status=401, mimetype="text/html")
        resp = Response("welcome admin", mimetype="text/html")
        if rotates:
            resp.set_cookie("sessionid", secrets.token_hex(8))  # secure: new session id on login
        return resp  # vulnerable: no rotation, keeps the pre-auth id

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def vuln_url() -> Iterator[str]:
    url, server = _serve(_app(rotates=False))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def secure_url() -> Iterator[str]:
    url, server = _serve(_app(rotates=True))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def no_auth_url() -> Iterator[str]:
    url, server = _serve(_app(rotates=False, authenticates=False))
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _cfg(base: str) -> FormLoginConfig:
    return FormLoginConfig(
        login_url=f"{base}/login", credentials={"username": "admin", "password": "admin"}, as_json=False
    )


async def test_session_not_rotated_is_flagged(vuln_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_session_fixation(client, _cfg(vuln_url))
    assert len(findings) == 1
    assert findings[0].rule_id == "session-fixation" and findings[0].cwe == "CWE-384"
    assert "sessionid" in findings[0].evidence[0].data


async def test_rotated_session_is_not_flagged(secure_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_session_fixation(client, _cfg(secure_url))
    assert findings == []  # a fresh session id was issued on login


async def test_login_that_ignores_credentials_is_not_flagged(no_auth_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_session_fixation(client, _cfg(no_auth_url))
    assert findings == []  # correct and wrong creds behave the same -> auth unconfirmed, no claim
