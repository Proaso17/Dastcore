"""CSRF token enforcement. A form that carries a token the server never checks is flagged
(the action still completes with the token stripped and a foreign Origin); a form whose token
is actually verified, and a token-less request, are both silent — the runtime replay oracle
keeps it false-positive-free."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.csrf import check_csrf

_VALID_TOKEN = "tok-valid-123"


def _app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.post("/transfer-vuln")  # VULNERABLE: token field exists but is never verified
    def transfer_vuln() -> Response:
        return Response("transfer complete", status=200)

    @app.post("/transfer-safe")  # HARDENED: the token is actually checked
    def transfer_safe() -> Response:
        if request.form.get("csrf_token") != _VALID_TOKEN:
            return Response("CSRF token missing or invalid", status=403)
        return Response("transfer complete", status=200)

    @app.post("/comment")  # token-less endpoint — nothing to test enforcement of
    def comment() -> Response:
        return Response("ok", status=200)

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def csrf_server() -> Iterator[str]:
    url, server = _serve(_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _form(url: str) -> HttpRequest:
    return HttpRequest(method="POST", url=url, data={"amount": "100", "csrf_token": _VALID_TOKEN})


async def test_unenforced_token_is_flagged(csrf_server: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_csrf(client, _form(f"{csrf_server}/transfer-vuln"))
    assert len(findings) == 1
    assert findings[0].rule_id == "csrf-token-not-enforced" and findings[0].cwe == "CWE-352"


async def test_enforced_token_is_not_flagged(csrf_server: str) -> None:
    async with HttpClient(_scope()) as client:
        # stripping the token here yields a 403 → the replay diverges → no finding
        assert await check_csrf(client, _form(f"{csrf_server}/transfer-safe")) == []


async def test_tokenless_request_is_not_flagged(csrf_server: str) -> None:
    async with HttpClient(_scope()) as client:
        req = HttpRequest(method="POST", url=f"{csrf_server}/comment", data={"text": "hi"})
        assert await check_csrf(client, req) == []


async def test_get_requests_are_skipped(csrf_server: str) -> None:
    async with HttpClient(_scope()) as client:
        req = HttpRequest(method="GET", url=f"{csrf_server}/comment", params={"csrf_token": _VALID_TOKEN})
        assert await check_csrf(client, req) == []
