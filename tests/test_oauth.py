"""OAuth2/OIDC lax redirect_uri validation. An authorize endpoint that redirects to any
redirect_uri is flagged (it honours an attacker origin); one that validates against a registered
allowlist, and a non-OAuth request, are silent — the redirect-to-foreign-origin oracle is FP-free."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.oauth import check_oauth_redirect

_REGISTERED = "https://app.example/callback"


def _vuln_app():
    from flask import Flask, Response, redirect, request

    app = Flask(__name__)

    @app.get("/oauth/authorize")
    def authorize() -> Response:
        # VULNERABLE: redirect to whatever redirect_uri was supplied, no validation.
        uri = request.args.get("redirect_uri", _REGISTERED)
        return redirect(f"{uri}?code=abc123", code=302)

    return app


def _safe_app():
    from flask import Flask, Response, redirect, request

    app = Flask(__name__)

    @app.get("/oauth/authorize")
    def authorize() -> Response:
        uri = request.args.get("redirect_uri", "")
        if uri != _REGISTERED:  # HARDENED: exact allowlist match
            return Response("invalid redirect_uri", status=400)
        return redirect(f"{uri}?code=abc123", code=302)

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
    url, server = _serve(_vuln_app())
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def safe_url() -> Iterator[str]:
    url, server = _serve(_safe_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _authorize_req(base: str) -> HttpRequest:
    return HttpRequest(
        method="GET",
        url=f"{base}/oauth/authorize",
        params={"client_id": "app1", "response_type": "code", "redirect_uri": _REGISTERED},
    )


async def test_lax_redirect_uri_is_flagged(vuln_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_oauth_redirect(client, _authorize_req(vuln_url))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "oauth-redirect-uri-validation" and f.cwe == "CWE-601"
    assert "código" in f.evidence[0].data or "code" in f.evidence[0].data  # noted the leaked code


async def test_validated_redirect_uri_is_not_flagged(safe_url: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_oauth_redirect(client, _authorize_req(safe_url)) == []


async def test_non_oauth_request_is_skipped(vuln_url: str) -> None:
    async with HttpClient(_scope()) as client:
        # no client_id → not an authorization request → not probed
        req = HttpRequest(method="GET", url=f"{vuln_url}/oauth/authorize", params={"foo": "bar"})
        assert await check_oauth_redirect(client, req) == []
