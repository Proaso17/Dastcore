"""Blind SSRF via the JWT `jku`/`x5u` header, confirmed out-of-band.

A verifier that fetches the key-set URL named inside the token makes a server-side request to
an attacker-controlled address. We forge a token whose `jku`/`x5u` points at a local OAST
collaborator; a vulnerable server fetches it (recorded callback) and is flagged, while a server
that ignores the header makes no callback and is silent — zero false positives by construction.
"""

from __future__ import annotations

import base64
import json
import socket
import threading
import urllib.request
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.detectors.jwt import check_jwt_key_url_ssrf
from dastcore.engine.oast import LocalOastServer


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _token() -> str:
    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"sub": "1", "role": "user"}).encode())
    return f"{header}.{payload}.c2ln"


def _header_url(bearer: str, field: str) -> str | None:
    """Pull the jku/x5u URL out of a bearer JWT's header (padding-tolerant base64url)."""
    try:
        raw = bearer.split(".")[0]
        decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        return json.loads(decoded).get(field)
    except (ValueError, json.JSONDecodeError, IndexError):
        return None


def _vuln_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.route("/api", methods=["GET"])
    def api() -> Response:
        bearer = request.headers.get("Authorization", "").removeprefix("Bearer ")
        # VULNERABLE: resolve the verification key from the URL in the token, unvalidated.
        for field in ("jku", "x5u"):
            url = _header_url(bearer, field)
            if url:
                try:
                    urllib.request.urlopen(url, timeout=2).read()  # the SSRF
                except OSError:
                    pass
        return Response("ok", status=200)

    return app


def _safe_app():
    from flask import Flask, Response

    app = Flask(__name__)

    @app.route("/api", methods=["GET"])
    def api() -> Response:
        return Response("ok", status=200)  # never touches jku/x5u

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


async def test_jku_and_x5u_fetch_is_flagged(vuln_url: str) -> None:
    oast = LocalOastServer()
    await oast.start()
    try:
        async with HttpClient(_scope()) as client:
            findings = await check_jwt_key_url_ssrf(client, f"{vuln_url}/api", _token(), oast)
    finally:
        await oast.stop()
    rules = {f.rule_id for f in findings}
    assert "jwt-jku-ssrf" in rules and "jwt-x5u-ssrf" in rules
    assert all(f.cwe == "CWE-918" and f.family == "ssrf" for f in findings)
    assert all(f.evidence[0].type == "oob" for f in findings)


async def test_server_ignoring_header_is_not_flagged(safe_url: str) -> None:
    oast = LocalOastServer()
    await oast.start()
    try:
        async with HttpClient(_scope()) as client:
            assert await check_jwt_key_url_ssrf(client, f"{safe_url}/api", _token(), oast) == []
    finally:
        await oast.stop()


async def test_no_oast_is_a_noop(vuln_url: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_jwt_key_url_ssrf(client, f"{vuln_url}/api", _token(), None) == []
