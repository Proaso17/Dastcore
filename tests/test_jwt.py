"""JWT alg:none detector — token forging (pure) and the end-to-end oracle against a
vulnerable endpoint (accepts unsigned) vs a strict one (rejects), with the bad-signature
control ensuring we don't fire on an endpoint that simply isn't checking auth."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.detectors.jwt import (
    check_jwt_none_acceptance,
    check_jwt_weak_secret,
    forge_alg_none,
    forge_bad_signature,
    looks_like_jwt,
)

_SECRET = b"benchmark-jwt-secret"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _mint(claims: dict, alg: str = "HS256", secret: bytes = _SECRET) -> str:
    header = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = _b64(json.dumps(claims).encode())
    sig = _b64(hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


WEAK_TOKEN = _mint({"sub": "alice"}, secret=b"secret")  # signed with a dictionary-word secret


VALID = _mint({"sub": "alice", "role": "user"})


# --- pure token operations --------------------------------------------------------------


def test_looks_like_jwt() -> None:
    assert looks_like_jwt(VALID) is True
    assert looks_like_jwt("not-a-jwt") is False
    assert looks_like_jwt("a.b") is False  # only two segments
    assert looks_like_jwt("aaa.bbb.") is False  # empty signature


def test_forge_alg_none_keeps_payload_drops_signature() -> None:
    forged = forge_alg_none(VALID)
    head, payload, sig = forged.split(".")
    assert sig == ""  # no signature
    assert payload == VALID.split(".")[1]  # same claims
    assert json.loads(base64.urlsafe_b64decode(head + "=="))["alg"] == "none"


def test_forge_bad_signature_changes_only_the_signature() -> None:
    bad = forge_bad_signature(VALID)
    assert bad.split(".")[:2] == VALID.split(".")[:2]
    assert bad.split(".")[2] != VALID.split(".")[2]


# --- oracle against a live server -------------------------------------------------------


def _jwt_app(secret: bytes = _SECRET):
    from flask import Flask, Response, request

    app = Flask(__name__)

    def verify(token: str, accept_none: bool) -> dict | None:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        except Exception:
            return None
        if str(header.get("alg", "")).lower() == "none":
            return payload if accept_none else None
        expected = _b64(hmac.new(secret, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest())
        return payload if hmac.compare_digest(expected, parts[2]) else None

    def _handle(accept_none: bool) -> Response:
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        claims = verify(token, accept_none)
        if claims is None:
            return Response("unauthorized", status=401)
        return Response(f"ok {claims['sub']}", status=200)

    @app.get("/vuln")
    def vuln() -> Response:  # insecurely accepts alg:none
        return _handle(accept_none=True)

    @app.get("/strict")
    def strict() -> Response:  # rejects alg:none
        return _handle(accept_none=False)

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def jwt_server() -> Iterator[str]:
    url, server = _serve(_jwt_app())
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def weak_secret_server() -> Iterator[str]:
    url, server = _serve(_jwt_app(secret=b"secret"))  # HS256 secret is a dictionary word
    yield url
    server.shutdown()


async def test_detects_alg_none_on_vulnerable_endpoint(jwt_server: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        findings = await check_jwt_none_acceptance(client, f"{jwt_server}/vuln", VALID)
    assert len(findings) == 1
    assert findings[0].rule_id == "jwt-alg-none" and findings[0].cwe == "CWE-347"


async def test_no_finding_on_strict_endpoint(jwt_server: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        findings = await check_jwt_none_acceptance(client, f"{jwt_server}/strict", VALID)
    assert findings == []


async def test_no_finding_when_token_is_not_a_jwt(jwt_server: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        assert await check_jwt_none_acceptance(client, f"{jwt_server}/vuln", "opaque-token") == []


async def test_detects_weak_hmac_secret(weak_secret_server: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        findings = await check_jwt_weak_secret(client, f"{weak_secret_server}/strict", WEAK_TOKEN)
    assert len(findings) == 1
    assert findings[0].rule_id == "jwt-weak-secret"
    assert "secret" in findings[0].evidence[0].data


async def test_strong_secret_is_not_flagged(jwt_server: str) -> None:
    # server signs with a long non-dictionary secret; none of the candidates match
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        assert await check_jwt_weak_secret(client, f"{jwt_server}/strict", VALID) == []
