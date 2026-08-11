"""Advanced JWT attacks (Module 10): signature-not-verified, kid injection, and RS256→HS256
algorithm confusion — each confirmed differentially against a live vulnerable endpoint and
silent against a strict one, so a forgery being accepted is what fires (never a public route)."""

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
    check_jwt_algorithm_confusion,
    check_jwt_kid_injection,
    check_jwt_signature_not_verified,
)

_SECRET = b"a-long-high-entropy-secret-not-a-word"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode(seg: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def _mint_hs(claims: dict, secret: bytes = _SECRET) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps(claims).encode())
    sig = _b64(hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


HS_TOKEN = _mint_hs({"sub": "alice", "role": "user"})


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


def _hs_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    def _bearer() -> list[str]:
        return request.headers.get("Authorization", "").removeprefix("Bearer ").split(".")

    @app.get("/nosig")  # parses the JWT but never checks the signature
    def nosig() -> Response:
        parts = _bearer()
        try:
            _decode(parts[0]), _decode(parts[1])
        except Exception:
            return Response("unauthorized", status=401)
        return Response("ok", status=200) if len(parts) == 3 else Response("unauthorized", status=401)

    @app.get("/kid")  # loads the signing key from the kid path (traversal → empty key)
    def kid() -> Response:
        parts = _bearer()
        if len(parts) != 3:
            return Response("unauthorized", status=401)
        try:
            header = _decode(parts[0])
        except Exception:
            return Response("unauthorized", status=401)
        kid_val = str(header.get("kid", "")).replace("\\", "/").rstrip("/")
        key = b"" if kid_val.endswith("dev/null") else _SECRET  # /dev/null → empty file
        expected = _b64(hmac.new(key, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest())
        ok = header.get("alg") == "HS256" and hmac.compare_digest(expected, parts[2])
        return Response("ok", status=200) if ok else Response("unauthorized", status=401)

    @app.get("/strict")  # verifies HS256 with the real secret, nothing else
    def strict() -> Response:
        parts = _bearer()
        if len(parts) != 3:
            return Response("unauthorized", status=401)
        expected = _b64(hmac.new(_SECRET, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest())
        return Response("ok", status=200) if hmac.compare_digest(expected, parts[2]) else Response("no", status=401)

    return app


@pytest.fixture(scope="module")
def hs_server() -> Iterator[str]:
    url, server = _serve(_hs_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


async def test_signature_not_verified_is_detected(hs_server: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_jwt_signature_not_verified(client, f"{hs_server}/nosig", HS_TOKEN)
    assert len(findings) == 1 and findings[0].rule_id == "jwt-signature-not-verified"


async def test_signature_not_verified_silent_on_strict(hs_server: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_jwt_signature_not_verified(client, f"{hs_server}/strict", HS_TOKEN) == []


async def test_kid_injection_is_detected(hs_server: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_jwt_kid_injection(client, f"{hs_server}/kid", HS_TOKEN)
    assert len(findings) == 1 and findings[0].rule_id == "jwt-kid-injection"


async def test_kid_injection_silent_on_strict(hs_server: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_jwt_kid_injection(client, f"{hs_server}/strict", HS_TOKEN) == []


# --- RS256 → HS256 algorithm confusion (needs cryptography) ------------------------------

cryptography = pytest.importorskip("cryptography")


def _rsa_app_and_token() -> tuple[object, str]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from flask import Flask, Response, jsonify, request

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()
    pub_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    numbers = pub.public_numbers()

    def _int_b64(value: int) -> str:
        return _b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    # Mint an RS256 token signed with the private key.
    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "k1"}).encode())
    payload = _b64(json.dumps({"sub": "alice", "role": "user"}).encode())
    sig = _b64(key.sign(f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256()))
    rs_token = f"{header}.{payload}.{sig}"

    app = Flask(__name__)

    @app.get("/.well-known/jwks.json")
    def jwks() -> Response:
        return jsonify({"keys": [{"kty": "RSA", "kid": "k1", "n": _int_b64(numbers.n), "e": _int_b64(numbers.e)}]})

    @app.get("/api")  # VULNERABLE: verifies HS256 with the RSA public key as the secret
    def api() -> Response:
        parts = request.headers.get("Authorization", "").removeprefix("Bearer ").split(".")
        if len(parts) != 3:
            return Response("unauthorized", status=401)
        try:
            alg = _decode(parts[0]).get("alg")
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            if alg == "RS256":
                pub.verify(
                    base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4)),
                    signing_input,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
                return Response("ok", status=200)
            if alg == "HS256":  # the bug: reuses the public key as an HMAC secret
                expected = _b64(hmac.new(pub_pem, signing_input, hashlib.sha256).digest())
                return Response("ok", status=200) if hmac.compare_digest(expected, parts[2]) else Response("no", 401)
        except Exception:
            return Response("unauthorized", status=401)
        return Response("unauthorized", status=401)

    return app, rs_token


@pytest.fixture(scope="module")
def rsa_server() -> Iterator[tuple[str, str]]:
    app, rs_token = _rsa_app_and_token()
    url, server = _serve(app)
    yield url, rs_token
    server.shutdown()


async def test_algorithm_confusion_rs256_to_hs256_is_detected(rsa_server: tuple[str, str]) -> None:
    url, rs_token = rsa_server
    async with HttpClient(_scope()) as client:
        findings = await check_jwt_algorithm_confusion(client, f"{url}/api", rs_token)
    assert len(findings) == 1
    assert findings[0].rule_id == "jwt-alg-confusion" and findings[0].severity == "critical"
