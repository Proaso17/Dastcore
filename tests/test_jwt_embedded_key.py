"""JWT jwk / x5c header injection: a server that verifies signatures but trusts the key carried in
the token's own header lets an attacker forge any token. Confirmed differentially; silent on a strict
server. Offline — a fake client verifies the forged token's RS256 signature against its embedded key."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.x509 import load_der_x509_certificate

from dastcore.core.models import HttpResponse
from dastcore.detectors.jwt import check_jwt_jwk_injection, check_jwt_x5c_injection


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


_SERVER_HS = b"the-real-server-secret"
_TOKEN = f"{_b64(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode())}.{_b64(json.dumps({'sub': 'alice'}).encode())}"
_TOKEN = f"{_TOKEN}.{_b64(hmac.new(_SERVER_HS, _TOKEN.encode(), hashlib.sha256).digest())}"


def _embedded_key_valid(token: str) -> bool:
    """True if the token's RS256 signature verifies against a key carried in its OWN header (the vuln)."""
    try:
        head_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(_b64d(head_b64))
        if "jwk" in header:
            jwk = header["jwk"]
            n = int.from_bytes(_b64d(jwk["n"]), "big")
            e = int.from_bytes(_b64d(jwk["e"]), "big")
            pub = RSAPublicNumbers(e, n).public_key()
        elif "x5c" in header:
            pub = load_der_x509_certificate(base64.b64decode(header["x5c"][0])).public_key()
        else:
            return False
        pub.verify(_b64d(sig_b64), f"{head_b64}.{payload_b64}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:  # noqa: BLE001 — any parse/verify failure = not accepted
        return False


class _Server:
    """`trust_embedded=True` = vulnerable (accepts a token verified by its embedded jwk/x5c)."""

    def __init__(self, *, trust_embedded: bool) -> None:
        self.trust_embedded = trust_embedded

    async def request(self, method: str, url: str, *, headers=None, **_kw) -> HttpResponse:
        bearer = (headers or {}).get("Authorization", "").removeprefix("Bearer ")
        if bearer == _TOKEN:  # the genuine, server-signed token
            return HttpResponse(status_code=200, text="welcome alice", url=url)
        if self.trust_embedded and _embedded_key_valid(bearer):
            return HttpResponse(status_code=200, text="welcome (forged)", url=url)
        return HttpResponse(status_code=401, text="unauthorized", url=url)


async def test_jwk_injection_flagged_on_vulnerable_server() -> None:
    findings = await check_jwt_jwk_injection(_Server(trust_embedded=True), "http://t.test/me", _TOKEN)  # type: ignore[arg-type]
    assert len(findings) == 1 and findings[0].rule_id == "jwt-jwk-injection"
    assert findings[0].severity == "critical"


async def test_x5c_injection_flagged_on_vulnerable_server() -> None:
    findings = await check_jwt_x5c_injection(_Server(trust_embedded=True), "http://t.test/me", _TOKEN)  # type: ignore[arg-type]
    assert len(findings) == 1 and findings[0].rule_id == "jwt-x5c-injection"


async def test_strict_server_is_not_flagged() -> None:
    strict = _Server(trust_embedded=False)  # verifies sigs, ignores jwk/x5c -> forgery rejected
    assert await check_jwt_jwk_injection(strict, "http://t.test/me", _TOKEN) == []  # type: ignore[arg-type]
    assert await check_jwt_x5c_injection(strict, "http://t.test/me", _TOKEN) == []  # type: ignore[arg-type]


def test_forge_produces_a_self_consistent_token() -> None:
    # sanity: the detector's forged jwk token really verifies against its own embedded key
    from dastcore.detectors.jwt import _jwk_header, _rsa_forge

    forged = _rsa_forge(_TOKEN, _jwk_header)
    assert forged is not None and _embedded_key_valid(forged)
