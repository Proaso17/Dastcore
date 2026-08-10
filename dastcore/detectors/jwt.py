"""Active detectors for JWT signature weaknesses (CWE-347 / OWASP API2:2023).

When a scan carries a JWT bearer, these:
  * forge an `alg:none`/unsigned variant and check whether the server accepts it; and
  * try re-signing the token with a list of common HMAC secrets (HS256/384/512).

Both are false-positive-safe via a *bad-signature* control: the finding only fires when
the server rejects a tampered signature (proving it verifies at all) but accepts the
forged/weakly-signed token — otherwise the endpoint just isn't checking auth.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# alg values that bypass signature verification in a broken parser, most→least common.
_NONE_ALGS = ("none", "None", "NONE", "nOnE")

# HMAC algorithms whose secret we can brute against a small list.
_HS_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

# Common/default HMAC signing secrets seen in the wild and in framework tutorials.
_WEAK_SECRETS = (
    "secret",
    "password",
    "changeme",
    "admin",
    "jwt",
    "key",
    "test",
    "123456",
    "secretkey",
    "your-256-bit-secret",
    "private",
    "supersecret",
    "token",
    "mysecret",
)


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def looks_like_jwt(token: str) -> bool:
    """True if `token` is a three-segment JWT whose header decodes to JSON with an `alg`."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return False
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (ValueError, json.JSONDecodeError):
        return False
    return isinstance(header, dict) and "alg" in header


def forge_alg_none(token: str, alg: str = "none") -> str:
    """Return the token rewritten with an `alg:none` header, the same payload, no signature."""
    parts = token.split(".")
    header = _b64url_encode(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    return f"{header}.{parts[1]}."


def forge_bad_signature(token: str) -> str:
    """Return the token with its signature altered to a valid-shaped but wrong value."""
    parts = token.split(".")
    sig = parts[2]
    flipped = "B" if sig[-1] != "B" else "C"
    return f"{parts[0]}.{parts[1]}.{sig[:-1]}{flipped}"


def _point(request: HttpRequest) -> InjectionPoint:
    return InjectionPoint(location="header", name="Authorization", base_value="", request_template=request)


async def _send_bearer(client: HttpClient, target_url: str, bearer: str) -> HttpResponse | None:
    try:
        return await client.request("GET", target_url, headers={"Authorization": f"Bearer {bearer}"})
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _hmac_sign(token: str, secret: str, alg_fn) -> str:
    """Re-sign a token's header.payload with an HMAC secret, returning the new token."""
    header, payload, _ = token.split(".")
    signature = _b64url_encode(hmac.new(secret.encode(), f"{header}.{payload}".encode(), alg_fn).digest())
    return f"{header}.{payload}.{signature}"


async def check_jwt_none_acceptance(client: HttpClient, target_url: str, token: str) -> list[Finding]:
    """Report a server that accepts an `alg:none`/unsigned JWT while rejecting a bad signature."""
    if not looks_like_jwt(token):
        return []

    async def _get(bearer: str) -> HttpResponse | None:
        return await _send_bearer(client, target_url, bearer)

    original = await _get(token)
    if original is None or original.status_code >= 400:
        return []  # the real token isn't authorized here — nothing to compare against

    bad = await _get(forge_bad_signature(token))
    if bad is None or bad.status_code < 400:
        return []  # a wrong signature is accepted too -> the endpoint isn't verifying at all

    for alg in _NONE_ALGS:
        forged = await _get(forge_alg_none(token, alg))
        if forged is not None and forged.status_code < 400:
            request = HttpRequest(method="GET", url=target_url, headers={"Authorization": "Bearer <alg:none JWT>"})
            return [
                Finding(
                    id=f"jwt-alg-none:GET:{target_url}",
                    rule_id="jwt-alg-none",
                    name="JWT signature not verified (alg:none accepted)",
                    severity="high",
                    cwe="CWE-347",
                    owasp="API2:2023-Broken Authentication",
                    family="jwt",
                    injection_point=_point(request),
                    evidence=[
                        Evidence(
                            type="differential",
                            data=(
                                f"unsigned token (alg={alg!r}) accepted ({forged.status_code}) while a "
                                f"tampered signature was rejected ({bad.status_code})"
                            ),
                            confidence="high",
                        )
                    ],
                    request=request,
                    response=forged,
                    remediation=(
                        "Verify the JWT signature with a fixed, server-side algorithm allow-list (e.g. only "
                        "RS256 or HS256). Reject alg:none and any algorithm the server did not issue; never "
                        "trust the alg header from the token."
                    ),
                )
            ]
    return []


async def check_jwt_weak_secret(client: HttpClient, target_url: str, token: str) -> list[Finding]:
    """Report an HS256/384/512 JWT signed with a guessable secret.

    Re-signs the token with each candidate secret and checks acceptance, gated by the
    same bad-signature control so it can't fire on an endpoint that ignores auth."""
    if not looks_like_jwt(token):
        return []
    try:
        alg = json.loads(_b64url_decode(token.split(".")[0])).get("alg", "")
    except (ValueError, json.JSONDecodeError):
        return []
    alg_fn = _HS_ALGS.get(alg)
    if alg_fn is None:  # not an HMAC token — the secret can't be brute-forced this way
        return []

    original = await _send_bearer(client, target_url, token)
    if original is None or original.status_code >= 400:
        return []
    bad = await _send_bearer(client, target_url, forge_bad_signature(token))
    if bad is None or bad.status_code < 400:
        return []  # a wrong signature is accepted -> not verifying; different finding

    for secret in _WEAK_SECRETS:
        resp = await _send_bearer(client, target_url, _hmac_sign(token, secret, alg_fn))
        if resp is not None and resp.status_code < 400:
            request = HttpRequest(method="GET", url=target_url, headers={"Authorization": "Bearer <re-signed JWT>"})
            return [
                Finding(
                    id=f"jwt-weak-secret:GET:{target_url}",
                    rule_id="jwt-weak-secret",
                    name="JWT signed with a weak/guessable secret",
                    severity="high",
                    cwe="CWE-347",
                    owasp="API2:2023-Broken Authentication",
                    family="jwt",
                    injection_point=_point(request),
                    evidence=[
                        Evidence(
                            type="differential",
                            data=(
                                f"a token re-signed with the guessed {alg} secret {secret!r} was accepted "
                                f"({resp.status_code}) while a tampered signature was rejected ({bad.status_code})"
                            ),
                            confidence="high",
                        )
                    ],
                    request=request,
                    response=resp,
                    remediation=(
                        "Sign JWTs with a long, high-entropy secret (or an RS256 private key) stored server-side, "
                        "never a dictionary word or framework default. Rotate the secret and invalidate old tokens."
                    ),
                )
            ]
    return []
