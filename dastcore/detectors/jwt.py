"""Active detector: JWT signature not verified (alg:none / unsigned acceptance).

When a scan carries a JWT bearer, this forges an `alg:none` variant of it (same claims,
empty signature) and checks whether the server accepts it. To avoid false positives it
first sends a *bad-signature* control: only if the server rejects a tampered signature
(proving it validates signatures at all) but accepts the unsigned token is it reported —
otherwise the endpoint simply isn't checking auth, which is a different finding.

CWE-347 (Improper Verification of Cryptographic Signature) / OWASP API2:2023.
"""

from __future__ import annotations

import base64
import json

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# alg values that bypass signature verification in a broken parser, most→least common.
_NONE_ALGS = ("none", "None", "NONE", "nOnE")


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


async def check_jwt_none_acceptance(client: HttpClient, target_url: str, token: str) -> list[Finding]:
    """Report a server that accepts an `alg:none`/unsigned JWT while rejecting a bad signature."""
    if not looks_like_jwt(token):
        return []

    async def _get(bearer: str) -> HttpResponse | None:
        try:
            return await client.request("GET", target_url, headers={"Authorization": f"Bearer {bearer}"})
        except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
            return None

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
