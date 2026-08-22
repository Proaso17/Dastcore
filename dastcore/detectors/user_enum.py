"""User / account enumeration — OWASP A07, WSTG-IDNT-04.

An auth surface (login, password reset, registration) that answers *differently* for an account that
exists versus one that doesn't lets an attacker harvest valid usernames/emails — the precursor to
credential stuffing and targeted phishing. We detect it black-box, without valid credentials:

1. Submit two **random** identities to learn the endpoint's stable "unknown account" response.
2. If those two disagree with each other, the endpoint is noisy → bail (zero false positives: the
   divergence must come from the identity, not per-request jitter).
3. Submit a set of **likely-existing** identities (admin, administrator, test, root, role@domain).
   If a likely one gets a distinct response (different status, or a clearly divergent body) and it
   **reproduces**, the endpoint discloses account existence.

Runs over every discovered auth-looking request, so it covers the whole surface, not just the entry URL.
"""

from __future__ import annotations

import re
import secrets
from copy import deepcopy
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.validation.baseline import similarity_ratio

_AUTH_PATH_RE = re.compile(
    r"(login|log-in|signin|sign-in|authenticate|auth\b|session|password|passwd|forgot|reset|recover|"
    r"register|signup|sign-up)",
    re.IGNORECASE,
)
_IDENTITY_FIELDS = ("email", "username", "user", "login", "userid", "user_id", "account", "phone")
_PASSWORD_FIELDS = ("password", "passwd", "pass", "pwd")
_LIKELY_USERS = ("admin", "administrator", "test", "root", "support")
_SIMILAR = 0.86  # bodies at least this similar are "the same outcome"
_MAX_ENDPOINTS = 8


def _differ(a: HttpResponse, b: HttpResponse) -> bool:
    if a.status_code != b.status_code:
        return True
    return similarity_ratio(a.text, b.text) < _SIMILAR


def _pick(keys: list[str], candidates: tuple[str, ...]) -> str | None:
    lowered = {k.lower(): k for k in keys}
    for cand in candidates:
        if cand in lowered:
            return lowered[cand]
    return None


def _candidates(requests: list[HttpRequest]) -> list[HttpRequest]:
    seen: set[str] = set()
    out: list[HttpRequest] = []
    for req in requests:
        path = urlsplit(req.url).path
        if not _AUTH_PATH_RE.search(path):
            continue
        has_body = bool(req.json_body) or bool(req.data) or req.method in ("POST", "PUT", "PATCH")
        if not has_body:
            continue
        key = f"{req.method} {path}"
        if key not in seen:
            seen.add(key)
            out.append(req)
    return out[:_MAX_ENDPOINTS]


async def _send(client: HttpClient, request: HttpRequest) -> HttpResponse | None:
    try:
        return await client.request(
            request.method, request.url,
            params=request.params or None, headers=request.headers or None,
            cookies=request.cookies or None, data=request.data, json=request.json_body,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _build(request: HttpRequest, id_field: str, pw_field: str, identity: str) -> HttpRequest:
    """A copy of ``request`` with the identity field set to ``identity`` and the password randomised."""
    password = f"dc-{secrets.token_hex(8)}"
    if request.json_body is not None or not request.data:
        body = deepcopy(request.json_body) if isinstance(request.json_body, dict) else {}
        body[id_field] = identity
        body[pw_field] = password
        return request.model_copy(update={"json_body": body, "data": None})
    data = dict(request.data or {})
    data[id_field] = identity
    data[pw_field] = password
    return request.model_copy(update={"data": data})


def _identities(request: HttpRequest, id_field: str) -> tuple[list[str], list[str]]:
    """(random 'unknown' identities, likely-existing identities), email-shaped if the field looks like email."""
    host = urlsplit(request.url).hostname or "example.com"
    domain = ".".join(host.split(".")[-2:]) if "." in host else host
    email_like = "email" in id_field.lower() or "@" in str((request.json_body or {}).get(id_field, ""))
    if email_like:
        randoms = [f"dc-none-{secrets.token_hex(6)}@{domain}", f"dc-x-{secrets.token_hex(6)}@{domain}"]
        likely = [f"{u}@{domain}" for u in ("admin", "info", "support", "test")]
    else:
        randoms = [f"dcnone{secrets.token_hex(6)}", f"dcx{secrets.token_hex(6)}"]
        likely = list(_LIKELY_USERS)
    return randoms, likely


async def _check_endpoint(client: HttpClient, request: HttpRequest) -> Finding | None:
    keys = list((request.json_body or {}).keys()) + list((request.data or {}).keys())
    id_field = _pick(keys, _IDENTITY_FIELDS) or "username"
    pw_field = _pick(keys, _PASSWORD_FIELDS) or "password"
    randoms, likely = _identities(request, id_field)

    base_a = await _send(client, _build(request, id_field, pw_field, randoms[0]))
    base_b = await _send(client, _build(request, id_field, pw_field, randoms[1]))
    if base_a is None or base_b is None or _differ(base_a, base_b):
        return None  # unreachable or noisy endpoint -> can't trust a diff (zero-FP)

    for user in likely:
        probe = await _send(client, _build(request, id_field, pw_field, user))
        if probe is None or not _differ(probe, base_a):
            continue
        # Reproduce: the divergence must hold against a *fresh* random baseline, not be a one-off.
        confirm = await _send(client, _build(request, id_field, pw_field, user))
        fresh_random = await _send(client, _build(request, id_field, pw_field, f"dcz{secrets.token_hex(6)}"))
        if confirm is None or fresh_random is None or not _differ(confirm, fresh_random):
            continue
        path = urlsplit(request.url).path or "/"
        return Finding(
            id=f"user-enumeration:{request.method}:{path}:{id_field}",
            rule_id="user-enumeration",
            name="User/account enumeration via differential auth response",
            severity="medium",
            cwe="CWE-204",
            owasp="WSTG-IDNT-04",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            family="user-enum",
            injection_point=InjectionPoint(location="json" if request.json_body is not None else "body",
                                           name=id_field, base_value="", request_template=request),
            evidence=[Evidence(
                type="differential",
                data=(
                    f"'{id_field}={user}' returned a distinct, reproducible response "
                    f"(HTTP {probe.status_code}, {len(probe.text)}B) versus random unknown accounts "
                    f"(HTTP {base_a.status_code}, {len(base_a.text)}B) — the endpoint reveals which "
                    "accounts exist"
                )[:240],
                confidence="high",
            )],
            request=_build(request, id_field, pw_field, user),
            response=probe,
            remediation=(
                "Devuelve una respuesta y un tiempo idénticos exista o no la cuenta: un mensaje genérico "
                "(«si la cuenta existe, te enviaremos un correo» / «credenciales inválidas») y el mismo "
                "código de estado. No reveles «usuario no encontrado» vs «contraseña incorrecta», ni en el "
                "login ni en el registro/recuperación. Aplica rate-limiting por IP/cuenta."
            ),
        )
    return None


async def run_user_enumeration_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Flag auth endpoints that disclose whether an account exists (A07 / WSTG-IDNT-04)."""
    findings: list[Finding] = []
    for request in _candidates(requests):
        try:
            finding = await _check_endpoint(client, request)
        except (OutOfScopeError, BudgetExceededError):
            break
        if finding is not None:
            findings.append(finding)
    return findings
