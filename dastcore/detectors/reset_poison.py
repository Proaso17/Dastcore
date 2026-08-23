"""Password reset poisoning — OWASP A07, WSTG-ATHN-09 / CWE-640.

A password-reset endpoint that builds the reset link from a client-controlled host header (``Host`` or
an override like ``X-Forwarded-Host``) lets an attacker send the victim a link pointing at *their* domain
— when the victim clicks it, the reset token is exfiltrated → account takeover (and often a 2FA reset).

Black-box, zero-FP: we inject a **unique random canary host** via each candidate header and confirm the
app **reflects that exact host back** (in the response body or a header — i.e. it built a URL from the
untrusted header). A random host can't appear by coincidence, so a reflection is proof; a blind reset
(no reflection) is never reported. Runs over every discovered reset-looking endpoint.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_RESET_PATH_RE = re.compile(r"(forgot|reset|recover|lost.?password|password/(email|forgot|reset|new))", re.I)
_HOST_HEADERS = ("X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Original-Host", "Forwarded", "Host")
_IDENTITY_FIELDS = ("email", "username", "user", "login", "account")
_MAX_ENDPOINTS = 6


def _candidates(requests: list[HttpRequest]) -> list[HttpRequest]:
    seen: set[str] = set()
    out: list[HttpRequest] = []
    for req in requests:
        path = urlsplit(req.url).path
        if not _RESET_PATH_RE.search(path):
            continue
        if req.method not in ("POST", "PUT") and not req.json_body and not req.data:
            continue
        key = f"{req.method} {path}"
        if key not in seen:
            seen.add(key)
            out.append(req)
    return out[:_MAX_ENDPOINTS]


def _with_email(request: HttpRequest) -> HttpRequest:
    """Ensure the reset request carries an email so it hits the 'send a reset link' path."""
    keys = {k.lower() for k in list((request.json_body or {}).keys()) + list((request.data or {}).keys())}
    field = next((f for f in _IDENTITY_FIELDS if f in keys), "email")
    email = "dastcore-reset-probe@example.com"
    if request.json_body is not None or not request.data:
        body = dict(request.json_body) if isinstance(request.json_body, dict) else {}
        body.setdefault(field, email)
        return request.model_copy(update={"json_body": body, "data": None})
    data = dict(request.data or {})
    data.setdefault(field, email)
    return request.model_copy(update={"data": data})


async def _send(client: HttpClient, request: HttpRequest, header: str, canary: str) -> HttpResponse | None:
    value = f"host={canary}" if header == "Forwarded" else canary
    headers = {**request.headers, header: value}
    try:
        return await client.request(
            request.method, request.url,
            params=request.params or None, headers=headers,
            cookies=request.cookies or None, data=request.data, json=request.json_body,
            timeout=8.0, retries=0,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _reflected(canary: str, response: HttpResponse) -> bool:
    if canary in (response.text or ""):
        return True
    return any(canary in value for value in response.headers.values())


async def run_reset_poisoning_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Flag password-reset endpoints that build the reset link from an untrusted host header (A07)."""
    findings: list[Finding] = []
    for request in _candidates(requests):
        base = _with_email(request)
        for header in _HOST_HEADERS:
            canary = f"dcrp{secrets.token_hex(6)}.attacker.example"
            resp = await _send(client, base, header, canary)
            if resp is None or not _reflected(canary, resp):
                continue
            path = urlsplit(request.url).path or "/"
            findings.append(Finding(
                id=f"password-reset-poisoning:{request.method}:{path}:{header.lower()}",
                rule_id="password-reset-poisoning",
                name="Password reset poisoning (reset link built from an untrusted host header)",
                severity="high",
                cwe="CWE-640",
                owasp="WSTG-ATHN-09",
                cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                family="auth",
                injection_point=InjectionPoint(location="header", name=header, base_value="",
                                               request_template=base),
                evidence=[Evidence(
                    type="reflected",
                    data=(f"A random host injected via '{header}' was reflected back by the reset endpoint "
                          f"({canary}) — the reset link is built from the client-controlled host, so it can "
                          "be pointed at an attacker domain to steal the victim's reset token")[:280],
                    confidence="high",
                )],
                request=base.model_copy(update={"headers": {**base.headers, header: canary}}),
                response=resp,
                remediation=(
                    "Construye la URL de recuperación desde una base **fija** de configuración del servidor, "
                    "nunca desde el Host ni de cabeceras tipo X-Forwarded-Host. Valida el Host contra una "
                    "allowlist de dominios y confía en X-Forwarded-* solo detrás de un proxy de confianza."
                ),
            ))
            break  # one finding per endpoint (the first trusted header)
    return findings
