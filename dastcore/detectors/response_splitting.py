"""HTTP response splitting / header injection. CWE-113 / CWE-93, OWASP A03:2021.

When a parameter is reflected into a *response header* (a redirect ``Location``, a ``Set-Cookie``,
a language echo) without stripping CR/LF, an attacker can inject their own header — or split off a
second response — enabling cache poisoning, session fixation, or reflected XSS via an injected body.

Confirmed in-band: inject ``\\r\\n<unique-header>: <marker>`` into each parameter and check whether the
server emits that exact header back. The header name and value are random per point, so seeing them in
the response proves our CR/LF broke out of the original header — never a coincidence. (The generic CRLF
rule is OAST-only; this catches the reflected, in-band case the collaborator can't.)
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse
from dastcore.engine.injection_points import extract_injection_points
from dastcore.engine.rule_engine import build_mutated_request

_MAX_POINTS = 40


async def _send(client: HttpClient, request: HttpRequest) -> HttpResponse | None:
    try:
        return await client.request(
            request.method,
            request.url,
            params=request.params or None,
            headers=request.headers or None,
            cookies=request.cookies or None,
            data=request.data,
            json=request.json_body,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _header_value(response: HttpResponse, name: str) -> str | None:
    target = name.lower()
    for key, value in response.headers.items():
        if key.lower() == target:
            return value
    return None


def _finding(point, request: HttpRequest, response: HttpResponse, header: str) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"http-response-splitting:{request.method}:{path}:{point.location}:{point.name}",
        rule_id="http-response-splitting",
        name="HTTP response splitting / header injection",
        severity="high",
        cwe="CWE-113",
        owasp="A03:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
        family="crlf",
        injection_point=point,
        evidence=[
            Evidence(
                type="reflected",
                data=(
                    f"CR/LF inyectado en '{point.name}' ({point.location}) produjo una cabecera de respuesta "
                    f"controlada por el atacante ('{header}') — el valor se refleja en una cabecera sin sanear los "
                    "saltos de línea, permitiendo inyectar cabeceras o partir la respuesta"
                )[:200],
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "No reflejes entrada de usuario en cabeceras de respuesta sin eliminar CR/LF. Usa las APIs de "
            "cabeceras/redirección del framework (que rechazan saltos de línea) y valida/allowlist los valores "
            "reflejados (p. ej. la URL de un redirect)."
        ),
    )


async def run_response_splitting_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Inject a CR/LF-prefixed header into each parameter and report the ones the server emits back."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for request in requests:
        for point in extract_injection_points(request, include_headers=False):
            sig = (urlsplit(request.url).path or "/", point.location, point.name)
            if sig in seen:
                continue
            seen.add(sig)
            if len(seen) > _MAX_POINTS:
                return findings

            token = secrets.token_hex(5)
            header = f"X-Dc-{token}"
            marker = f"dcsplit{token}"
            payload = f"{point.base_value}\r\n{header}: {marker}"
            mutated = build_mutated_request(point, payload)
            resp = await _send(client, mutated)
            if resp is None or _header_value(resp, header) != marker:
                continue
            confirm = await _send(client, mutated)  # reproducible
            if confirm is not None and _header_value(confirm, header) == marker:
                findings.append(_finding(point, mutated, resp, header))
    return findings
