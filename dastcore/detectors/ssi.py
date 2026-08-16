"""Server-Side Includes (SSI) injection. CWE-97 / CWE-96, OWASP A03:2021.

If user input reaches a page the server parses for SSI directives, an ``<!--#exec cmd="…"-->`` runs a
shell command on the host. Confirmed the reflection-safe way used elsewhere: the directive echoes a
unique arithmetic *result* between two markers, and we look for that computed value — the reflected
literal still contains the ``$((a*b))`` expression, never the product, so a page that merely echoes the
payload can't match. A hit means SSI is enabled *and* executes commands (effectively RCE).
"""

from __future__ import annotations

import re
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


def _has_exact(text: str, left: str, right: str, expected: str) -> bool:
    return any(
        m.group(1).strip() == expected for m in re.finditer(re.escape(left) + r"(.+?)" + re.escape(right), text, re.S)
    )


def _finding(point, request: HttpRequest, response: HttpResponse, product: str) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"ssi-injection:{request.method}:{path}:{point.location}:{point.name}",
        rule_id="ssi-injection",
        name="Server-Side Includes (SSI) injection",
        severity="critical",
        cwe="CWE-97",
        owasp="A03:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        family="ssi",
        injection_point=point,
        evidence=[
            Evidence(
                type="reflected",
                data=(
                    f"la directiva SSI inyectada en '{point.name}' ({point.location}) se evaluó ({product}) en la "
                    "respuesta — el servidor procesa Server-Side Includes y ejecuta comandos (RCE)"
                )[:200],
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "Desactiva SSI (`Options -Includes`/`-IncludesNOEXEC`) en rutas que reflejan entrada de usuario, o "
            "escapa las secuencias de directiva (`<!--#`) antes de renderizar. Nunca pases entrada de usuario a "
            "páginas procesadas por SSI."
        ),
    )


async def run_ssi_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Inject an SSI ``exec`` that echoes a unique product and report the points where it evaluates."""
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

            a, b = 100 + secrets.randbelow(900), 100 + secrets.randbelow(900)
            product = str(a * b)
            tok = secrets.token_hex(4)
            left, right = f"sl{tok}", f"sr{tok}"
            payloads = [
                f'<!--#exec cmd="echo {left}$(({a}*{b})){right}"-->',
                f'<!--#exec cmd="echo {left}`expr {a} \\* {b}`{right}"-->',
            ]
            for payload in payloads:
                mutated = build_mutated_request(point, payload)
                resp = await _send(client, mutated)
                if resp is not None and _has_exact(resp.text, left, right, product):
                    findings.append(_finding(point, mutated, resp, product))
                    break
    return findings
