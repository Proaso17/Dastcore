"""Server-side code / Expression Language injection. CWE-94 / CWE-95 / CWE-1327, OWASP A03:2021.

Complements the ``{{…}}`` template-injection rule with the *other* expression syntaxes an attacker can
land in: EL / interpolation (``${…}``, ``#{…}`` — Spring/JSF, Ruby, Node template literals) and ERB/EJS
(``<%= … %>``). Each payload wraps a unique arithmetic between two markers and we look for the computed
*product* between them: the reflected literal always keeps the ``a*b`` expression, never the product, so
a page that only echoes the payload can never match. A hit is server-side code execution.
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

# (open, close, rule_id, name, cwe) — EL/interpolation report as EL injection, ERB/EJS as code injection.
_SYNTAXES = [
    ("${", "}", "expression-language-injection", "Expression Language injection (${...})", "CWE-1327"),
    ("#{", "}", "expression-language-injection", "Expression Language / interpolación (#{...})", "CWE-1327"),
    ("<%=", "%>", "code-injection", "Server-side code injection (plantilla <%= %>)", "CWE-94"),
]


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


def _finding(
    point, request: HttpRequest, response: HttpResponse, rule_id: str, name: str, cwe: str, product: str
) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"{rule_id}:{request.method}:{path}:{point.location}:{point.name}",
        rule_id=rule_id,
        name=name,
        severity="critical",
        cwe=cwe,
        owasp="A03:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        family="code-injection",
        injection_point=point,
        evidence=[
            Evidence(
                type="reflected",
                data=(
                    f"la expresión inyectada en '{point.name}' ({point.location}) se evaluó ({product}) en la "
                    "respuesta — el servidor ejecuta la entrada como código/expresión"
                )[:200],
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "Nunca evalúes entrada de usuario como código o expresión. Usa APIs de datos (no `eval`/plantillas "
            "dinámicas) y, en motores de EL/plantillas, un contexto restringido (sandbox) sin acceso a objetos "
            "peligrosos; valida/allowlist estrictamente cualquier expresión permitida."
        ),
    )


async def _try_raw_eval(client: HttpClient, point) -> Finding | None:
    """Detect a *direct* eval()/assert() sink that runs the whole value as code (PHP ``eval``, Python
    ``eval``, Ruby ``eval``, Node ``eval``) — no template delimiters, so the ``${}``/``<%= %>`` syntaxes
    above miss it. The payload is bare arithmetic ``a*b``; a hit is the *product* present while the literal
    ``a*b`` is absent (a plain reflection keeps the expression, only execution yields the product). A
    SECOND, independent product must also compute, so a number that merely happened to be on the page can
    never false-positive. bWAPP ``phpi.php`` is the canonical case."""
    a, b = 1000 + secrets.randbelow(9000), 1000 + secrets.randbelow(9000)
    raw, prod = f"{a}*{b}", str(a * b)
    resp = await _send(client, build_mutated_request(point, raw))
    if resp is None or prod not in resp.text or raw in resp.text:
        return None
    # Confirm with a different product so a coincidental number on the page can't trigger a finding.
    c, d = 1000 + secrets.randbelow(9000), 1000 + secrets.randbelow(9000)
    raw2, prod2 = f"{c}*{d}", str(c * d)
    if prod2 == prod:  # astronomically unlikely, but a distinct value is the whole point
        return None
    resp2 = await _send(client, build_mutated_request(point, raw2))
    if resp2 is None or prod2 not in resp2.text or raw2 in resp2.text:
        return None
    return _finding(
        point, build_mutated_request(point, raw2), resp2, "code-injection",
        "Server-side code injection (eval directo)", "CWE-94", prod2,
    )


async def run_code_injection_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Try EL / interpolation / ERB expression syntaxes and report the points that evaluate them."""
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
            left, right = f"cl{tok}", f"cr{tok}"
            hit = False
            for op, close, rule_id, name, cwe in _SYNTAXES:
                payload = f"{left}{op}{a}*{b}{close}{right}"
                resp = await _send(client, build_mutated_request(point, payload))
                if resp is not None and _has_exact(resp.text, left, right, product):
                    findings.append(
                        _finding(point, build_mutated_request(point, payload), resp, rule_id, name, cwe, product)
                    )
                    hit = True
                    break
            if hit:
                continue
            raw_finding = await _try_raw_eval(client, point)  # direct eval() sink (no delimiters)
            if raw_finding is not None:
                findings.append(raw_finding)
    return findings
