"""CSS Injection. CWE-116 / OWASP A03:2021.

When user input is reflected inside a CSS context — a ``<style>`` block or a ``style=""`` attribute —
without CSS-escaping, an attacker can inject CSS: exfiltrate secrets/anti-CSRF tokens via attribute
selectors that fire ``url()`` requests, overlay or deface the UI, or ``@import`` an attacker stylesheet.

Two-step, false-positive-free oracle:

1. **Locate the context** — a plain unique marker must land *inside* a ``<style>`` block or a ``style``
   attribute value. Reflection in plain HTML text is XSS territory (owned by the XSS detector) and is
   skipped here, so the two never overlap.
2. **Prove the break-out** — a probe carrying raw CSS metacharacters must survive *un-encoded in that
   same context*: ``}<token>{`` inside a ``<style>`` block (opening a new rule/selector) or
   ``;<token>:red`` inside a ``style`` attribute (a new declaration). If the app CSS/HTML-escapes the
   metacharacters, nothing fires. The hit is reproduced before reporting.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.engine.injection_points import extract_injection_points
from dastcore.engine.rule_engine import build_mutated_request

_MAX_POINTS = 40

_STYLE_BLOCK = re.compile(r"<style\b[^>]*>(.*?)</style>", re.IGNORECASE | re.DOTALL)
_STYLE_ATTR = re.compile(r"""style\s*=\s*"([^"]*)"|style\s*=\s*'([^']*)'""", re.IGNORECASE)


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


def _in_style_block(text: str, needle: str) -> bool:
    return any(needle in m.group(1) for m in _STYLE_BLOCK.finditer(text))


def _in_style_attr(text: str, needle: str) -> bool:
    for m in _STYLE_ATTR.finditer(text):
        value = m.group(1) if m.group(1) is not None else m.group(2)
        if value and needle in value:
            return True
    return False


def _finding(point: InjectionPoint, request: HttpRequest, response: HttpResponse, context: str) -> Finding:
    path = urlsplit(request.url).path or "/"
    where = f"{point.location}:{point.name}"
    return Finding(
        id=f"css-injection:{request.method}:{path}:{where}",
        rule_id="css-injection",
        name="CSS Injection",
        severity="medium",
        cwe="CWE-116",
        owasp="A03:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        family="css_injection",
        injection_point=point,
        evidence=[
            Evidence(
                type="reflected",
                data=(
                    f"el parámetro '{point.name}' se refleja en un {context} y los metacaracteres CSS "
                    "sobreviven sin escapar: se inyectó una regla/declaración CSS nueva. Permite exfiltrar "
                    "datos con selectores de atributo + url() o manipular la interfaz"
                )[:200],
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "Escapa la entrada del usuario antes de reflejarla en un contexto CSS (o no la reflejes ahí). "
            "Usa una allowlist estricta de valores CSS y codifica `{`, `}`, `;`, `:` y `<`/`>`; evita "
            "construir hojas de estilo o atributos style con datos no confiables."
        ),
    )


async def _probe(client: HttpClient, point: InjectionPoint) -> Finding | None:
    """Locate the CSS context for `point`, then confirm a raw-metacharacter break-out; reproduce."""
    marker = "dccss" + secrets.token_hex(5)
    ctx = await _send(client, build_mutated_request(point, marker))
    if ctx is None:
        return None

    if _in_style_block(ctx.text, marker):
        token = "dcb" + secrets.token_hex(4)
        payload = "}" + token + "{}"  # close the current rule, open a new selector `token{}`
        needle = token + "{"
        context = "bloque <style>"
        in_context = _in_style_block
    elif _in_style_attr(ctx.text, marker):
        token = "dca" + secrets.token_hex(4)
        payload = ";" + token + ":red"  # inject a new declaration into the style attribute
        needle = token + ":red"
        context = 'atributo style=""'
        in_context = _in_style_attr
    else:
        return None  # reflected outside any CSS context (or not reflected) → not CSS injection

    probe_req = build_mutated_request(point, payload)
    hit = await _send(client, probe_req)
    if hit is None or not in_context(hit.text, needle):
        return None
    confirm = await _send(client, probe_req)
    if confirm is None or not in_context(confirm.text, needle):
        return None  # not reproducible → noise
    return _finding(point, probe_req, hit, context)


async def run_css_injection_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Probe every request's parameters for input reflected unsafely into a CSS context."""
    findings: list[Finding] = []
    seen: set[str] = set()
    probed = 0
    for request in requests:
        for point in extract_injection_points(request, include_headers=False):
            if point.location not in ("query", "body", "json"):
                continue
            path = urlsplit(request.url).path or "/"
            key = f"{path}:{point.location}:{point.name}"
            if key in seen:
                continue
            seen.add(key)
            probed += 1
            if probed > _MAX_POINTS:
                return findings
            found = await _probe(client, point)
            if found is not None:
                findings.append(found)
    return findings
