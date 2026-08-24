"""Error-based (blind) Server-Side Template Injection — OWASP A03 / CWE-1336, WSTG-INPV-18.

The in-band SSTI check needs the arithmetic result (`{{7*7}}` → `49`) to be reflected. When it isn't —
the template renders into an email, a PDF, a log, a header — SSTI is *blind*. This catches it by error:
inject a polyglot that is invalid syntax in **every** major template engine, and confirm a
**template-engine-specific error** appears that a benign control value doesn't produce. The signature
is engine-specific (never a generic 500), and the error must be reproducible, so it's zero-FP.

Runs over every discovered request's injection points, so it covers the whole surface.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpResponse, InjectionPoint
from dastcore.engine.injection_points import extract_injection_points
from dastcore.engine.rule_engine import build_mutated_request

# PortSwigger's SSTI polyglot: invalid syntax across Jinja2/Twig/Freemarker/Velocity/Smarty/ERB/EL/…
_POLYGLOT = "${{<%[%'\"}}%\\"
_CONTROL = "dcsstictl"  # a benign value that no engine errors on

# Template-engine-specific error signatures (never a generic 500). Match → the input hit a template engine.
_ENGINE_ERROR_RE = re.compile(
    r"(jinja2\.exceptions|jinja2\.\w|TemplateSyntaxError|Twig\\?Error|Twig_Error\w*|"
    r"unexpected (?:token|char)|freemarker\.core|FreeMarker template error|org\.apache\.velocity|"
    r"ParseErrorException|Smarty_Internal|Syntax [Ee]rror in template|mako\.exceptions|"
    r"SyntaxException|Parse error on line|thymeleaf|TemplateProcessingException|"
    r"javax\.el\.ELException|PropertyNotFoundException|Razor|liquid::SyntaxError)",
    re.IGNORECASE,
)
_MAX_POINTS = 30


async def _send(client: HttpClient, request) -> HttpResponse | None:
    try:
        return await client.request(
            request.method, request.url,
            params=request.params or None, headers=request.headers or None,
            cookies=request.cookies or None, data=request.data, json=request.json_body,
            timeout=8.0, retries=0,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _engine_errors(text: str) -> set[str]:
    return {m.group(0).lower() for m in _ENGINE_ERROR_RE.finditer(text or "")}


async def run_ssti_error_checks(client: HttpClient, requests: list, *, max_points: int = _MAX_POINTS) -> list[Finding]:
    """Flag blind SSTI: a polyglot that triggers a reproducible template-engine error (A03 / CWE-1336)."""
    seen: set[str] = set()
    points: list[InjectionPoint] = []
    for req in requests:
        for point in extract_injection_points(req, include_headers=False):
            key = f"{req.method} {urlsplit(req.url).path} {point.location}:{point.name}"
            if key not in seen:
                seen.add(key)
                points.append(point)

    findings: list[Finding] = []
    for point in points[:max_points]:
        control = await _send(client, build_mutated_request(point, _CONTROL))
        if control is None:
            continue
        control_errs = _engine_errors(control.text)
        poly = await _send(client, build_mutated_request(point, _POLYGLOT))
        if poly is None:
            continue
        new_errs = _engine_errors(poly.text) - control_errs
        if not new_errs:
            continue
        # Reproduce: the engine error must persist on a second injection, not be a transient one-off.
        confirm = await _send(client, build_mutated_request(point, _POLYGLOT))
        if confirm is None or not (_engine_errors(confirm.text) - control_errs):
            continue
        path = urlsplit(point.request_template.url).path or "/"
        engine = sorted(new_errs)[0]
        findings.append(Finding(
            id=f"ssti-error-based:{point.request_template.method}:{path}:{point.location}:{point.name}",
            rule_id="ssti-error-based",
            name="Server-Side Template Injection (blind, error-based)",
            severity="high",
            cwe="CWE-1336",
            owasp="WSTG-INPV-18",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            family="ssti",
            injection_point=InjectionPoint(location=point.location, name=point.name,
                                           base_value=point.base_value, request_template=point.request_template),
            evidence=[Evidence(
                type="differential",
                data=(f"a template-injection polyglot in '{point.name}' triggered a reproducible "
                      f"template-engine error ({engine!r}) that a benign value did not — the input is "
                      "evaluated as a template (blind SSTI, typically escalates to RCE)")[:260],
                confidence="high",
            )],
            request=build_mutated_request(point, _POLYGLOT),
            response=poly,
            remediation=(
                "No metas entrada del usuario en la plantilla como código: pásala solo como **datos/"
                "contexto** a un motor con sandbox y auto-escape. Nunca construyas el template string con "
                "concatenación de entrada. Si necesitas plantillas de usuario, usa un motor lógica-menos "
                "(p. ej. Mustache) en un sandbox estricto."
            ),
        ))
    return findings
