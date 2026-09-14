"""DOM Clobbering. CWE-79 (HTML injection) / OWASP A03:2021.

DOM clobbering plants HTML elements with attacker-chosen ``id``/``name`` attributes; the browser then
exposes them as named globals (``window.<id>`` / ``document.<name>``), so code that reads such a global
(``var url = window.CONFIG.url``, ``document.currentScript``…) gets an attacker-controlled element
instead — leading to XSS, open redirect, or logic bypass. Crucially it works **even when scripts are
sanitized**: HTML sanitizers (e.g. DOMPurify with default options) routinely allow ``id``/``name`` and
elements like ``<a>``/``<form>``, so this is the notable gap XSS filtering leaves open.

False-positive-free static oracle. A single probe carries two markers:

* a benign named element ``<a id=<tok> name=<tok>></a>`` (the clobbering primitive), and
* a script vector ``<img src=x onerror=<tok2>>`` (the XSS control).

It fires only when, in a ``text/html`` response, the named element **survives as a literal tag**
(un-encoded, ``id``/``name`` intact) while the script vector does **not** survive un-encoded. That
combination is exactly "HTML injection where scripts are blocked but named elements are not" — a DOM
clobbering primitive that XSS detection misses. If the script vector also survives, it is XSS territory
and this detector defers (no double-reporting). Reproduced before reporting.
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


def _is_html(response: HttpResponse) -> bool:
    ctype = ""
    for name, value in (response.headers or {}).items():
        if name.lower() == "content-type":
            ctype = value.lower()
            break
    return "html" in ctype


def _named_element_survived(text: str, token: str) -> bool:
    """Our ``<a id=token name=token>`` reflected as a real tag (id/name intact, not entity-encoded)."""
    return re.search(r"<a\b[^>]*\b(?:id|name)\s*=\s*[\"']?" + re.escape(token), text, re.IGNORECASE) is not None


def _script_survived(text: str, token: str) -> bool:
    """The ``<img ... onerror=token2>`` XSS vector reflected un-encoded (would execute) -> XSS territory."""
    return re.search(r"<img\b[^>]*\bonerror\s*=\s*[\"']?" + re.escape(token), text, re.IGNORECASE) is not None


def _finding(point: InjectionPoint, request: HttpRequest, response: HttpResponse) -> Finding:
    path = urlsplit(request.url).path or "/"
    where = f"{point.location}:{point.name}"
    return Finding(
        id=f"dom-clobbering:{request.method}:{path}:{where}",
        rule_id="dom-clobbering",
        name="DOM Clobbering (inyección HTML con id/name)",
        severity="medium",
        cwe="CWE-79",
        owasp="A03:2021",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        family="dom_clobbering",
        injection_point=point,
        evidence=[
            Evidence(
                type="reflected",
                data=(
                    f"'{point.name}' permite inyectar un elemento con id/name propio que sobrevive al "
                    "saneado (los scripts sí se bloquean): el navegador lo expone como global "
                    "(window.<id>/document.<name>), clobbering variables que la página lee → XSS, "
                    "open redirect o bypass de lógica"
                )[:200],
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "Al sanear HTML de usuario, elimina o namespacea los atributos `id` y `name` (y usa "
            "`SANITIZE_NAMED_PROPS` en DOMPurify). No leas configuración/URLs desde globals nombrados "
            "(`window.X`/`document.X`) que un elemento inyectado pueda clobberar; usa referencias locales."
        ),
    )


async def _probe(client: HttpClient, point: InjectionPoint) -> Finding | None:
    ctok = "dcclob" + secrets.token_hex(4)
    xtok = "dcxss" + secrets.token_hex(4)
    payload = f"<a id={ctok} name={ctok}></a><img src=x onerror={xtok}>"
    probe_req = build_mutated_request(point, payload)
    hit = await _send(client, probe_req)
    if hit is None or not _is_html(hit):
        return None
    if _script_survived(hit.text, xtok):
        return None  # the script vector executes -> XSS owns this; don't double-report
    if not _named_element_survived(hit.text, ctok):
        return None
    confirm = await _send(client, probe_req)
    if confirm is None or _script_survived(confirm.text, xtok) or not _named_element_survived(confirm.text, ctok):
        return None  # not reproducible / became script-injectable -> noise
    return _finding(point, probe_req, hit)


async def run_dom_clobbering_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Probe reflected parameters for HTML injection that keeps attacker id/name (a DOM clobbering primitive)."""
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
