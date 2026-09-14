"""HTTP verb tampering / method-override access-control bypass. CWE-650 / OWASP A01:2021.

Many WAFs and edge ACLs make their decision on the literal HTTP method, while the backend accepts the
real method via an override header (``X-HTTP-Method-Override``) or treats the method case-insensitively.
So an action the edge blocks (401/403 for method M) can be reached by delivering M differently:

* **method-override header** — send ``GET`` (which the edge allows) carrying ``X-HTTP-Method-Override: M``;
  a framework that honours it runs M, bypassing the method-based rule;
* **method case variation** — send ``M`` with mangled case (``DeLeTe``); a case-sensitive edge rule
  misses it while the backend still runs M.

False-positive-free differentials:

* override: the overridden request must succeed **and differ from both** the denial *and* a plain base
  request without the header — so "GET was simply allowed" can't masquerade as an override bypass;
* case: the variant must succeed and differ from the denial, while a **bogus method** does not return
  the same page — so an app that answers any method with a generic 200 can't trip it.

Both are reproduced before reporting.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.validation.baseline import similarity_ratio

_DENIED = {401, 403}
_DIFF = 0.9  # bodies below this similarity are "different"
_MAX_PROBES = 40
_OVERRIDE_HEADERS = ("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override", "X-Original-Method")


async def _send(
    client: HttpClient, method: str, request: HttpRequest, extra_headers: dict[str, str] | None = None
) -> HttpResponse | None:
    headers = dict(request.headers or {})
    if extra_headers:
        headers.update(extra_headers)
    try:
        return await client.request(
            method,
            request.url,
            params=request.params or None,
            headers=headers or None,
            cookies=request.cookies or None,
            data=request.data,
            json=request.json_body,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _ok(resp: HttpResponse | None) -> bool:
    return resp is not None and 200 <= resp.status_code < 300


def _differs(a: HttpResponse, b: HttpResponse) -> bool:
    return similarity_ratio(a.text, b.text) < _DIFF


def _mangle_case(method: str) -> str:
    return "".join(c.lower() if i % 2 else c.upper() for i, c in enumerate(method))


def _finding(request: HttpRequest, technique: str, response: HttpResponse) -> Finding:
    path = urlsplit(request.url).path or "/"
    method = request.method.upper()
    return Finding(
        id=f"verb-tampering:{method}:{path}",
        rule_id="verb-tampering",
        name="Bypass de control de acceso por manipulación de método HTTP",
        severity="high",
        cwe="CWE-650",
        owasp="A01:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        family="access_bypass",
        injection_point=InjectionPoint(location="header", name="method", base_value=method, request_template=request),
        evidence=[
            Evidence(
                type="differential",
                data=(
                    f"'{method} {path}' se deniega directamente (401/403), pero se alcanza mediante "
                    f"{technique} devolviendo 2xx con contenido distinto a la denegación: el filtro de "
                    "borde decide por el método literal y el backend ejecuta el método real"
                )[:220],
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "Aplica el control de acceso sobre el método EFECTIVO, después de resolver overrides, y "
            "de forma insensible a mayúsculas. Deshabilita `X-HTTP-Method-Override` si no se usa, y "
            "autoriza en el backend, no solo en el proxy de borde."
        ),
    )


async def check_verb_tampering(client: HttpClient, request: HttpRequest) -> Finding | None:
    """Test one request denied by method for override-header and case-variation bypasses."""
    method = request.method.upper()
    deny = await _send(client, method, request)
    if deny is None or deny.status_code not in _DENIED:
        return None

    # Technique 1 — method-override header (base GET carries the real method).
    base = "GET" if method != "GET" else "POST"
    no_override = await _send(client, base, request)
    for header in _OVERRIDE_HEADERS:
        hit = await _send(client, base, request, {header: method})
        if not _ok(hit) or not _differs(hit, deny):  # type: ignore[arg-type]
            continue
        # a plain base request must not already produce the same success (else GET was just allowed)
        if _ok(no_override) and not _differs(hit, no_override):  # type: ignore[arg-type]
            continue
        repro = await _send(client, base, request, {header: method})
        if _ok(repro) and _differs(repro, deny):  # type: ignore[arg-type]
            return _finding(request, f"la cabecera {header}: {method}", hit)  # type: ignore[arg-type]

    # Technique 2 — method case variation (a case-sensitive edge rule misses it).
    variant = _mangle_case(method)
    if variant != method:
        hit = await _send(client, variant, request)
        if _ok(hit) and _differs(hit, deny):  # type: ignore[arg-type]
            bogus = await _send(client, "XDCPROBE", request)
            generic = _ok(bogus) and not _differs(bogus, hit)  # type: ignore[arg-type]
            if not generic:
                repro = await _send(client, variant, request)
                if _ok(repro) and _differs(repro, deny):  # type: ignore[arg-type]
                    return _finding(request, f"el método '{variant}' (case alterado)", hit)  # type: ignore[arg-type]
    return None


async def run_verb_tampering_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Test each denied request for HTTP method-based access-control bypasses, deduped by method+path."""
    findings: list[Finding] = []
    seen: set[str] = set()
    probed = 0
    for request in requests:
        path = urlsplit(request.url).path or "/"
        key = f"{request.method.upper()}:{path}"
        if key in seen:
            continue
        seen.add(key)
        if probed >= _MAX_PROBES:
            break
        probed += 1
        found = await check_verb_tampering(client, request)
        if found is not None:
            findings.append(found)
    return findings
