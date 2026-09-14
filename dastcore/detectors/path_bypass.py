"""Reverse-proxy / path-normalization access-control bypass. CWE-284 / OWASP A01:2021.

A front proxy or WAF often makes its allow/deny decision on the literal request path, while the
backend *normalizes* the path differently. So a path the proxy blocks (401/403) can be reached with a
normalization trick the backend collapses back to the protected path: ``/admin/./``, ``/admin/..;/``,
``/admin%2f``, ``//admin``, a trailing dot, etc. This complements the header-based bypass in
``access_bypass.py`` (``X-Forwarded-For`` / ``X-Original-URL``).

False-positive-free differential with a catch-all guard:

1. the path must be **denied directly** (401/403) — proving it is access-controlled;
2. a normalization variant must return **success** with content that differs from the denial;
3. the *same trick applied to a bogus sibling path* must **not** return that same content — otherwise
   the server just serves a generic page for these shapes (an SPA catch-all, a login redirect) and it
   is not a real bypass. The hit is reproduced before reporting.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.validation.baseline import similarity_ratio

_DENIED = {401, 403}
_MAX_FETCH = 120       # cap direct fetches used to find protected paths
_MAX_PROBES = 25       # cap protected paths we actually probe
_DIFF = 0.9            # bodies below this similarity are "different"
_SAME = 0.85           # control body at/above this similarity to the hit -> generic page, not a bypass

# Path-normalization tricks, as base -> variant path. The backend may collapse each back to `base`.
_TRICKS: list[tuple[str, Callable[[str], str]]] = [
    ("trailing-slash", lambda b: b + "/"),
    ("dot-slash", lambda b: b + "/./"),
    ("trailing-dot-segment", lambda b: b + "/."),
    ("double-slash", lambda b: b + "//"),
    ("dotdot-semicolon", lambda b: b + "/..;/"),
    ("suffix-dotdot-semicolon", lambda b: b + "..;/"),
    ("semicolon", lambda b: b + ";/"),
    ("trailing-dot", lambda b: b + "."),
    ("encoded-slash", lambda b: b + "%2f"),
    ("leading-double-slash", lambda b: "//" + b.lstrip("/")),
    ("leading-dot-slash", lambda b: "/." + b),
]


async def _get_url(client: HttpClient, url: str) -> HttpResponse | None:
    try:
        return await client.request("GET", url)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _build(scheme: str, netloc: str, path: str, query: str) -> str:
    return urlunsplit((scheme, netloc, path, query, ""))


def _is_success(resp: HttpResponse | None) -> bool:
    return resp is not None and 200 <= resp.status_code < 300


def _finding(
    scheme: str, netloc: str, path: str, trick: str, variant_url: str, response: HttpResponse
) -> Finding:
    request = HttpRequest(method="GET", url=variant_url)
    return Finding(
        id=f"path-normalization-bypass:{path}",
        rule_id="path-normalization-bypass",
        name="Bypass de control de acceso por normalización de ruta",
        severity="high",
        cwe="CWE-284",
        owasp="A01:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        family="access_bypass",
        injection_point=InjectionPoint(location="path", name=path, base_value="", request_template=request),
        evidence=[
            Evidence(
                type="differential",
                data=(
                    f"la ruta protegida {path} (denegada directamente con 401/403) se alcanza con la "
                    f"variante de normalización '{trick}' ({urlsplit(variant_url).path}) devolviendo 2xx "
                    "con contenido distinto a la denegación; el mismo truco sobre una ruta inexistente no "
                    "da ese contenido → el proxy/WAF filtra por la ruta literal y el backend la normaliza"
                )[:220],
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "Normaliza la ruta ANTES de aplicar el control de acceso, y hazlo igual en el proxy y en el "
            "backend (resuelve `.`/`..`, colapsa `//`, decodifica `%2f`, ignora parámetros de ruta `;`). "
            "Aplica autorización en el backend, no solo en el proxy de borde."
        ),
    )


async def _probe_path(client: HttpClient, scheme: str, netloc: str, path: str, query: str, deny: HttpResponse) -> Finding | None:
    base = path.rstrip("/")
    if not base:
        return None
    bogus_base = base + "dc" + secrets.token_hex(3)
    for trick, fn in _TRICKS:
        variant_path = fn(base)
        if variant_path == path:
            continue
        variant_url = _build(scheme, netloc, variant_path, query)
        hit = await _get_url(client, variant_url)
        if not _is_success(hit) or similarity_ratio(hit.text, deny.text) >= _DIFF:  # type: ignore[union-attr]
            continue
        # catch-all guard: the same trick on a non-existent sibling must NOT yield the same page
        control = await _get_url(client, _build(scheme, netloc, fn(bogus_base), query))
        if _is_success(control) and similarity_ratio(control.text, hit.text) >= _SAME:  # type: ignore[union-attr]
            continue
        # reproduce
        repro = await _get_url(client, variant_url)
        if not _is_success(repro) or similarity_ratio(repro.text, deny.text) >= _DIFF:  # type: ignore[union-attr]
            continue
        return _finding(scheme, netloc, path, trick, variant_url, hit)  # type: ignore[arg-type]
    return None


async def run_path_bypass_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Find protected paths (denied directly) and test path-normalization variants that bypass the proxy."""
    findings: list[Finding] = []
    seen: set[str] = set()
    fetched = 0
    probed = 0
    for request in requests:
        if request.method.upper() != "GET":
            continue
        parts = urlsplit(request.url)
        path = parts.path or "/"
        if path == "/" or path in seen:
            continue
        seen.add(path)
        if fetched >= _MAX_FETCH or probed >= _MAX_PROBES:
            break
        fetched += 1
        deny = await _get_url(client, request.url)
        if deny is None or deny.status_code not in _DENIED:
            continue
        probed += 1
        found = await _probe_path(client, parts.scheme, parts.netloc, path, parts.query, deny)
        if found is not None:
            findings.append(found)
    return findings
