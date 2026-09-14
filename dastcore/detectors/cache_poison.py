"""Active detector: web cache poisoning via unkeyed input.

Some apps reflect a request header — ``X-Forwarded-Host``, ``X-Forwarded-Scheme``… — into the
response (e.g. building absolute URLs from it) while the cache in front keys entries only on the
URL. An attacker sends the header once; the poisoned response is cached and then served to every
other visitor of that URL.

The oracle is a two-step differential that is false-positive-free and minimally destructive: it
poisons a **unique cache-buster URL** (not the real page) with a random marker via the candidate
header, then sends a **clean** request to that same URL *without* the header. Because the clean
request never sent the marker, finding it in the clean (cached) response can only mean the cache
served the poisoned copy — confirmed poisoning. If the header isn't reflected, or the clean
request doesn't return the marker, nothing is reported.

The marker is looked for in the cached response **body and in dangerous response headers**
(``Location`` and other redirects, ``Set-Cookie``, ``Link``, CORS ``Access-Control-Allow-Origin``):
a poisoned ``Location`` redirect or ACAO header is higher impact than a body reflection.

Safe to run on every scan: it only ever writes cache entries under a random cache-buster URL that no
real user requests, so it cannot poison the real page. Runs in both the ``scan`` command and the
bug-bounty campaign (they share ``_run_scan``).

CWE-524 (Use of Cache Containing Sensitive Information) / OWASP WSTG-INPV-19.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# Request headers commonly reflected into a response but often left out of the cache key.
_UNKEYED_HEADERS = (
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Port",
    "X-Forwarded-Prefix",
    "Forwarded",
)
# Response headers where a reflected marker is dangerous (open redirect, cookie/CORS control).
_HEADER_SINKS = ("location", "content-location", "refresh", "link", "set-cookie", "access-control-allow-origin")
_MAX_URLS = 25  # bound the request budget


def _point(request: HttpRequest, header: str) -> InjectionPoint:
    return InjectionPoint(location="header", name=header, base_value="", request_template=request)


def _marker_sink(response: HttpResponse, marker: str) -> str | None:
    """Where the poisoned marker surfaced in a response: a dangerous response header, or the body."""
    for name, value in (response.headers or {}).items():
        if name.lower() in _HEADER_SINKS and marker in value:
            return f"la cabecera de respuesta '{name}'"
    if marker in response.text:
        return "el cuerpo de la respuesta"
    return None


async def _get(
    client: HttpClient, url: str, params: dict[str, str], headers: dict[str, str] | None
) -> HttpResponse | None:
    try:
        return await client.request("GET", url, params=params, headers=headers or None)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


async def check_cache_poisoning(client: HttpClient, request: HttpRequest) -> list[Finding]:
    """Try each unkeyed header on a unique cache-buster URL; confirm via a clean cache hit."""
    base_params = dict(request.params)
    for header in _UNKEYED_HEADERS:
        buster = secrets.token_hex(6)
        marker = f"dc{secrets.token_hex(6)}.poison.test"
        params = {**base_params, "dccb": buster}  # a unique key we own, not the real page

        poisoned = await _get(client, request.url, params, {header: marker})
        if poisoned is None or _marker_sink(poisoned, marker) is None:
            continue  # header not reflected (body or a response header) → this vector can't poison

        clean = await _get(client, request.url, params, None)  # same URL, no malicious header
        sink = _marker_sink(clean, marker) if clean is not None else None
        if sink is None:
            continue  # the clean request didn't get the marker → not served from a poisoned cache

        path = urlsplit(request.url).path or "/"
        attack = request.model_copy(update={"method": "GET", "params": params, "headers": {header: marker}})
        return [
            Finding(
                id=f"cache-poisoning:{path}:{header}",
                rule_id="web-cache-poisoning",
                name=f"Web cache poisoning via {header}",
                severity="high",
                cwe="CWE-524",
                owasp="WSTG-INPV-19",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
                family="cache-poisoning",
                injection_point=_point(request, header),
                evidence=[
                    Evidence(
                        type="differential",
                        data=(
                            f"un marcador enviado solo en la cabecera '{header}' de una petición apareció en "
                            f"{sink} de la respuesta cacheada y luego se devolvió a una petición *limpia* (sin esa "
                            f"cabecera) para {path} — la cabecera no está en la clave de caché, así que un atacante "
                            "puede envenenar la caché para otros usuarios"
                        )[:220],
                        confidence="high",
                    )
                ],
                request=attack,
                response=clean,
                remediation=(
                    "Incluye en la clave de caché toda entrada que influya en la respuesta (o no reflejes cabeceras "
                    "como `X-Forwarded-Host` en el contenido). Normaliza/ignora cabeceras no confiables en el origen "
                    "y configura el caché para no cachear respuestas que varían por cabeceras no clavadas."
                ),
            )
        ]
    return []


async def run_cache_poisoning_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Run the cache-poisoning check over each unique GET-able path, deduplicated."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for request in requests:
        if request.method.upper() not in ("GET", "HEAD"):
            continue
        path = urlsplit(request.url).path or "/"
        if path in seen:
            continue
        seen.add(path)
        if len(seen) > _MAX_URLS:
            break
        findings.extend(await check_cache_poisoning(client, request))
    return findings
