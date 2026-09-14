"""HTTP Parameter Pollution (HPP). CWE-235, OWASP WSTG-INPV-04.

A duplicated query parameter (``?p=a&p=b``) is parsed inconsistently across stacks: *first* wins
(Flask/Tomcat/Go), *last* wins (PHP/Django/Rails), or the values are *concatenated* into one
(ASP.NET/IIS, Node.js). Where the last value wins, an attacker who appends ``&p=evil`` overrides a
value an earlier layer set; where values are concatenated, a payload can be split across duplicates
to slip past a validator that only inspects one occurrence.

The behaviour is proven black-box with two unique sentinels:

* baseline ``p=S1`` must reflect S1 and ``p=S2`` must reflect S2 (so the parameter is observably
  reflected — otherwise we can't tell which occurrence the server used, and we don't guess);
* the polluted request ``p=S1&p=S2`` then reveals the precedence — **last-wins override** (only S2
  comes back, S1 gone) or **concatenation** (S1 and S2 come back joined by ``,``/``;``).

A *first-wins* stack (e.g. Flask) returns S1, which is normal and never reported — so this stays
false-positive-free and, notably, never fires on the Flask test targets. Read-only (GET only); one
finding per endpoint.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_MAX_ENDPOINTS = 40
_MAX_PARAMS_PER_REQ = 6


def _url_with_pairs(base_url: str, pairs: list[tuple[str, str]]) -> str:
    parts = urlsplit(base_url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


async def _get(client: HttpClient, url: str) -> HttpResponse | None:
    try:
        return await client.request("GET", url)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _classify(text: str, s1: str, s2: str) -> str | None:
    """How the server treated the duplicated parameter, or None if not a reportable HPP behaviour."""
    for sep in (",", ";", ", ", "; "):
        if f"{s1}{sep}{s2}" in text or f"{s2}{sep}{s1}" in text:
            return "concatenación (ambos valores procesados)"
    if s2 in text and s1 not in text:
        return "el último valor prevalece (override)"
    return None


def _finding(request: HttpRequest, name: str, behavior: str, response: HttpResponse) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"http-parameter-pollution:{request.method}:{path}:{name}",
        rule_id="http-parameter-pollution",
        name="HTTP Parameter Pollution",
        severity="low",
        cwe="CWE-235",
        owasp="WSTG-INPV-04",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        family="hpp",
        injection_point=InjectionPoint(location="query", name=name, base_value="", request_template=request),
        evidence=[
            Evidence(
                type="differential",
                data=(
                    f"el parámetro duplicado '{name}' se procesa de forma insegura: {behavior}. "
                    "Un atacante puede duplicar el parámetro para sobrescribir un valor fijado por otra "
                    "capa o repartir un payload entre ocurrencias y esquivar validaciones que solo miran una"
                )[:220],
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "Normaliza los parámetros duplicados en el servidor: rechaza o colapsa explícitamente las "
            "claves repetidas y valida el conjunto completo de ocurrencias, no solo la primera/última. "
            "Asegura que WAF/validador y backend interpreten los duplicados igual."
        ),
    )


async def check_hpp(client: HttpClient, request: HttpRequest) -> list[Finding]:
    """Probe one GET request's query parameters for insecure duplicate-parameter handling."""
    if request.method.upper() != "GET" or not request.params:
        return []
    base_pairs = list(request.params.items())
    tested = 0
    for name, _orig in base_pairs:
        if tested >= _MAX_PARAMS_PER_REQ:
            break
        tested += 1
        s1 = "dchppa" + secrets.token_hex(4)
        s2 = "dchppb" + secrets.token_hex(4)

        r1 = await _get(client, _url_with_pairs(request.url, [(k, s1 if k == name else v) for k, v in base_pairs]))
        r2 = await _get(client, _url_with_pairs(request.url, [(k, s2 if k == name else v) for k, v in base_pairs]))
        if r1 is None or r2 is None or s1 not in r1.text or s2 not in r2.text:
            continue  # not observably reflected -> can't confirm which occurrence won

        others = [(k, v) for k, v in base_pairs if k != name]
        polluted = others + [(name, s1), (name, s2)]
        rp = await _get(client, _url_with_pairs(request.url, polluted))
        if rp is None:
            continue
        behavior = _classify(rp.text, s1, s2)
        if behavior is None:
            continue

        rp2 = await _get(client, _url_with_pairs(request.url, polluted))
        if rp2 is None or _classify(rp2.text, s1, s2) != behavior:
            continue  # not reproducible -> noise
        return [_finding(request, name, behavior, rp)]  # one finding per endpoint is enough
    return []


async def run_hpp_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Run the HPP check over every GET request with query params, deduplicated by request shape."""
    findings: list[Finding] = []
    seen: set[str] = set()
    endpoints = 0
    for request in requests:
        signature = request.signature()
        if signature in seen:
            continue
        seen.add(signature)
        if endpoints >= _MAX_ENDPOINTS:
            break
        endpoints += 1
        findings.extend(await check_hpp(client, request))
    return findings
