"""Passive exposure checks that need one follow-up request.

`check_source_map` looks for a `//# sourceMappingURL=` reference in a served JavaScript
file and confirms the referenced `.map` is actually reachable and is a real source map —
which hands an attacker the original, un-minified frontend source (often with comments,
internal endpoints and the occasional secret). It only fires when the map is served and
parses as a source map, so it can't false-positive on a stray comment or an inline
(`data:`) map that isn't a separate reachable file.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# `//# sourceMappingURL=app.js.map` (also the legacy `//@` form).
_SOURCEMAP_REF = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def _looks_like_javascript(request: HttpRequest, response: HttpResponse) -> bool:
    ctype = next((v for k, v in response.headers.items() if k.lower() == "content-type"), "").lower()
    if "javascript" in ctype or "ecmascript" in ctype:
        return True
    path = urlsplit(request.url).path.lower()
    return path.endswith((".js", ".mjs"))


def _is_source_map(text: str) -> bool:
    """A Source Map v3 document: JSON with a version and either sources or mappings."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False
    return isinstance(data, dict) and "version" in data and ("sources" in data or "mappings" in data)


def _point(request: HttpRequest) -> InjectionPoint:
    return InjectionPoint(location="path", name="-", base_value="", request_template=request)


async def check_source_map(client: HttpClient, request: HttpRequest, response: HttpResponse) -> list[Finding]:
    """If a served JS file references a source map, fetch it and report a reachable one."""
    if not _looks_like_javascript(request, response):
        return []
    match = _SOURCEMAP_REF.search(response.text)
    if match is None:
        return []
    ref = match.group(1).strip()
    if ref.startswith("data:"):
        return []  # inline map, not a separately reachable file
    map_url = urljoin(request.url, ref)
    try:
        map_response = await client.get(map_url)
    except (OutOfScopeError, BudgetExceededError):
        return []
    if map_response.status_code != 200 or not _is_source_map(map_response.text):
        return []

    map_request = HttpRequest(method="GET", url=map_url)
    source_count = len(json.loads(map_response.text).get("sources", []))
    map_path = urlsplit(map_url).path or "/"
    return [
        Finding(
            id=f"source-map-exposure:{map_path}",
            rule_id="source-map-exposure",
            name="Exposed JavaScript source map",
            severity="medium",
            cwe="CWE-540",
            owasp="WSTG-CONF-04",
            family="exposure",
            injection_point=_point(map_request),
            evidence=[
                Evidence(
                    type="response_match",
                    data=f"reachable source map {map_path} reconstructs {source_count} original source file(s)",
                    confidence="high",
                )
            ],
            request=map_request,
            response=map_response,
            remediation=(
                "No despliegues los source maps (.map) a producción, o restríngelos a redes internas. "
                "Exponen el código fuente original del frontend (comentarios, endpoints, a veces secretos)."
            ),
        )
    ]
