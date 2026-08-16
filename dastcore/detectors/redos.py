"""Regular-expression denial of service (ReDoS / catastrophic backtracking). CWE-1333 / CWE-400.

Timing is the classic false-positive trap, so this uses three independent guards that jitter and load
cannot fake together:

1. **Super-linear scaling** — the evil input is measured at growing sizes; catastrophic backtracking
   makes time *multiply* as the input grows by a few characters, where a healthy endpoint stays flat.
2. **Same-length control** — a benign string of the *identical length* must be fast, so the blow-up is
   attributable to the backtracking-triggering content, not to the payload size or bandwidth.
3. **Reproducibility** — the stall repeats.

Only when all three hold is it reported. Hard caps (max input size, per-probe time ceiling) keep it
from actually taking the target down. Intrusive, so it rides ``--test-dos`` and is off in ``quick``.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse
from dastcore.engine.injection_points import extract_injection_points
from dastcore.engine.rule_engine import build_mutated_request

_MAX_POINTS = 15
# Fine (+2) escalation so the first probe past the threshold — the knee — overshoots only modestly,
# which bounds how long any single request can take (we never chase the exponential all the way up).
_SIZES = [14, 16, 18, 20, 22, 24, 26, 28, 30, 32]
_SLOW_MS = 1000.0  # the knee: first probe at/above this stops the escalation
_GROWTH = 2.5  # the knee must be at least this many times slower than the previous size (super-linear)

# Inputs that trigger the common catastrophic patterns — a run of one char plus a non-matching breaker
# that forces the engine to backtrack over every split.
_EVIL: list[Callable[[int], str]] = [
    lambda n: "a" * n + "!",  # (a+)+ , (a*)* , ([a-z]+)* , (a|a)*
    lambda n: "a" * n + "@a.a!",  # email-validation regexes
    lambda n: "0" * n + "!",  # numeric validators
    lambda n: " " * n + "!",  # ^(\s+)+$ trimming
]


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


def _finding(point, request: HttpRequest, size: int, evil_ms: float, benign_ms: float) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"redos:{request.method}:{path}:{point.location}:{point.name}",
        rule_id="redos",
        name="ReDoS (catastrophic regex backtracking) — denegación de servicio",
        severity="high",
        cwe="CWE-1333",
        owasp="A05:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        family="dos",
        injection_point=point,
        evidence=[
            Evidence(
                type="time_based",
                data=(
                    f"'{point.name}' ({point.location}): una entrada patológica de {size} chars tardó {evil_ms:.0f}ms "
                    f"y crece de forma super-lineal, frente a {benign_ms:.0f}ms de una entrada benigna de igual "
                    "longitud — backtracking catastrófico en una expresión regular"
                )[:200],
                confidence="high",
            )
        ],
        request=request,
        response=HttpResponse(status_code=0, elapsed_ms=evil_ms),
        remediation=(
            "Evita cuantificadores anidados/solapados en las expresiones regulares (`(a+)+`, `(a|a)*`), acota la "
            "longitud de entrada antes de aplicarlas y usa un motor con protección de backtracking (RE2) o "
            "validación no basada en regex."
        ),
    )


async def _probe_point(client: HttpClient, point) -> Finding | None:
    for build in _EVIL:
        times: list[tuple[int, float]] = []
        for size in _SIZES:
            elapsed = await _timed(client, build_mutated_request(point, build(size)))
            if elapsed is None:
                break
            times.append((size, elapsed))
            if elapsed >= _SLOW_MS:  # reached the knee -> stop before the exponential runs away
                break
        if len(times) < 3:
            continue
        prev_ms, (last_n, last_ms) = times[-2][1], times[-1]
        if last_ms < _SLOW_MS or last_ms < _GROWTH * max(prev_ms, 1.0):
            continue  # not slow enough, or not super-linear -> healthy scaling
        benign = "a" * len(build(last_n))  # same length, no backtracking breaker
        benign_ms = await _timed(client, build_mutated_request(point, benign))
        if benign_ms is None or benign_ms >= _SLOW_MS or benign_ms > last_ms / 4:
            continue  # same-length input is also slow -> generic slowness, not ReDoS
        again = await _timed(client, build_mutated_request(point, build(last_n)))  # reproducible
        if again is not None and again >= _SLOW_MS:
            return _finding(point, point.request_template, last_n, max(last_ms, again), benign_ms)
    return None


async def run_redos_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Time pathological inputs at growing sizes on each input; report super-linear, reproducible stalls."""
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
            hit = await _probe_point(client, point)
            if hit is not None:
                findings.append(hit)
    return findings
