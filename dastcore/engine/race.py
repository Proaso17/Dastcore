"""Race-condition / business-logic testing via a synchronized concurrent burst.

Many single-use actions (redeem a one-time coupon, withdraw once, accept an invite) guard
themselves with a check-then-act that is *not atomic*. Firing many identical requests in a
tight window makes them all pass the check before any commits — so the action runs more
times than allowed (double-spend, limit bypass).

The oracle is a differential that keeps this false-positive-free: after a concurrent burst,
if **more than one** request succeeded AND a following *sequential* request is now rejected,
the endpoint really does enforce a single-use limit — one the burst bypassed. If the extra
sequential request also succeeds, the endpoint simply allows repeats (not a race) and nothing
is reported.

Intrusive and stateful: only runs behind ``--test-race`` and never in the ``quick`` profile.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint


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
    except (OutOfScopeError, BudgetExceededError):
        return None


def _succeeded(response: HttpResponse | None) -> bool:
    return response is not None and response.status_code < 400


def _point(request: HttpRequest) -> InjectionPoint:
    return InjectionPoint(location="body", name="-", base_value="", request_template=request)


async def check_race_condition(client: HttpClient, request: HttpRequest, *, attempts: int = 20) -> list[Finding]:
    """Fire ``attempts`` identical requests concurrently and confirm a single-use race.

    Returns a finding only when more than one concurrent request succeeded and a subsequent
    sequential request is rejected — proving the endpoint enforces a limit the burst broke.
    """
    if request.method.upper() in ("GET", "HEAD", "OPTIONS", "TRACE"):
        return []  # only state-changing verbs can double-spend

    results = await asyncio.gather(*(_send(client, request) for _ in range(attempts)))
    successes = sum(1 for r in results if _succeeded(r))
    if successes < 2:
        return []  # at most one got through — the guard held (or the endpoint failed)

    control = await _send(client, request)
    if _succeeded(control):
        return []  # a later request still succeeds → the endpoint allows repeats, not a race

    winner = next((r for r in results if _succeeded(r)), None)
    assert winner is not None
    path = urlsplit(request.url).path or "/"
    return [
        Finding(
            id=f"race-condition:{request.method}:{path}",
            rule_id="race-condition",
            name="Race condition (non-atomic single-use action)",
            severity="high",
            cwe="CWE-362",
            owasp="WSTG-BUSL-08",
            cvss="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
            family="race",
            injection_point=_point(request),
            evidence=[
                Evidence(
                    type="differential",
                    data=(
                        f"{successes}/{attempts} concurrent {request.method} {path} requests succeeded, yet a "
                        f"following sequential request was rejected ({control.status_code if control else 'n/a'}) — "
                        "the single-use limit is not enforced atomically (TOCTOU)"
                    )[:200],
                    confidence="high",
                )
            ],
            request=request,
            response=winner,
            remediation=(
                "Haz atómica la comprobación-y-acción: usa un bloqueo a nivel de fila/registro "
                "(SELECT … FOR UPDATE), una restricción única en BD, o una operación condicional "
                "atómica (compare-and-set). No confíes en un 'if ya_usado' seguido de un update."
            ),
        )
    ]


async def run_race_checks(client: HttpClient, requests: list[HttpRequest], *, attempts: int = 20) -> list[Finding]:
    """Run the race check against every state-changing request, de-duplicated by shape."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for request in requests:
        if request.method.upper() in ("GET", "HEAD", "OPTIONS", "TRACE"):
            continue
        signature = request.signature()
        if signature in seen:
            continue
        seen.add(signature)
        findings.extend(await check_race_condition(client, request, attempts=attempts))
    return findings
