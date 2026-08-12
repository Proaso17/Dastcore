"""Active detector: server-side prototype pollution (Node.js / Express).

An app that deep-merges request JSON into an object — ``Object.assign(target, req.body)`` or a
recursive merge — lets an attacker reach ``Object.prototype`` via a ``__proto__`` key, so a
property set on the prototype leaks into *every* object the process creates. That's a gadget for
privilege escalation, DoS, and sometimes RCE.

The oracle is the well-known ``json spaces`` differential, which is false-positive-free because
no ordinary app changes its JSON formatting based on an injected key: Express reads
``app.get('json spaces')`` off the (now-polluted) prototype when serialising, so after polluting
``__proto__.json spaces`` its JSON responses come back **indented** where they were compact.

- a benign write returns a compact JSON body (control);
- after ``{"__proto__": {"json spaces": 8}}`` the same benign write returns an *indented* body;
- the pollution is then reset with ``{"__proto__": {"json spaces": 0}}``.

Only when the formatting flips from compact to indented is it reported. Stateful (it mutates the
server's global prototype, then resets it), so it runs only behind ``--test-proto-pollution`` and
never in the ``quick`` profile.

CWE-1321 (Prototype Pollution) / OWASP A08:2021.
"""

from __future__ import annotations

import re
from copy import deepcopy
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_INDENTED = re.compile(r"[{\[,]\s*\n\s")  # a structural newline+indent → pretty-printed JSON


def _looks_json(response: HttpResponse) -> bool:
    if "json" in response.headers.get("content-type", "").lower():
        return True
    body = response.text.lstrip()
    return body.startswith("{") or body.startswith("[")


def _indented(response: HttpResponse) -> bool:
    return _looks_json(response) and bool(_INDENTED.search(response.text))


def _point(request: HttpRequest) -> InjectionPoint:
    return InjectionPoint(location="json", name="__proto__", base_value="", request_template=request)


def _polluted(request: HttpRequest, value: object) -> HttpRequest:
    body = deepcopy(request.json_body)
    assert isinstance(body, dict)
    body["__proto__"] = {"json spaces": value}
    return request.model_copy(update={"json_body": body})


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


async def check_proto_pollution(client: HttpClient, request: HttpRequest) -> list[Finding]:
    """Confirm server-side prototype pollution on one JSON write via the json-spaces oracle."""
    if request.method.upper() not in ("POST", "PUT", "PATCH") or not isinstance(request.json_body, dict):
        return []

    control = await _send(client, request)
    if control is None or not _looks_json(control) or _indented(control):
        return []  # need a compact JSON response to observe the flip against

    if await _send(client, _polluted(request, 8)) is None:  # pollute __proto__.json spaces
        return []
    observed = await _send(client, request)  # a benign write, now serialised via the polluted proto
    await _send(client, _polluted(request, 0))  # always reset the prototype, whatever we found

    if observed is None or not _indented(observed):
        return []  # formatting unchanged → not polluted (or not Express-style serialisation)

    path = urlsplit(request.url).path or "/"
    return [
        Finding(
            id=f"proto-pollution:{request.method}:{path}",
            rule_id="prototype-pollution",
            name="Server-side prototype pollution",
            severity="high",
            cwe="CWE-1321",
            owasp="A08:2021",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H",
            family="proto-pollution",
            injection_point=_point(request),
            evidence=[
                Evidence(
                    type="differential",
                    data=(
                        f"injecting __proto__.'json spaces' into {request.method} {path} made subsequent JSON "
                        "responses indented (Express serialises using the polluted prototype), while the control "
                        "response was compact — the app merges request input into Object.prototype"
                    )[:200],
                    confidence="high",
                )
            ],
            request=_polluted(request, 8),
            response=observed,
            remediation=(
                "No fusiones entrada del usuario en objetos sin filtrar claves peligrosas (`__proto__`, "
                "`constructor`, `prototype`). Usa `Object.create(null)`, `Map`, o un merge que las rechace; "
                "valida el body contra un esquema y congela `Object.prototype` donde sea viable."
            ),
        )
    ]


async def run_proto_pollution_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Run the prototype-pollution check over every JSON write, deduplicated by request shape."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for request in requests:
        if request.method.upper() not in ("POST", "PUT", "PATCH") or not isinstance(request.json_body, dict):
            continue
        signature = request.signature()
        if signature in seen:
            continue
        seen.add(signature)
        findings.extend(await check_proto_pollution(client, request))
    return findings
