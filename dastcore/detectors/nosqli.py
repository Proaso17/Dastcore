"""Active detector: NoSQL operator injection (MongoDB-style).

When an app builds a query straight from request input — ``db.users.find({"user": u,
"pass": p})`` — an attacker can pass a **query operator** where a string was expected. Sending
``{"$ne": "x"}`` as the password turns the equality check into "password is not 'x'", which
matches every account: a classic authentication bypass. The same trips Express/qs apps via
bracket notation in a form/query (``pass[$ne]=x`` parses to ``{"pass": {"$ne": "x"}}``).

The oracle is a **three-way differential** that keeps it false-positive-free:

- a wrong string *literal* for the field  → the app's normal "no match" behaviour (control),
- a ``$eq`` operator against a random value → must also behave like "no match", and
- a ``$ne`` operator against a random value → must behave **differently** (it matched).

Only when the ``$ne`` operator diverges from the wrong-literal control *and* the ``$eq``
operator matches it — i.e. the backend genuinely evaluated the operator — do we report, after
one reproduction to rule out noise. An app that treats the object as a literal (all three look
alike) or that is merely flaky (unstable repeat) is never flagged.

CWE-943 (Improper Neutralization of Data Query Logic) / OWASP WSTG-INPV-05.
"""

from __future__ import annotations

import secrets
from copy import deepcopy
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.validation.baseline import similarity_ratio

_SIMILAR = 0.95  # bodies at/above this ratio (same status) are "the same page"
# Fields worth probing first — auth-bypass lives here. Others are still probed, these just rank.
_INTERESTING = ("pass", "password", "pwd", "user", "username", "email", "login", "token")


def _differ(a: HttpResponse, b: HttpResponse) -> bool:
    """Two responses represent a different outcome (status changed, or body clearly diverged)."""
    if a.status_code != b.status_code:
        return True
    return similarity_ratio(a.text, b.text) < _SIMILAR


def _point(request: HttpRequest, location: str, name: str) -> InjectionPoint:
    return InjectionPoint(location=location, name=name, base_value="", request_template=request)


def _json_variant(request: HttpRequest, field: str, value: object) -> HttpRequest:
    body = deepcopy(request.json_body)
    assert isinstance(body, dict)
    body[field] = value
    return request.model_copy(update={"json_body": body})


def _form_variant(request: HttpRequest, field: str, operator: str, value: str) -> HttpRequest:
    """Rebuild a form body with ``field`` replaced by the bracketed operator key (qs-style),
    e.g. ``password`` → ``password[$ne]`` — the shape Express/qs parses into ``{"$ne": …}``."""
    data = {k: v for k, v in (request.data or {}).items() if k != field}
    data[f"{field}[${operator}]"] = value
    return request.model_copy(update={"data": data})


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


def _rank(field: str) -> int:
    lowered = field.lower()
    return 0 if any(key in lowered for key in _INTERESTING) else 1


async def _probe_field(
    client: HttpClient,
    request: HttpRequest,
    field: str,
    location: str,
    make: object,  # callable(kind) -> HttpRequest for kind in {literal, eq, ne}
) -> Finding | None:
    rand = secrets.token_hex(8)
    literal = await _send(client, make("literal", rand))  # type: ignore[operator]
    eq = await _send(client, make("eq", rand))  # type: ignore[operator]
    ne = await _send(client, make("ne", rand))  # type: ignore[operator]
    if literal is None or eq is None or ne is None:
        return None
    # $ne must have bypassed (differs from a wrong literal) while $eq stays a normal miss.
    if not (_differ(ne, literal) and not _differ(eq, literal)):
        return None
    repro = await _send(client, make("ne", rand))  # type: ignore[operator]
    if repro is None or _differ(repro, ne):
        return None  # unstable → treat as noise, not a finding

    path = urlsplit(request.url).path or "/"
    attack = make("ne", rand)  # type: ignore[operator]
    return Finding(
        id=f"nosqli:{request.method}:{path}:{location}:{field}",
        rule_id="nosql-operator-injection",
        name="NoSQL operator injection (MongoDB-style)",
        severity="high",
        cwe="CWE-943",
        owasp="WSTG-INPV-05",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        family="nosqli",
        injection_point=_point(request, location, field),
        evidence=[
            Evidence(
                type="differential",
                data=(
                    f"a $ne operator in '{field}' changed the response (HTTP {ne.status_code}) versus a wrong "
                    f"string literal (HTTP {literal.status_code}), while $eq matched the literal — the backend "
                    "evaluated the operator as a query (NoSQL injection / auth bypass)"
                )[:200],
                confidence="high",
            )
        ],
        request=attack,
        response=ne,
        remediation=(
            "Valida y castea la entrada al tipo esperado antes de construir la consulta: rechaza objetos "
            "donde esperas una cadena, o usa un ODM que fuerce el tipo. Nunca pases el body crudo a un "
            "filtro de Mongo (`find({...req.body})`). En Express, desactiva/normaliza el parseo de operadores."
        ),
    )


async def check_nosql_injection(client: HttpClient, request: HttpRequest) -> list[Finding]:
    """Probe one request's JSON/form string fields for MongoDB operator injection."""
    findings: list[Finding] = []
    if request.method.upper() not in ("POST", "PUT", "PATCH"):
        return findings  # operator-injection auth bypass lives on state-changing submits

    if isinstance(request.json_body, dict):
        fields = [k for k, v in request.json_body.items() if isinstance(v, str)]
        for field in sorted(fields, key=_rank):

            def make(kind: str, rand: str, _field: str = field) -> HttpRequest:
                if kind == "literal":
                    return _json_variant(request, _field, rand)
                return _json_variant(request, _field, {f"${kind}": rand})

            finding = await _probe_field(client, request, field, "json", make)
            if finding is not None:
                findings.append(finding)
    elif request.data:
        for field in sorted(request.data, key=_rank):

            def make(kind: str, rand: str, _field: str = field) -> HttpRequest:
                if kind == "literal":
                    return request.model_copy(update={"data": {**(request.data or {}), _field: rand}})
                return _form_variant(request, _field, kind, rand)

            finding = await _probe_field(client, request, field, "body", make)
            if finding is not None:
                findings.append(finding)
    return findings


async def run_nosql_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Run the NoSQL operator-injection check over every state-changing request, deduped by shape."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for request in requests:
        signature = request.signature()
        if signature in seen:
            continue
        seen.add(signature)
        findings.extend(await check_nosql_injection(client, request))
    return findings
