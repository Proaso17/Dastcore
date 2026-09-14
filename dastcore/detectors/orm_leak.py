"""ORM Leak / query-operator injection. CWE-943 / OWASP A03:2021.

Modern REST APIs often pass query parameters straight into an ORM/ODM filter. If the app honours
*operator syntax* in the parameter (``?name[$ne]=x``, ``?age[gt]=0``, ``?name[$regex]=.``), an attacker
turns an exact-match filter into a match-everything one and exfiltrates records they should never see
(every user, other tenants' rows). Stacks: MongoDB/Mongoose, Sequelize, Prisma, Ransack, etc.

False-positive-free differential — the hard part is telling a *real operator being interpreted* from an
app that simply *ignores unknown parameters* (which would also return the full list). A **bogus-operator
control** settles it:

* ``field=<random>``        (no-match literal) → the filter returns little/nothing (proves it filters);
* ``field[<bogus-op>]=<random>`` → a real ORM rejects the unknown operator (empty/error); an app that
  ignores bracket params returns the full list;
* ``field[$ne]=<random>`` / ``field[gt]=`` / ``field[$regex]=.`` (real operators) → returns the full set.

It fires only when a **real** operator returns substantially more than *both* the no-match literal and
the *bogus* operator (so a param-ignoring app, where real and bogus behave the same, never trips it),
and more than the legitimate query. Reproduced. Read-only (GET query parameters).
"""

from __future__ import annotations

import secrets
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_MAX_ENDPOINTS = 30
_MAX_PARAMS_PER_REQ = 5
_MIN_PLAIN_LEN = 20
_MIN_LEAK_LEN = 100
_RATIO = 2.0  # a real operator must return >= this multiple of the no-match / bogus-operator responses

# Real operators to try (label shown in evidence, operator key, value).
_REAL_OPS: tuple[tuple[str, str, str], ...] = (
    ("$ne", "$ne", ""),        # not-equal to a random value -> everything
    ("$gt", "$gt", ""),        # greater-than empty -> every non-empty value
    ("gt", "gt", "0"),         # Sequelize/Ransack numeric greater-than
    ("$regex", "$regex", "."),  # matches any character
)


async def _get(client: HttpClient, url: str) -> HttpResponse | None:
    try:
        return await client.request("GET", url)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _url_with(base_url: str, pairs: list[tuple[str, str]]) -> str:
    parts = urlsplit(base_url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def _pairs_with_op(base_pairs: list[tuple[str, str]], name: str, op_key: str, value: str) -> list[tuple[str, str]]:
    """Replace the `name` parameter with an operator form `name[op_key]=value`, other params intact."""
    out = [(k, v) for k, v in base_pairs if k != name]
    out.append((f"{name}[{op_key}]", value))
    return out


def _finding(request: HttpRequest, name: str, op_label: str, response: HttpResponse) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"orm-leak:{request.method}:{path}:{name}",
        rule_id="orm-leak",
        name="ORM Leak / inyección de operador en filtro",
        severity="high",
        cwe="CWE-943",
        owasp="A03:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        family="orm_leak",
        injection_point=InjectionPoint(location="query", name=name, base_value="", request_template=request),
        evidence=[
            Evidence(
                type="differential",
                data=(
                    f"el filtro '{name}' interpreta operadores de ORM: '{name}[{op_label}]' devolvió muchos "
                    "más registros que un valor sin coincidencia y que un operador inventado (control) — "
                    "convierte un filtro exacto en 'match-all' y expone registros de otras cuentas"
                )[:220],
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "No pases parámetros de query directamente al filtro del ORM. Valida tipos y usa una "
            "allowlist de campos/operadores; rechaza claves con sintaxis de operador (`campo[...]`) y "
            "castea los valores al tipo esperado antes de consultar."
        ),
    )


async def check_orm_leak(client: HttpClient, request: HttpRequest) -> list[Finding]:
    """Probe one GET request's query parameters for ORM operator injection that over-returns records."""
    if request.method.upper() != "GET" or not request.params:
        return []
    base_pairs = list(request.params.items())

    plain = await _get(client, request.url if not request.params else _url_with(request.url, base_pairs))
    if plain is None or plain.status_code >= 400:
        return []
    plain_len = len(plain.text)
    if plain_len < _MIN_PLAIN_LEN:
        return []

    tested = 0
    for name, _orig in base_pairs:
        if tested >= _MAX_PARAMS_PER_REQ:
            break
        tested += 1
        rand = "dcorm" + secrets.token_hex(5)

        nomatch = await _get(client, _url_with(request.url, [(k, rand if k == name else v) for k, v in base_pairs]))
        bogus = await _get(client, _url_with(request.url, _pairs_with_op(base_pairs, name, "dcz" + secrets.token_hex(3), rand)))
        if nomatch is None or bogus is None:
            continue
        nomatch_len, bogus_len = len(nomatch.text), len(bogus.text)
        # the parameter must actually filter (a no-match value returns less than the legit query)
        if not nomatch_len < plain_len:
            continue

        for op_label, op_key, op_val in _REAL_OPS:
            realop = await _get(client, _url_with(request.url, _pairs_with_op(base_pairs, name, op_key, op_val)))
            if realop is None or realop.status_code >= 400:
                continue
            realop_len = len(realop.text)
            if not (
                realop_len >= _MIN_LEAK_LEN
                and realop_len > plain_len
                and realop_len >= nomatch_len * _RATIO
                and realop_len >= bogus_len * _RATIO  # real operator != a bogus one -> not param-ignoring
            ):
                continue
            # reproduce: the real operator stays large and the bogus control stays small
            re_real = await _get(client, _url_with(request.url, _pairs_with_op(base_pairs, name, op_key, op_val)))
            re_bogus = await _get(client, _url_with(request.url, _pairs_with_op(base_pairs, name, "dcz" + secrets.token_hex(3), rand)))
            if re_real is None or re_bogus is None:
                continue
            if len(re_real.text) >= _MIN_LEAK_LEN and len(re_real.text) >= len(re_bogus.text) * _RATIO:
                return [_finding(request, name, op_label, realop)]
    return []


async def run_orm_leak_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Run the ORM-leak check over every GET request with query params, deduplicated by request shape."""
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
        findings.extend(await check_orm_leak(client, request))
    return findings
