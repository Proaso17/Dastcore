"""GraphQL-native active checks (Module 9).

Beyond "is introspection on", these target failure modes specific to GraphQL that legacy
DAST tools miss, each confirmed by the server's own behaviour so they don't false-positive:

* **Field-suggestion leakage** — "Did you mean …" errors reconstruct the schema field by
  field even when introspection is disabled.
* **Batching / aliasing abuse** — a single request runs many operations (a JSON array of
  queries, or dozens of aliased fields) with no complexity limit, which bypasses per-request
  rate limiting and auth throttling (credential stuffing, DoS amplification).
* **CSRF over GraphQL** — the endpoint executes a query sent via GET or as
  `application/x-www-form-urlencoded`, so a cross-site request can drive it.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit, urlunsplit

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# The suggested field, skipping the quotes/backslashes JSON escaping puts before it
# (the body reads `Did you mean \"user\"`, so a plain `"?` wouldn't reach the name).
_DID_YOU_MEAN = re.compile(r"did you mean\W*([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
_BOGUS_FIELD = "dastcoreNoSuchField_x"


def _point(request: HttpRequest, name: str) -> InjectionPoint:
    return InjectionPoint(location="body", name=name, base_value="", request_template=request)


def _finding(rule_id: str, name: str, severity: str, url: str, data: str, response: HttpResponse, remediation: str):
    request = HttpRequest(method="POST", url=url, json_body={"query": "…"})
    return Finding(
        id=f"{rule_id}:{urlsplit(url).path or '/'}",
        rule_id=rule_id,
        name=name,
        severity=severity,  # type: ignore[arg-type]
        cwe="CWE-200",
        owasp="API8:2023-Security Misconfiguration",
        family="graphql",
        injection_point=_point(request, "query"),
        evidence=[Evidence(type="response_match", data=data[:200], confidence="high")],
        request=request,
        response=response,
        remediation=remediation,
    )


async def _post_json(client: HttpClient, url: str, body: object) -> HttpResponse | None:
    try:
        return await client.post(url, json=body)
    except (OutOfScopeError, BudgetExceededError):
        return None


def _parse(text: str) -> object | None:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


async def check_graphql_field_suggestions(client: HttpClient, endpoint_url: str) -> list[Finding]:
    """Fire when an unknown field yields a "Did you mean <real field>" error — the schema
    leaks field names even with introspection off."""
    response = await _post_json(client, endpoint_url, {"query": "{ " + _BOGUS_FIELD + " }"})
    if response is None:
        return []
    match = _DID_YOU_MEAN.search(response.text)
    if match is None or match.group(1).lower() == _BOGUS_FIELD.lower():
        return []
    return [
        _finding(
            "graphql-field-suggestions",
            "GraphQL field-suggestion leakage (schema disclosure with introspection off)",
            "low",
            endpoint_url,
            f"an unknown field returned a suggestion leaking a real field: 'Did you mean {match.group(1)}'",
            response,
            "Desactiva las sugerencias de campo ('Did you mean…') en producción; filtran el esquema aunque "
            "la introspección esté apagada.",
        )
    ]


async def check_graphql_batching(client: HttpClient, endpoint_url: str, *, aliases: int = 100) -> list[Finding]:
    """Fire when the endpoint runs a big batch in one request without a complexity limit —
    either a JSON array of queries (array batching) or many aliased fields."""
    # 1) JSON array batching (disabled by default on hardened servers).
    array_body = [{"query": "{ __typename }"} for _ in range(5)]
    array_resp = await _post_json(client, endpoint_url, array_body)
    if array_resp is not None:
        parsed = _parse(array_resp.text)
        if isinstance(parsed, list) and len([r for r in parsed if isinstance(r, dict) and "data" in r]) >= 5:
            return [
                _finding(
                    "graphql-batching",
                    "GraphQL request batching enabled (rate-limit / auth-throttle bypass)",
                    "medium",
                    endpoint_url,
                    f"a JSON array of {len(array_body)} queries was executed in a single request "
                    "(array batching) — this bypasses per-request rate limiting",
                    array_resp,
                    _BATCHING_REMEDIATION,
                )
            ]
    # 2) Alias amplification: many aliases of a cheap field, executed with no limit.
    alias_query = "{ " + " ".join(f"a{i}: __typename" for i in range(aliases)) + " }"
    alias_resp = await _post_json(client, endpoint_url, {"query": alias_query})
    if alias_resp is not None:
        parsed = _parse(alias_resp.text)
        data = parsed.get("data") if isinstance(parsed, dict) else None
        if isinstance(data, dict) and sum(1 for i in range(aliases) if f"a{i}" in data) >= aliases:
            return [
                _finding(
                    "graphql-batching",
                    "GraphQL alias amplification (no query-complexity limit)",
                    "medium",
                    endpoint_url,
                    f"{aliases} aliased operations ran in a single request with no complexity limit — "
                    "this amplifies brute-force/DoS and evades per-request throttling",
                    alias_resp,
                    _BATCHING_REMEDIATION,
                )
            ]
    return []


_BATCHING_REMEDIATION = (
    "Limita el batching y la complejidad de las consultas GraphQL: desactiva el array-batching si "
    "no lo necesitas, y aplica límites de profundidad/complejidad/número de aliases y rate-limiting "
    "a nivel de operación (no solo de petición)."
)


def _with_query_param(url: str, query: str) -> str:
    parts = urlsplit(url)
    from urllib.parse import urlencode

    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode({"query": query}), ""))


async def check_graphql_csrf(client: HttpClient, endpoint_url: str) -> list[Finding]:
    """Fire when a query executes via GET or `application/x-www-form-urlencoded` — a simple
    cross-site request (or a `<form>`/`<img>`) can then drive the GraphQL API."""

    def _executed(response: HttpResponse | None) -> bool:
        parsed = _parse(response.text) if response is not None else None
        return isinstance(parsed, dict) and isinstance(parsed.get("data"), dict) and "__typename" in parsed["data"]

    try:
        get_resp = await client.request("GET", _with_query_param(endpoint_url, "{ __typename }"))
    except (OutOfScopeError, BudgetExceededError):
        get_resp = None
    via = "GET" if _executed(get_resp) else ""

    if not via:
        try:
            form_resp = await client.request(
                "POST",
                endpoint_url,
                data={"query": "{ __typename }"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except (OutOfScopeError, BudgetExceededError):
            form_resp = None
        if _executed(form_resp):
            via, get_resp = "application/x-www-form-urlencoded POST", form_resp

    if not via or get_resp is None:
        return []
    return [
        _finding(
            "graphql-csrf",
            "GraphQL CSRF (query executed via GET / form-encoded request)",
            "medium",
            endpoint_url,
            f"a GraphQL query executed via a {via} request — a cross-site request can drive the API",
            get_resp,
            "Acepta operaciones GraphQL solo por POST con Content-Type application/json (rechaza GET y "
            "form-urlencoded para mutaciones), y protege con tokens CSRF / SameSite las que cambian estado.",
        )
    ]


async def run_graphql_checks(client: HttpClient, endpoint_url: str) -> list[Finding]:
    """Run every GraphQL-native check against the endpoint."""
    findings: list[Finding] = []
    findings.extend(await check_graphql_field_suggestions(client, endpoint_url))
    findings.extend(await check_graphql_batching(client, endpoint_url))
    findings.extend(await check_graphql_csrf(client, endpoint_url))
    return findings
