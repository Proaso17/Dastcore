"""Multi-session authorization detector for GraphQL: object-level authorization (BOLA/IDOR).

REST BOLA compares who can reach an object-scoped URL; the GraphQL equivalent hides the object
id inside a field argument — ``node(id: "…")``, ``order(id: 1)``, ``user(id: 1)`` — often a
*nested* resolver that never re-checks ownership even when the top-level query is scoped.

This introspects the schema, finds every query field that takes an id-like argument and returns
an **object**, then fetches a small range of ids through two different authenticated identities
(and, if given, unauthenticated). The oracle is the same differential that keeps REST BOLA
false-positive-free: fire only when the **identical owned object** — a body carrying ownership
markers (email, owner_id, balance, …) — comes back to two different identities. A resolver that
scopes the object to its owner returns different data (or an error) to the second identity and
is never flagged; a shared/public object (no ownership markers) is not flagged either.

CWE-639 (Authorization Bypass Through User-Controlled Key) / OWASP API1:2023 (BOLA).
"""

from __future__ import annotations

import json
import re

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.detectors.authz import Identity, _is_success, _normalize_body, _ownership_marker

_ID_ARG = re.compile(r"(^|_)(id|uuid|guid)$", re.IGNORECASE)
_NUMERIC_TYPES = {"Int", "Float"}
_CANDIDATE_IDS = ("1", "2", "3", "4", "5")
_MAX_FETCHERS = 12  # bound the request budget on large schemas
_MAX_SUBFIELDS = 20

# A richer introspection than discovery.graphql: field/arg *types* so we can build valid
# selection sets and format id arguments by their scalar type.
_INTROSPECTION = (
    "query { __schema { queryType { name } "
    "types { kind name fields { name "
    "type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } "
    "args { name defaultValue type { kind name ofType { kind name ofType { kind name } } } } } } } }"
)


async def _introspect_full(client: HttpClient, endpoint_url: str) -> dict | None:
    try:
        response = await client.post(endpoint_url, json={"query": _INTROSPECTION})
    except (OutOfScopeError, BudgetExceededError):
        return None
    try:
        payload = json.loads(response.text)
    except (json.JSONDecodeError, ValueError):
        return None
    schema = (payload.get("data") or {}).get("__schema")
    return schema if isinstance(schema, dict) else None


def _unwrap(type_ref: dict | None) -> tuple[str | None, str | None]:
    """Follow NON_NULL/LIST wrappers to the underlying named type → (kind, name)."""
    cur = type_ref
    while cur:
        if cur.get("name"):
            return cur.get("kind"), cur.get("name")
        cur = cur.get("ofType")
    return None, None


def _is_required(arg: dict) -> bool:
    return (arg.get("type") or {}).get("kind") == "NON_NULL" and arg.get("defaultValue") in (None, "")


def _scalar_selection(type_map: dict[str, dict], type_name: str | None) -> str:
    """A selection set of the object's own scalar/enum fields (those needing no args)."""
    type_def = type_map.get(type_name or "")
    names: list[str] = []
    for field in (type_def or {}).get("fields") or []:
        if any(_is_required(a) for a in field.get("args") or []):
            continue
        kind, _ = _unwrap(field.get("type"))
        if kind in ("SCALAR", "ENUM"):
            names.append(field["name"])
        if len(names) >= _MAX_SUBFIELDS:
            break
    names.append("__typename")
    return " ".join(dict.fromkeys(names))  # dedupe, preserve order


def _id_fetchers(schema: dict) -> list[tuple[dict, str, str]]:
    """Query fields taking an id-like arg and returning an object → (field, id_arg, arg_kind)."""
    query_type = (schema.get("queryType") or {}).get("name")
    type_map = {t["name"]: t for t in schema.get("types", []) if t.get("name")}
    fetchers: list[tuple[dict, str, str]] = []
    for field in (type_map.get(query_type or "") or {}).get("fields") or []:
        ret_kind, _ = _unwrap(field.get("type"))
        if ret_kind != "OBJECT":
            continue  # need an object body to compare ownership on
        for arg in field.get("args") or []:
            arg_kind, arg_type = _unwrap(arg.get("type"))
            if _ID_ARG.search(arg["name"]) or arg_type == "ID":
                fetchers.append((field, arg["name"], arg_type or "String"))
                break
    return fetchers


def _document(field: dict, id_arg: str, arg_type: str, id_value: str, selection: str) -> str:
    literal = id_value if arg_type in _NUMERIC_TYPES else f'"{id_value}"'
    return f"query {{ {field['name']}({id_arg}: {literal}) {{ {selection} }} }}"


async def _fetch(client: HttpClient, endpoint_url: str, document: str) -> HttpResponse | None:
    try:
        return await client.post(endpoint_url, json={"query": document})
    except (OutOfScopeError, BudgetExceededError):
        return None


def _object_body(response: HttpResponse | None) -> str | None:
    """The normalized JSON data body of a *successful, error-free* GraphQL object response."""
    if response is None or not _is_success(response.status_code):
        return None
    try:
        payload = json.loads(response.text)
    except (json.JSONDecodeError, ValueError):
        return None
    if payload.get("errors"):
        return None  # a resolver error is not a leaked object
    data = payload.get("data")
    if not isinstance(data, dict) or not data:
        return None
    inner = next(iter(data.values()))
    if inner in (None, {}, []):
        return None  # null/empty → the object was not returned to this identity
    return _normalize_body(json.dumps(inner, sort_keys=True))


def _bola_finding(
    endpoint_url: str, document: str, response: HttpResponse, field: str, names: list[str], marker: str
) -> Finding:
    request = HttpRequest(method="POST", url=endpoint_url, json_body={"query": document})
    return Finding(
        id=f"graphql-bola:{field}",
        rule_id="graphql-bola",
        name="Broken Object Level Authorization via GraphQL (BOLA/IDOR)",
        severity="high",
        cwe="CWE-639",
        owasp="API1:2023",
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        family="authz",
        injection_point=InjectionPoint(location="json", name=field, base_value="", request_template=request),
        evidence=[
            Evidence(
                type="differential",
                data=(
                    f"the GraphQL field '{field}' returned the identical owned object (contains '{marker}') to "
                    f"multiple identities: {', '.join(names)} — object-level authorization is not enforced in the "
                    "resolver"
                )[:200],
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "Verifica en cada resolver que la identidad autenticada puede acceder al objeto concreto que pide el "
            "argumento id (no solo que esté autenticada). No confíes en que la query de nivel superior esté "
            "scoped: los resolvers anidados y los fetchers por id deben comprobar la propiedad del objeto."
        ),
    )


async def run_graphql_authz_checks(
    identities: list[Identity], endpoint_url: str, *, unauth_client: HttpClient | None = None
) -> list[Finding]:
    """Cross-identity GraphQL BOLA: same owned object returned to two identities via a by-id fetch."""
    if len(identities) < 2:
        return []  # BOLA needs at least two identities to compare
    schema = await _introspect_full(identities[0].client, endpoint_url)
    if schema is None:
        return []
    type_map = {t["name"]: t for t in schema.get("types", []) if t.get("name")}

    findings: list[Finding] = []
    for field, id_arg, arg_type in _id_fetchers(schema)[:_MAX_FETCHERS]:
        ret_kind, ret_type = _unwrap(field.get("type"))
        selection = _scalar_selection(type_map, ret_type)
        fired = False
        for id_value in _CANDIDATE_IDS:
            if fired:
                break
            document = _document(field, id_arg, arg_type, id_value, selection)
            bodies: dict[str, list[str]] = {}
            resp_by_body: dict[str, HttpResponse] = {}
            probers: list[tuple[str, HttpClient]] = [(i.name, i.client) for i in identities]
            if unauth_client is not None:
                probers.append(("unauthenticated", unauth_client))
            for name, client in probers:
                response = await _fetch(client, endpoint_url, document)
                body = _object_body(response)
                if body is None:
                    continue
                bodies.setdefault(body, []).append(name)
                resp_by_body.setdefault(body, response)  # type: ignore[arg-type]
            for body, who in bodies.items():
                marker = _ownership_marker(body)
                if len(who) >= 2 and marker is not None:
                    findings.append(
                        _bola_finding(endpoint_url, document, resp_by_body[body], field["name"], who, marker)
                    )
                    fired = True
                    break
    return findings
