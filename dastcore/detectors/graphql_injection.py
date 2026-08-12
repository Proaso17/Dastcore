"""Active detector: injection through GraphQL field arguments.

The rule engine fuzzes query/body/header parameters, but a GraphQL operation hides its inputs
*inside* the query string — ``query { user(id: "1") { name } }`` — so classic injection points
never see them. This detector introspects the schema, then for every query/mutation field with
arguments it slips an injection payload into one argument at a time and confirms with the same
error-based oracle used for SQLi: a database error signature that appears with the payload but
not with a benign control. No signature, no finding — a resolver that safely parameterises its
query is never flagged.

Object-returning fields need a selection set to execute, so the probe adds ``{ __typename }``
(valid on any object/interface/union) when the server asks for one — otherwise validation would
reject the document before the resolver ever runs.

CWE-89 (SQL Injection) surfaced via GraphQL / OWASP API8:2023.
"""

from __future__ import annotations

import re

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.discovery.graphql import introspect

# Same DB error fingerprints the sqli rule uses — an error-based oracle is FP-safe by construction.
_SQL_ERROR = re.compile(
    r"SQL syntax|SQLite3::error|sqlite3\.OperationalError|ORA-\d{5}|mysql_fetch|"
    r"PostgreSQL.{0,20}ERROR|unrecognized token|near \".{0,20}\": syntax error",
    re.IGNORECASE,
)
_PAYLOAD = "1'"  # a lone quote breaks an unparameterised string literal
_SELECTION_REQUIRED = re.compile(
    r"must have a selection of subfields|selectionSet|requires? a selection", re.IGNORECASE
)


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _document(operation: str, field: str, arg_names: list[str], inject: int, payload: str, selection: bool) -> str:
    args = ", ".join(f'{name}: "{_escape(payload if i == inject else "1")}"' for i, name in enumerate(arg_names))
    head = f"{field}({args})" if args else field
    tail = " { __typename }" if selection else ""
    return f"{operation} {{ {head}{tail} }}"


async def _run(client: HttpClient, endpoint_url: str, document: str) -> HttpResponse | None:
    try:
        return await client.post(endpoint_url, json={"query": document})
    except (OutOfScopeError, BudgetExceededError):
        return None


def _fields(schema: dict, type_name: str | None) -> list[dict]:
    if not type_name:
        return []
    for type_def in schema.get("types", []):
        if type_def.get("name") == type_name:
            return type_def.get("fields") or []
    return []


async def check_graphql_arg_injection(client: HttpClient, endpoint_url: str) -> list[Finding]:
    """Probe every GraphQL field argument for error-based injection via the introspected schema."""
    schema = await introspect(client, endpoint_url)
    if schema is None:
        return []  # no introspection → nothing to enumerate (introspection itself is flagged elsewhere)

    findings: list[Finding] = []
    seen: set[str] = set()
    operations = [("query", (schema.get("queryType") or {}).get("name"))]
    operations.append(("mutation", (schema.get("mutationType") or {}).get("name")))

    for operation, type_name in operations:
        for field in _fields(schema, type_name):
            name = field.get("name")
            arg_names = [a["name"] for a in (field.get("args") or []) if a.get("name")]
            if not name or not arg_names:
                continue

            # Decide the selection form once from a benign probe, so baseline and payload match.
            benign = await _run(client, endpoint_url, _document(operation, name, arg_names, -1, "1", False))
            if benign is None:
                continue
            selection = bool(_SELECTION_REQUIRED.search(benign.text))
            if selection:
                benign = await _run(client, endpoint_url, _document(operation, name, arg_names, -1, "1", True))
                if benign is None:
                    continue
            if _SQL_ERROR.search(benign.text):
                continue  # the benign form already errors → can't attribute the payload

            for index, arg in enumerate(arg_names):
                key = f"{operation}:{name}:{arg}"
                if key in seen:
                    continue
                document = _document(operation, name, arg_names, index, _PAYLOAD, selection)
                injected = await _run(client, endpoint_url, document)
                if injected is None or not _SQL_ERROR.search(injected.text):
                    continue
                repro = await _run(client, endpoint_url, document)
                if repro is None or not _SQL_ERROR.search(repro.text):
                    continue  # unstable → noise
                seen.add(key)
                match = _SQL_ERROR.search(injected.text)
                request = HttpRequest(method="POST", url=endpoint_url, json_body={"query": document})
                findings.append(
                    Finding(
                        id=f"graphql-arg-sqli:{operation}:{name}:{arg}",
                        rule_id="graphql-arg-injection",
                        name="SQL injection via GraphQL argument",
                        severity="high",
                        cwe="CWE-89",
                        owasp="API8:2023",
                        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        family="sqli",
                        injection_point=InjectionPoint(
                            location="json", name=f"{operation}.{name}.{arg}", base_value="", request_template=request
                        ),
                        evidence=[
                            Evidence(
                                type="response_match",
                                data=(
                                    f"a quote injected into the '{arg}' argument of {operation} '{name}' surfaced a "
                                    f"database error ({match.group(0) if match else 'SQL error'}) absent from the "
                                    "benign control — the resolver builds an unparameterised query"
                                )[:200],
                                confidence="high",
                            )
                        ],
                        request=request,
                        response=injected,
                        remediation=(
                            "Parametriza las consultas en los resolvers de GraphQL igual que en REST: nunca "
                            "concatenes el valor del argumento en el SQL/consulta. Valida y castea los argumentos "
                            "según el tipo del esquema."
                        ),
                    )
                )
    return findings
