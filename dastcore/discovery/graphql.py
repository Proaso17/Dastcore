"""GraphQL introspection.

If a GraphQL endpoint has introspection enabled, it will describe its own schema
on request. This module runs the standard introspection query, extracts the
query/mutation fields, and turns each into a concrete `HttpRequest` the scanner
and authorization detector can probe — surfacing an API's whole operation set
without any documentation.
"""
from __future__ import annotations

import json

from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest

INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { "
    "queryType { name } mutationType { name } "
    "types { kind name fields { name args { name } } } } }"
)


async def introspect(http_client: HttpClient, endpoint_url: str) -> dict | None:
    """Return the `__schema` object if introspection is enabled, else None."""
    response = await http_client.post(endpoint_url, json={"query": INTROSPECTION_QUERY})
    try:
        payload = json.loads(response.text)
    except (json.JSONDecodeError, ValueError):
        return None
    schema = (payload.get("data") or {}).get("__schema")
    return schema if isinstance(schema, dict) else None


def _fields_of(schema: dict, type_name: str | None) -> list[dict]:
    if not type_name:
        return []
    for type_def in schema.get("types", []):
        if type_def.get("name") == type_name:
            return type_def.get("fields") or []
    return []


def _sample_document(operation: str, field: dict) -> str:
    args = field.get("args") or []
    if args:
        arg_str = ", ".join(f'{arg["name"]}: "1"' for arg in args if arg.get("name"))
        selection = f'{field["name"]}({arg_str})' if arg_str else field["name"]
    else:
        selection = field["name"]
    return f"{operation} {{ {selection} }}"


def operations_from_schema(schema: dict, endpoint_url: str) -> list[HttpRequest]:
    """Build one probe request per query and mutation field."""
    requests: list[HttpRequest] = []
    query_type = (schema.get("queryType") or {}).get("name")
    mutation_type = (schema.get("mutationType") or {}).get("name")

    for field in _fields_of(schema, query_type):
        if field.get("name"):
            requests.append(
                HttpRequest(method="POST", url=endpoint_url, json_body={"query": _sample_document("query", field)})
            )
    for field in _fields_of(schema, mutation_type):
        if field.get("name"):
            requests.append(
                HttpRequest(
                    method="POST", url=endpoint_url, json_body={"query": _sample_document("mutation", field)}
                )
            )
    return requests


async def discover_graphql(http_client: HttpClient, endpoint_url: str) -> list[HttpRequest]:
    """Introspect a GraphQL endpoint and return probe requests for every operation."""
    schema = await introspect(http_client, endpoint_url)
    if schema is None:
        return []
    return operations_from_schema(schema, endpoint_url)
