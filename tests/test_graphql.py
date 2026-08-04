"""Phase 7: GraphQL introspection."""
from __future__ import annotations

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.discovery.graphql import discover_graphql, introspect, operations_from_schema

_SCOPE = ScopeConfig(allow_domains=["127.0.0.1"])


def test_operations_from_schema_builds_query_and_mutation_requests() -> None:
    schema = {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "fields": [{"name": "me", "args": []}, {"name": "user", "args": [{"name": "id"}]}]},
            {"name": "Mutation", "fields": [{"name": "deleteUser", "args": [{"name": "id"}]}]},
        ],
    }
    requests = operations_from_schema(schema, "http://t/graphql")
    docs = [r.json_body["query"] for r in requests]
    assert any(d.startswith("query") and "me" in d for d in docs)
    assert any(d.startswith("query") and "user(" in d for d in docs)
    assert any(d.startswith("mutation") and "deleteUser(" in d for d in docs)
    assert all(r.method == "POST" and r.url.endswith("/graphql") for r in requests)


async def test_introspect_returns_none_on_non_graphql(vuln_app_url: str) -> None:
    async with HttpClient(_SCOPE) as client:
        schema = await introspect(client, f"{vuln_app_url}/health")
    assert schema is None


async def test_discover_graphql_against_target(vuln_app_url: str) -> None:
    async with HttpClient(_SCOPE) as client:
        requests = await discover_graphql(client, f"{vuln_app_url}/graphql")
    docs = [r.json_body["query"] for r in requests]
    assert any("me" in d for d in docs)
    assert any("deleteUser" in d for d in docs)
