"""SQL injection through GraphQL field arguments. A resolver that concatenates an argument
into SQL leaks a DB error on a quote and is flagged (both for a scalar-returning field and an
object-returning one, via a __typename selection); a parameterised resolver and an endpoint
without introspection are silent — the error-based oracle keeps it false-positive-free."""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.detectors.graphql_injection import check_graphql_arg_injection

_SCHEMA = {
    "queryType": {"name": "Query"},
    "mutationType": None,
    "types": [
        {
            "name": "Query",
            "fields": [
                {"name": "lookup", "args": [{"name": "id"}]},  # scalar-returning, VULNERABLE
                {"name": "user", "args": [{"name": "id"}]},  # object-returning, VULNERABLE
                {"name": "safe", "args": [{"name": "id"}]},  # parameterised, not vulnerable
                {"name": "ping", "args": []},  # no args — skipped
            ],
        },
    ],
}


def _extract_arg(query: str, field: str) -> str | None:
    """Pull the id argument value out of a `field(id: "...")` document."""
    marker = f"{field}("
    if marker not in query:
        return None
    after = query.split(marker, 1)[1]
    inner = after.split(")", 1)[0]
    if ': "' not in inner:
        return None
    return inner.split(': "', 1)[1].rsplit('"', 1)[0]


def _app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.post("/graphql")
    def graphql() -> Response:
        body = request.get_json(silent=True) or {}
        query = body.get("query", "")
        if "IntrospectionQuery" in query or "__schema" in query:
            return Response(json.dumps({"data": {"__schema": _SCHEMA}}), status=200, mimetype="application/json")

        # object-returning fields require a selection set before they execute
        for field in ("user",):
            if f"{field}(" in query and "{" not in query.split(f"{field}(", 1)[1]:
                return Response(
                    json.dumps({"errors": [{"message": "Field 'user' must have a selection of subfields."}]}),
                    status=200,
                    mimetype="application/json",
                )

        for field in ("lookup", "user"):  # VULNERABLE: value concatenated into SQL
            val = _extract_arg(query, field)
            if val is not None and "'" in val:
                return Response(
                    json.dumps({"errors": [{"message": f"You have an error in your SQL syntax near '{val}'"}]}),
                    status=200,
                    mimetype="application/json",
                )
        # `safe` (parameterised) and clean values just return data
        return Response(json.dumps({"data": {"ok": True}}), status=200, mimetype="application/json")

    return app


def _app_no_introspection():
    from flask import Flask, Response

    app = Flask(__name__)

    @app.post("/graphql")
    def graphql() -> Response:
        return Response(json.dumps({"errors": [{"message": "introspection disabled"}]}), status=200)

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def gql_server() -> Iterator[str]:
    url, server = _serve(_app())
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def gql_no_introspection() -> Iterator[str]:
    url, server = _serve(_app_no_introspection())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


async def test_scalar_and_object_field_injection_flagged(gql_server: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_graphql_arg_injection(client, f"{gql_server}/graphql")
    flagged = {f.injection_point.name for f in findings}
    assert "query.lookup.id" in flagged  # scalar-returning field
    assert "query.user.id" in flagged  # object-returning field, reached via __typename selection
    assert all(f.rule_id == "graphql-arg-injection" and f.cwe == "CWE-89" for f in findings)


async def test_parameterised_field_not_flagged(gql_server: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_graphql_arg_injection(client, f"{gql_server}/graphql")
    assert "query.safe.id" not in {f.injection_point.name for f in findings}


async def test_no_introspection_yields_nothing(gql_no_introspection: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_graphql_arg_injection(client, f"{gql_no_introspection}/graphql") == []
