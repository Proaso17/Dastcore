"""GraphQL-native checks (Module 9): field-suggestion leakage, batching/aliasing abuse, and
CSRF over GraphQL — each confirmed against a vulnerable endpoint and silent against a
hardened one, driven by the server's own behaviour so there are no false positives."""

from __future__ import annotations

import re
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.detectors.graphql import (
    check_graphql_batching,
    check_graphql_csrf,
    check_graphql_field_suggestions,
)

_KNOWN_FIELDS = {"me", "user", "__typename"}
_ALIAS = re.compile(r"(\w+)\s*:\s*__typename")


def _run_query(query: str) -> dict:
    """A tiny GraphQL executor: __typename, aliases, and 'Did you mean' on unknown fields."""
    data: dict = {}
    for (alias,) in _ALIAS.findall(query) or []:
        data[alias] = "Query"
    if "__typename" in query and not data:
        data["__typename"] = "Query"
    if "me" in query:
        data["me"] = {"id": 1, "name": "alice"}
    # unknown field → suggestion (leaks the schema)
    for token in re.findall(r"\b([a-zA-Z_]\w*)\b", query):
        if token in ("query", "mutation") or token in _KNOWN_FIELDS or token in data:
            continue
        if token.startswith("a") and token[1:].isdigit():  # alias like a0..a99
            continue
        return {"errors": [{"message": f'Cannot query field "{token}". Did you mean "user"?'}]}
    return {"data": data}


def _vuln_app():
    from flask import Flask, jsonify, request

    app = Flask(__name__)

    @app.route("/graphql", methods=["GET", "POST"])
    def graphql():
        if request.method == "GET":  # CSRF: executes via GET
            return jsonify(_run_query(request.args.get("query", "")))
        if request.content_type and "form-urlencoded" in request.content_type:  # CSRF: form-encoded
            return jsonify(_run_query(request.form.get("query", "")))
        body = request.get_json(silent=True)
        if isinstance(body, list):  # array batching enabled
            return jsonify([_run_query(item.get("query", "")) for item in body])
        return jsonify(_run_query((body or {}).get("query", "")))

    return app


def _strict_app():
    from flask import Flask, jsonify, request

    app = Flask(__name__)

    @app.post("/graphql")  # POST + JSON only; generic errors; no batching; complexity-limited
    def graphql():
        if not (request.content_type and "application/json" in request.content_type):
            return jsonify({"errors": [{"message": "must be application/json"}]}), 400
        body = request.get_json(silent=True)
        if isinstance(body, list):
            return jsonify({"errors": [{"message": "batching disabled"}]}), 400
        query = (body or {}).get("query", "")
        if len(_ALIAS.findall(query)) > 10:  # complexity limit rejects alias amplification
            return jsonify({"errors": [{"message": "query is too complex"}]}), 400
        unknown = [
            t
            for t in re.findall(r"\b([a-zA-Z_]\w*)\b", query)
            if t not in ("query", "mutation") and t not in _KNOWN_FIELDS and not (t.startswith("a") and t[1:].isdigit())
        ]
        if unknown:
            return jsonify({"errors": [{"message": "GraphQL validation error"}]})  # no suggestions
        return jsonify({"data": {a: "Query" for (a,) in _ALIAS.findall(query)} or {"__typename": "Query"}})

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}/graphql", server


@pytest.fixture(scope="module")
def vuln_gql() -> Iterator[str]:
    url, server = _serve(_vuln_app())
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def strict_gql() -> Iterator[str]:
    url, server = _serve(_strict_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


async def test_field_suggestions_detected(vuln_gql: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_graphql_field_suggestions(client, vuln_gql)
    assert len(findings) == 1 and findings[0].rule_id == "graphql-field-suggestions"


async def test_field_suggestions_silent_on_strict(strict_gql: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_graphql_field_suggestions(client, strict_gql) == []


async def test_batching_detected(vuln_gql: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_graphql_batching(client, vuln_gql, aliases=50)
    assert len(findings) == 1 and findings[0].rule_id == "graphql-batching"


async def test_batching_silent_on_strict(strict_gql: str) -> None:
    # strict server rejects array batching and enforces a complexity limit → no finding.
    async with HttpClient(_scope()) as client:
        assert await check_graphql_batching(client, strict_gql, aliases=50) == []


async def test_csrf_detected(vuln_gql: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_graphql_csrf(client, vuln_gql)
    assert len(findings) == 1 and findings[0].rule_id == "graphql-csrf"


async def test_csrf_silent_on_strict(strict_gql: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_graphql_csrf(client, strict_gql) == []
