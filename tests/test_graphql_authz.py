"""Multi-session GraphQL BOLA. A resolver that fetches an object by id without checking
ownership returns the identical owned object to two different identities → flagged; a resolver
that scopes the object to the authenticated user, and a field with no ownership markers, are
silent — the same owned-object differential that guards REST BOLA keeps it FP-free."""

from __future__ import annotations

import json
import re
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import AuthConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.session import SessionManager
from dastcore.detectors.authz import Identity
from dastcore.detectors.graphql_authz import run_graphql_authz_checks


def _scalar(name: str) -> dict:
    return {"kind": "SCALAR", "name": name, "ofType": None}


_SCHEMA = {
    "queryType": {"name": "Query"},
    "types": [
        {
            "kind": "OBJECT",
            "name": "Query",
            "fields": [
                {
                    "name": "order",
                    "type": {"kind": "OBJECT", "name": "Order", "ofType": None},
                    "args": [{"name": "id", "defaultValue": None, "type": _scalar("Int")}],
                },  # VULNERABLE
                {
                    "name": "safeOrder",
                    "type": {"kind": "OBJECT", "name": "Order", "ofType": None},
                    "args": [{"name": "id", "defaultValue": None, "type": _scalar("Int")}],
                },  # scoped
                {
                    "name": "banner",
                    "type": {"kind": "OBJECT", "name": "Banner", "ofType": None},
                    "args": [{"name": "id", "defaultValue": None, "type": _scalar("Int")}],
                },  # public, no owner
                {"name": "ping", "type": _scalar("String"), "args": []},
            ],
        },
        {
            "kind": "OBJECT",
            "name": "Order",
            "fields": [
                {"name": "id", "type": _scalar("Int"), "args": []},
                {"name": "owner_id", "type": _scalar("String"), "args": []},
                {"name": "total", "type": _scalar("Int"), "args": []},
                {"name": "secret", "type": _scalar("String"), "args": []},
            ],
        },
        {
            "kind": "OBJECT",
            "name": "Banner",
            "fields": [
                {"name": "id", "type": _scalar("Int"), "args": []},
                {"name": "text", "type": _scalar("String"), "args": []},
            ],
        },
    ],
}

# order 1 belongs to alice. A properly-scoped resolver returns it only to alice.
_ORDERS = {"1": {"id": 1, "owner_id": "alice", "total": 100, "secret": "sk-1"}}
_BANNERS = {"1": {"id": 1, "text": "welcome"}}  # public: no ownership markers


def _app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.post("/graphql")
    def graphql() -> Response:
        body = request.get_json(silent=True) or {}
        query = body.get("query", "")
        if "__schema" in query:
            return Response(json.dumps({"data": {"__schema": _SCHEMA}}), mimetype="application/json")

        user = request.headers.get("X-User", "")
        match = re.search(r"(\w+)\(id:\s*(\d+)\)", query)
        if not match:
            return Response(json.dumps({"data": {}}), mimetype="application/json")
        field, oid = match.group(1), match.group(2)

        if field == "order":  # VULNERABLE: no ownership check
            return Response(json.dumps({"data": {"order": _ORDERS.get(oid)}}), mimetype="application/json")
        if field == "safeOrder":  # HARDENED: only the owner sees it
            obj = _ORDERS.get(oid)
            scoped = obj if obj and obj["owner_id"] == user else None
            return Response(json.dumps({"data": {"safeOrder": scoped}}), mimetype="application/json")
        if field == "banner":  # public object, no ownership markers
            return Response(json.dumps({"data": {"banner": _BANNERS.get(oid)}}), mimetype="application/json")
        return Response(json.dumps({"data": {}}), mimetype="application/json")

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


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _identity(name: str) -> Identity:
    session = SessionManager(AuthConfig(type="header", headers={"X-User": name}))
    return Identity(name=name, role="user", client=HttpClient(_scope(), session=session))


async def test_unscoped_resolver_flags_bola(gql_server: str) -> None:
    alice, bob = _identity("alice"), _identity("bob")
    try:
        findings = await run_graphql_authz_checks([alice, bob], f"{gql_server}/graphql")
    finally:
        await alice.client.aclose()
        await bob.client.aclose()
    fields = {f.injection_point.name for f in findings}
    assert "order" in fields  # same owned object leaked to both identities
    assert "safeOrder" not in fields  # scoped resolver returns null to the non-owner
    assert "banner" not in fields  # public object has no ownership markers → not flagged
    bola = next(f for f in findings if f.injection_point.name == "order")
    assert bola.rule_id == "graphql-bola" and bola.cwe == "CWE-639" and bola.family == "authz"


async def test_single_identity_yields_nothing(gql_server: str) -> None:
    alice = _identity("alice")
    try:
        assert await run_graphql_authz_checks([alice], f"{gql_server}/graphql") == []
    finally:
        await alice.client.aclose()
