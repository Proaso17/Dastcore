"""Field-level GraphQL authorization: a sensitive field (email) returned with the same value to
two identities isn't access-scoped → flagged; a scoped sensitive field (each identity sees only
its own) and a type with no sensitive fields are silent."""

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
from dastcore.detectors.graphql_authz import run_graphql_field_authz_checks


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
                    "name": "profile",
                    "type": {"kind": "OBJECT", "name": "Profile", "ofType": None},
                    "args": [{"name": "id", "defaultValue": None, "type": _scalar("Int")}],
                },
                {
                    "name": "scopedProfile",
                    "type": {"kind": "OBJECT", "name": "Profile", "ofType": None},
                    "args": [{"name": "id", "defaultValue": None, "type": _scalar("Int")}],
                },
            ],
        },
        {
            "kind": "OBJECT",
            "name": "Profile",
            "fields": [
                {"name": "id", "type": _scalar("Int"), "args": []},
                {"name": "displayName", "type": _scalar("String"), "args": []},  # public, not sensitive
                {"name": "email", "type": _scalar("String"), "args": []},  # sensitive
                {"name": "role", "type": _scalar("String"), "args": []},  # sensitive
            ],
        },
    ],
}

_PROFILE = {"id": 1, "displayName": "Public Name", "email": "victim@corp.test", "role": "admin"}


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
        selected = re.findall(r"\b(id|displayName|email|role)\b", query)

        def _project(obj: dict) -> dict:
            return {k: obj.get(k) for k in selected}

        if "profile(" in query:  # VULNERABLE: sensitive fields returned to anyone
            return Response(json.dumps({"data": {"profile": _project(_PROFILE)}}), mimetype="application/json")
        if "scopedProfile(" in query:  # HARDENED: sensitive fields only for the owner
            visible = dict(_PROFILE)
            if user != "owner":
                visible["email"] = None
                visible["role"] = None
            return Response(json.dumps({"data": {"scopedProfile": _project(visible)}}), mimetype="application/json")
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


async def test_sensitive_field_leaked_to_two_identities_is_flagged(gql_server: str) -> None:
    owner, other = _identity("owner"), _identity("other")
    try:
        findings = await run_graphql_field_authz_checks([owner, other], f"{gql_server}/graphql")
    finally:
        await owner.client.aclose()
        await other.client.aclose()
    fields = {f.injection_point.name for f in findings}
    assert "profile.email" in fields  # sensitive field, same value to both identities
    assert "profile.role" in fields
    # a public, non-sensitive field is never flagged even when shared
    assert not any("displayName" in name for name in fields)
    # the scoped resolver (null to the non-owner) is not flagged
    assert not any(name.startswith("scopedProfile") for name in fields)
    leak = next(f for f in findings if f.injection_point.name == "profile.email")
    assert leak.rule_id == "graphql-field-authz" and leak.cwe == "CWE-639" and leak.family == "authz"


async def test_single_identity_yields_nothing(gql_server: str) -> None:
    owner = _identity("owner")
    try:
        assert await run_graphql_field_authz_checks([owner], f"{gql_server}/graphql") == []
    finally:
        await owner.client.aclose()
