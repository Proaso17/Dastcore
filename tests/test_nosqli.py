"""NoSQL operator injection (MongoDB-style). A login that feeds the raw request body into a
fake Mongo query is bypassed by ``{"$ne": ...}`` and flagged; a hardened login that casts to
str, a form-encoded vulnerable login (qs bracket notation), and a clean echo endpoint are all
silent — the three-way differential keeps it false-positive-free."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.nosqli import check_nosql_injection


def _fake_mongo_match(stored: dict[str, str], query: object) -> bool:
    """Evaluate a Mongo-ish {field: value|operator} query against one stored record."""
    if not isinstance(query, dict):
        return False
    for field, cond in query.items():
        actual = stored.get(field)
        if isinstance(cond, dict):  # operator object — the injectable path
            if "$ne" in cond and not (actual != cond["$ne"]):
                return False
            if "$eq" in cond and not (actual == cond["$eq"]):
                return False
            if "$gt" in cond and not (actual is not None and actual > cond["$gt"]):
                return False
        elif actual != cond:
            return False
    return True


def _app():
    from flask import Flask, Response, request

    app = Flask(__name__)
    user = {"username": "admin", "password": "s3cr3t"}

    @app.post("/login-json")  # VULNERABLE: raw JSON body used as the query filter
    def login_json() -> Response:
        query = request.get_json(silent=True) or {}
        ok = _fake_mongo_match(user, query)
        return Response("welcome admin" if ok else "invalid credentials", status=200 if ok else 401)

    @app.post("/login-form")  # VULNERABLE: qs-style bracket parsing -> operator objects
    def login_form() -> Response:
        query = _parse_bracketed(request.form)
        ok = _fake_mongo_match(user, query)
        return Response("welcome admin" if ok else "invalid credentials", status=200 if ok else 401)

    @app.post("/login-safe")  # HARDENED: values coerced to str, operators become literals
    def login_safe() -> Response:
        body = request.get_json(silent=True) or {}
        query = {k: str(v) for k, v in body.items()}
        ok = _fake_mongo_match(user, query)
        return Response("welcome admin" if ok else "invalid credentials", status=200 if ok else 401)

    @app.post("/echo")  # clean endpoint: reflects a field, never queries anything
    def echo() -> Response:
        body = request.get_json(silent=True) or {}
        return Response(f"hello {body.get('name', '')}", status=200)

    return app


def _parse_bracketed(form) -> dict:
    """Turn 'password[$ne]=x' form keys into {'password': {'$ne': 'x'}} (like Express/qs)."""
    out: dict[str, object] = {}
    for key, value in form.items():
        if "[" in key and key.endswith("]"):
            base, op = key[: key.index("[")], key[key.index("[") + 1 : -1]
            slot = out.setdefault(base, {})
            if isinstance(slot, dict):
                slot[op] = value
        else:
            out[key] = value
    return out


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def nosql_server() -> Iterator[str]:
    url, server = _serve(_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


async def test_json_operator_injection_is_flagged(nosql_server: str) -> None:
    req = HttpRequest(method="POST", url=f"{nosql_server}/login-json", json_body={"username": "admin", "password": "x"})
    async with HttpClient(_scope()) as client:
        findings = await check_nosql_injection(client, req)
    assert len(findings) >= 1
    f = findings[0]
    assert f.rule_id == "nosql-operator-injection" and f.cwe == "CWE-943"
    assert f.injection_point.location == "json"


async def test_form_bracket_injection_is_flagged(nosql_server: str) -> None:
    req = HttpRequest(method="POST", url=f"{nosql_server}/login-form", data={"username": "admin", "password": "x"})
    async with HttpClient(_scope()) as client:
        findings = await check_nosql_injection(client, req)
    assert any(f.injection_point.location == "body" for f in findings)


async def test_hardened_login_is_not_flagged(nosql_server: str) -> None:
    req = HttpRequest(method="POST", url=f"{nosql_server}/login-safe", json_body={"username": "admin", "password": "x"})
    async with HttpClient(_scope()) as client:
        assert await check_nosql_injection(client, req) == []  # str() cast neutralises the operator


async def test_clean_endpoint_is_not_flagged(nosql_server: str) -> None:
    req = HttpRequest(method="POST", url=f"{nosql_server}/echo", json_body={"name": "bob"})
    async with HttpClient(_scope()) as client:
        assert await check_nosql_injection(client, req) == []


async def test_get_requests_are_skipped(nosql_server: str) -> None:
    req = HttpRequest(method="GET", url=f"{nosql_server}/echo", params={"name": "bob"})
    async with HttpClient(_scope()) as client:
        assert await check_nosql_injection(client, req) == []
