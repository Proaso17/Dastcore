"""ORM Leak / query-operator injection. Flagged when a real operator (name[$ne]/name[gt]/name[$regex])
returns far more records than a no-match value AND than a bogus operator (control). An app that ignores
unknown bracket params (bogus and real behave the same) and an exact-match-only app are both silent."""

from __future__ import annotations

import re as _re
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.orm_leak import check_orm_leak

_USERS = [{"name": f"user{i:02d}", "email": f"user{i:02d}@corp.test"} for i in range(30)]


def _app():
    from flask import Flask, jsonify, request

    app = Flask(__name__)

    @app.get("/users")  # VULNERABLE: interprets ORM operators in the query parameter
    def users():
        q = request.args
        for key in q:
            if key == "name":
                return jsonify([u for u in _USERS if u["name"] == q["name"]])
            if key.startswith("name[") and key.endswith("]"):
                op, val = key[5:-1], q[key]
                if op == "$ne":
                    return jsonify([u for u in _USERS if u["name"] != val])
                if op in ("$gt", "gt"):
                    return jsonify([u for u in _USERS if u["name"] > val])
                if op == "$regex":
                    return jsonify([u for u in _USERS if _re.search(val, u["name"])])
                return jsonify([])  # unknown operator -> a real ORM rejects it -> empty
        return jsonify(_USERS)

    @app.get("/ignore")  # ignores unknown bracket params -> returns the full list for real AND bogus ops
    def ignore():
        name = request.args.get("name")
        return jsonify([u for u in _USERS if u["name"] == name]) if name is not None else jsonify(_USERS)

    @app.get("/exact")  # exact match only, no operator support
    def exact():
        name = request.args.get("name")
        return jsonify([u for u in _USERS if u["name"] == name]) if name else jsonify([])

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def orm_url() -> Iterator[str]:
    url, server = _serve(_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _req(base: str, path: str) -> HttpRequest:
    return HttpRequest(method="GET", url=f"{base}{path}", params={"name": "user05"})


async def test_orm_leak_flagged_on_operator_interpreting_endpoint(orm_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_orm_leak(client, _req(orm_url, "/users"))
    assert len(findings) == 1
    assert findings[0].rule_id == "orm-leak" and findings[0].cwe == "CWE-943"


async def test_no_orm_leak_when_bracket_params_ignored(orm_url: str) -> None:
    """Real and bogus operators both return the full list (app ignores brackets) -> not injection."""
    async with HttpClient(_scope()) as client:
        assert await check_orm_leak(client, _req(orm_url, "/ignore")) == []


async def test_no_orm_leak_on_exact_match_endpoint(orm_url: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_orm_leak(client, _req(orm_url, "/exact")) == []


async def test_non_get_and_no_params_are_skipped(orm_url: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_orm_leak(client, HttpRequest(method="POST", url=f"{orm_url}/users", params={"name": "x"})) == []
        assert await check_orm_leak(client, HttpRequest(method="GET", url=f"{orm_url}/users")) == []
