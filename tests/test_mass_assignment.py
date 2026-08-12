"""Mass assignment / over-posting. A create endpoint that binds the whole JSON body lets a
client set a privileged `role` field and echoes it back → flagged. An endpoint with a field
allowlist (ignores unexpected keys) and a plain echo endpoint are silent — the reflection
differential with a unique sentinel keeps it false-positive-free."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.mass_assignment import check_mass_assignment

_ALLOWED = {"name", "email"}


def _app():
    from flask import Flask, jsonify, request

    app = Flask(__name__)

    @app.post("/users-vuln")  # VULNERABLE: binds the whole body, echoes the created object
    def users_vuln():
        body = request.get_json(silent=True) or {}
        created = {**body, "id": 1}  # role/is_admin/etc. bound straight through
        return jsonify(created), 201

    @app.post("/users-safe")  # HARDENED: only whitelisted fields are bound
    def users_safe():
        body = request.get_json(silent=True) or {}
        created = {k: v for k, v in body.items() if k in _ALLOWED}
        created["id"] = 1
        return jsonify(created), 201

    @app.post("/echo")  # reflects only a known field; unexpected keys are never echoed
    def echo():
        body = request.get_json(silent=True) or {}
        return jsonify({"greeting": f"hi {body.get('name', '')}"}), 200

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def mass_server() -> Iterator[str]:
    url, server = _serve(_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _post(url: str) -> HttpRequest:
    return HttpRequest(method="POST", url=url, json_body={"name": "bob", "email": "bob@x.test"})


async def test_over_posting_is_flagged(mass_server: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_mass_assignment(client, _post(f"{mass_server}/users-vuln"))
    assert findings, "should flag a body-binding create"
    f = findings[0]
    assert f.rule_id == "mass-assignment" and f.cwe == "CWE-915"
    # it injected a privileged field the client hadn't sent
    assert f.injection_point.name in {
        "role",
        "is_admin",
        "isAdmin",
        "admin",
        "is_staff",
        "is_superuser",
        "verified",
        "is_verified",
        "approved",
        "active",
        "owner",
        "owner_id",
        "user_id",
        "account_id",
        "balance",
        "credits",
        "plan",
    }


async def test_field_allowlist_is_not_flagged(mass_server: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_mass_assignment(client, _post(f"{mass_server}/users-safe")) == []


async def test_echo_endpoint_is_not_flagged(mass_server: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_mass_assignment(client, _post(f"{mass_server}/echo")) == []


async def test_get_requests_are_skipped(mass_server: str) -> None:
    async with HttpClient(_scope()) as client:
        req = HttpRequest(method="GET", url=f"{mass_server}/echo", params={"name": "bob"})
        assert await check_mass_assignment(client, req) == []


async def test_non_json_body_is_skipped(mass_server: str) -> None:
    async with HttpClient(_scope()) as client:
        req = HttpRequest(method="POST", url=f"{mass_server}/users-vuln", data={"name": "bob"})
        assert await check_mass_assignment(client, req) == []
