"""Weak/default credentials: a login that accepts admin/admin is flagged; one that rejects every
default (or ignores the fields) is not."""

from __future__ import annotations

import secrets
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import FormLoginConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.detectors.weak_credentials import run_weak_credentials_check


def _app(*, accept_default: bool):
    from flask import Flask, Response, redirect, request

    app = Flask(__name__)

    @app.post("/login")
    def login():
        user, pw = request.form.get("username"), request.form.get("password")
        if accept_default and user == "admin" and pw == "admin":
            resp = redirect("/dashboard", code=302)  # a real login redirects to the app
            resp.set_cookie("sessionid", secrets.token_hex(8))
            return resp
        return Response("invalid credentials", status=200, mimetype="text/html")  # failed login re-renders

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def weak_url() -> Iterator[str]:
    url, server = _serve(_app(accept_default=True))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def strong_url() -> Iterator[str]:
    url, server = _serve(_app(accept_default=False))
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _cfg(base: str) -> FormLoginConfig:
    return FormLoginConfig(login_url=f"{base}/login", credentials={"username": "x", "password": "y"}, as_json=False)


async def test_default_credentials_are_flagged(weak_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_weak_credentials_check(client, _cfg(weak_url))
    assert len(findings) == 1
    assert findings[0].rule_id == "default-credentials" and findings[0].cwe == "CWE-1391"
    assert "admin" in findings[0].evidence[0].data


async def test_login_rejecting_all_defaults_is_not_flagged(strong_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_weak_credentials_check(client, _cfg(strong_url))
    assert findings == []
