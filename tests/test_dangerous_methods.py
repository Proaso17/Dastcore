"""Dangerous-HTTP-methods check: reports PUT/DELETE/PATCH advertised in the OPTIONS
Allow header, and stays quiet when only safe methods are exposed."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.detectors.active_checks import check_dangerous_methods


def _make_app(methods: list[str]):
    from flask import Flask, Response

    app = Flask(__name__)

    @app.route("/", methods=methods)
    def index() -> Response:
        return Response("ok")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture
def dangerous_url() -> Iterator[str]:
    url, server = _serve(_make_app(["GET", "PUT", "DELETE"]))
    yield url
    server.shutdown()


@pytest.fixture
def safe_url() -> Iterator[str]:
    url, server = _serve(_make_app(["GET"]))
    yield url
    server.shutdown()


async def test_flags_put_and_delete(dangerous_url: str) -> None:
    async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"])) as client:
        findings = await check_dangerous_methods(client, dangerous_url)
    assert len(findings) == 1
    assert findings[0].rule_id == "active-dangerous-methods" and findings[0].cwe == "CWE-749"
    assert "PUT" in findings[0].name and "DELETE" in findings[0].name


async def test_quiet_when_only_safe_methods(safe_url: str) -> None:
    async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"])) as client:
        assert await check_dangerous_methods(client, safe_url) == []
