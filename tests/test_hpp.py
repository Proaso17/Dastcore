"""HTTP Parameter Pollution. A duplicated query parameter is flagged only when the server's handling
is observably insecure — last-wins override or concatenation — proven with unique reflected sentinels.
A first-wins endpoint (Flask's default) and a non-reflecting one are silent, keeping it FP-free."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.hpp import check_hpp


def _app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/last")  # last-wins: reflects the LAST occurrence (PHP/Django/Rails style)
    def last() -> Response:
        vals = request.args.getlist("q")
        return Response(f"<html>result: {vals[-1] if vals else ''}</html>", mimetype="text/html")

    @app.get("/concat")  # concatenation: joins all occurrences (ASP.NET/Node style)
    def concat() -> Response:
        return Response(f"<html>result: {','.join(request.args.getlist('q'))}</html>", mimetype="text/html")

    @app.get("/first")  # first-wins (Flask default), reflected -> normal, must NOT be flagged
    def first() -> Response:
        return Response(f"<html>result: {request.args.get('q', '')}</html>", mimetype="text/html")

    @app.get("/noreflect")  # handles duplicates but never reflects the value -> can't confirm -> silent
    def noreflect() -> Response:
        return Response(f"<html>count: {len(request.args.getlist('q'))}</html>", mimetype="text/html")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def hpp_url() -> Iterator[str]:
    url, server = _serve(_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _req(base: str, path: str) -> HttpRequest:
    return HttpRequest(method="GET", url=f"{base}{path}", params={"q": "orig"})


async def test_last_wins_override_is_flagged(hpp_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_hpp(client, _req(hpp_url, "/last"))
    assert len(findings) == 1
    assert findings[0].rule_id == "http-parameter-pollution" and findings[0].cwe == "CWE-235"
    assert "override" in findings[0].evidence[0].data.lower()


async def test_concatenation_is_flagged(hpp_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_hpp(client, _req(hpp_url, "/concat"))
    assert len(findings) == 1
    assert "concatenaci" in findings[0].evidence[0].data.lower()


async def test_first_wins_endpoint_is_not_flagged(hpp_url: str) -> None:
    """Flask's default first-occurrence behaviour is normal, not HPP."""
    async with HttpClient(_scope()) as client:
        assert await check_hpp(client, _req(hpp_url, "/first")) == []


async def test_non_reflected_param_is_not_flagged(hpp_url: str) -> None:
    """Without a reflected value we can't tell which occurrence the server used -> never guess."""
    async with HttpClient(_scope()) as client:
        assert await check_hpp(client, _req(hpp_url, "/noreflect")) == []


async def test_non_get_and_no_params_are_skipped(hpp_url: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_hpp(client, HttpRequest(method="POST", url=f"{hpp_url}/last", params={"q": "x"})) == []
        assert await check_hpp(client, HttpRequest(method="GET", url=f"{hpp_url}/last")) == []
