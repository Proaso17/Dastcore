"""Web cache poisoning. An app that reflects X-Forwarded-Host into a response cached by URL only
is flagged (a clean request gets the poisoned copy); an app that keys the cache on the header, and
one that never reflects it, are silent — the poison→clean differential keeps it FP-free."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.cache_poison import check_cache_poisoning


def _vuln_app():
    from flask import Flask, Response, request

    app = Flask(__name__)
    cache: dict[str, str] = {}

    @app.get("/page")
    def page() -> Response:
        key = request.full_path  # VULNERABLE: cache keyed on URL only, ignores the header
        if key not in cache:
            host = request.headers.get("X-Forwarded-Host", "example.test")
            cache[key] = f'<link rel="canonical" href="https://{host}/page">'  # reflects the header
        return Response(cache[key], mimetype="text/html")

    return app


def _safe_keyed_app():
    from flask import Flask, Response, request

    app = Flask(__name__)
    cache: dict[str, str] = {}

    @app.get("/page")
    def page() -> Response:
        host = request.headers.get("X-Forwarded-Host", "example.test")
        key = request.full_path + "|" + host  # HARDENED: header is part of the cache key
        if key not in cache:
            cache[key] = f'<link rel="canonical" href="https://{host}/page">'
        return Response(cache[key], mimetype="text/html")

    return app


def _no_reflect_app():
    from flask import Flask, Response

    app = Flask(__name__)

    @app.get("/page")
    def page() -> Response:
        return Response("<h1>static page</h1>", mimetype="text/html")  # never reflects the header

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def vuln_url() -> Iterator[str]:
    url, server = _serve(_vuln_app())
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def keyed_url() -> Iterator[str]:
    url, server = _serve(_safe_keyed_app())
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def static_url() -> Iterator[str]:
    url, server = _serve(_no_reflect_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _req(base: str) -> HttpRequest:
    return HttpRequest(method="GET", url=f"{base}/page")


async def test_unkeyed_header_reflection_is_flagged(vuln_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_cache_poisoning(client, _req(vuln_url))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "web-cache-poisoning" and f.cwe == "CWE-524"
    assert "X-Forwarded-Host" in f.name


async def test_header_keyed_cache_is_not_flagged(keyed_url: str) -> None:
    async with HttpClient(_scope()) as client:
        # a clean request has its own key → never gets the poisoned entry
        assert await check_cache_poisoning(client, _req(keyed_url)) == []


async def test_non_reflecting_page_is_not_flagged(static_url: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_cache_poisoning(client, _req(static_url)) == []
