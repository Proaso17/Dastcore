"""Subdomain takeover: a host serving a provider's unclaimed-resource page is flagged; a live
host and a plain 404 are silent (the high-specificity provider fingerprints keep it FP-free)."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.takeover import run_subdomain_takeover_check


def _app(body: str, status: int = 200):
    from flask import Flask, Response

    app = Flask(__name__)

    @app.get("/")
    def root() -> Response:
        return Response(body, status=status, mimetype="text/html")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def dangling() -> Iterator[str]:
    url, server = _serve(_app("<html><body>There isn't a GitHub Pages site here.</body></html>", status=404))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def live() -> Iterator[str]:
    url, server = _serve(_app("<html><body><h1>Welcome to our app</h1></body></html>"))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def plain_404() -> Iterator[str]:
    url, server = _serve(_app("<html><body>404 Not Found — page missing</body></html>", status=404))
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


async def test_unclaimed_service_page_is_flagged(dangling: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_subdomain_takeover_check(client, dangling, [])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "subdomain-takeover" and "GitHub Pages" in f.name
    assert f.cwe == "CWE-284" and f.owasp == "WSTG-CONF-10"


async def test_live_host_is_not_flagged(live: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await run_subdomain_takeover_check(client, live, []) == []


async def test_plain_404_is_not_flagged(plain_404: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await run_subdomain_takeover_check(client, plain_404, []) == []


async def test_hosts_are_deduped_from_target_and_requests(dangling: str) -> None:
    # the same host referenced by target and several requests is fingerprinted once
    requests = [HttpRequest(method="GET", url=f"{dangling}/a"), HttpRequest(method="GET", url=f"{dangling}/b")]
    async with HttpClient(_scope()) as client:
        findings = await run_subdomain_takeover_check(client, dangling, requests)
    assert len(findings) == 1
