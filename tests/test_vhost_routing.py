"""Host-header vhost routing. An edge that serves a distinct internal app for Host: internal/admin is
flagged; one that serves the same app for any Host, and one that returns a generic default for any
unknown Host (bogus == candidate), are silent -> the baseline+bogus differential keeps it FP-free."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.detectors.vhost_routing import check_vhost_routing


def _routing_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.route("/", defaults={"p": ""})
    @app.route("/<path:p>")
    def root(p: str) -> Response:
        host = request.host  # the Host header value
        if host in ("internal", "admin") or host.startswith(("admin.", "internal.")):
            return Response("INTERNAL ADMIN DASHBOARD - secrets, tokens, users", status=200)
        if host.startswith("127.0.0.1"):
            return Response("public marketing site, nothing sensitive", status=200)
        return Response("unknown host", status=404)  # bogus/other -> not routed

    return app


def _same_for_any_host_app():
    from flask import Flask, Response

    app = Flask(__name__)

    @app.route("/", defaults={"p": ""})
    @app.route("/<path:p>")
    def root(p: str) -> Response:
        return Response("the one and only app, same for every Host", status=200)

    return app


def _generic_default_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.route("/", defaults={"p": ""})
    @app.route("/<path:p>")
    def root(p: str) -> Response:
        if request.host.startswith("127.0.0.1"):
            return Response("public site", status=200)
        return Response("GENERIC DEFAULT VHOST PAGE", status=200)  # same for internal AND bogus

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}/", server


@pytest.fixture(scope="module")
def routing_url() -> Iterator[str]:
    url, server = _serve(_routing_app())
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def same_url() -> Iterator[str]:
    url, server = _serve(_same_for_any_host_app())
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def generic_url() -> Iterator[str]:
    url, server = _serve(_generic_default_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


async def test_internal_vhost_routing_is_flagged(routing_url: str) -> None:
    async with HttpClient(_scope()) as client:
        finding = await check_vhost_routing(client, routing_url)
    assert finding is not None
    assert finding.rule_id == "vhost-routing" and finding.cwe == "CWE-284"


async def test_same_app_for_any_host_is_not_flagged(same_url: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_vhost_routing(client, same_url) is None


async def test_generic_default_for_unknown_hosts_is_not_flagged(generic_url: str) -> None:
    """Internal and bogus hosts get the same generic default page -> the bogus guard blocks the FP."""
    async with HttpClient(_scope()) as client:
        assert await check_vhost_routing(client, generic_url) is None
