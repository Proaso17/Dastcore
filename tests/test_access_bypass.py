"""Access-control bypass via trusted headers: a denied endpoint that flips to success once a
spoofed X-Forwarded-For / X-Original-URL is sent — and a properly-secured one that never does."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.access_bypass import run_access_bypass_checks

_TRUSTED_IP = "127.0.0.1"


def _ip_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/")
    def home() -> Response:
        return Response("<h1>Home</h1><p>public landing page</p>", mimetype="text/html")

    @app.get("/internal/metrics")
    def metrics() -> Response:
        # Access decision on a client-controlled header (the vulnerability).
        if request.headers.get("X-Forwarded-For", "").split(",")[0].strip() == _TRUSTED_IP:
            return Response("INTERNAL METRICS: qps=42 mem=71% secret_token=abc", mimetype="text/plain")
        return Response("forbidden", status=403, mimetype="text/plain")

    return app


def _url_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/")
    def home() -> Response:
        override = request.headers.get("X-Original-URL")
        if override == "/admin":  # backend trusts the rewrite header
            return Response("<h1>ADMIN AREA</h1><ul><li>user: alice</li><li>user: bob</li></ul>", mimetype="text/html")
        if override:  # some other overridden path -> not found
            return Response("nope, no such page", status=404, mimetype="text/html")
        return Response("<h1>Home</h1><p>public landing page</p>", mimetype="text/html")

    @app.get("/admin")
    def admin() -> Response:
        return Response("blocked by proxy", status=403, mimetype="text/html")  # blocked when hit directly

    return app


def _safe_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/")
    def home() -> Response:
        return Response("<h1>Home</h1><p>public landing page</p>", mimetype="text/html")

    @app.get("/admin")
    def admin() -> Response:
        # Ignores every client header; authorization is enforced server-side -> always denied here.
        _ = request.headers
        return Response("forbidden", status=403, mimetype="text/html")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def ip_url() -> Iterator[str]:
    url, server = _serve(_ip_app())
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def url_url() -> Iterator[str]:
    url, server = _serve(_url_app())
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def safe_url() -> Iterator[str]:
    url, server = _serve(_safe_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


async def test_ip_allowlist_bypass_is_detected(ip_url: str) -> None:
    probes = [HttpRequest(method="GET", url=f"{ip_url}/internal/metrics")]
    async with HttpClient(_scope()) as client:
        findings = await run_access_bypass_checks(client, probes)
    ip = [f for f in findings if f.rule_id == "access-bypass-trusted-header-ip"]
    assert len(ip) == 1
    assert ip[0].cwe == "CWE-290" and ip[0].family == "authz"
    assert "X-Forwarded-For" in ip[0].evidence[0].data


async def test_url_override_bypass_is_detected(url_url: str) -> None:
    probes = [HttpRequest(method="GET", url=f"{url_url}/admin")]
    async with HttpClient(_scope()) as client:
        findings = await run_access_bypass_checks(client, probes)
    url = [f for f in findings if f.rule_id == "access-bypass-trusted-header-url"]
    assert len(url) == 1
    assert url[0].cwe == "CWE-284"
    assert "X-Original-URL" in url[0].evidence[0].data


async def test_properly_secured_endpoint_is_not_flagged(safe_url: str) -> None:
    probes = [HttpRequest(method="GET", url=f"{safe_url}/admin")]
    async with HttpClient(_scope()) as client:
        findings = await run_access_bypass_checks(client, probes)
    assert findings == []  # denies regardless of any spoofed header


async def test_non_denied_endpoints_are_skipped(ip_url: str) -> None:
    # A normal 200 page is not access-controlled -> never probed for bypass.
    probes = [HttpRequest(method="GET", url=f"{ip_url}/")]
    async with HttpClient(_scope()) as client:
        findings = await run_access_bypass_checks(client, probes)
    assert findings == []
