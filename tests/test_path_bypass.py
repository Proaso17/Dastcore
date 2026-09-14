"""Path-normalization access-control bypass. A raw WSGI app keyed on the *raw* request target
simulates a proxy that denies /admin literally while normalization variants reach the secret. /secret
is never bypassable, and /portal returns a generic page for any variant (catch-all trap) -> neither fires."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.path_bypass import run_path_bypass_checks

# Variants the backend collapses back to /admin (the proxy blocks only the literal "/admin").
_ADMIN_BYPASS = {
    "/admin/", "/admin/./", "/admin/.", "/admin//", "/admin/..;/", "/admin..;/",
    "/admin;/", "/admin.", "/admin%2f", "//admin", "/./admin",
}


def _proxy_app():
    def app(environ, start_response):
        raw = (environ.get("RAW_URI") or environ.get("REQUEST_URI") or environ.get("PATH_INFO", ""))
        raw = raw.split("?", 1)[0]

        def resp(status: str, body: bytes):
            start_response(status, [("Content-Type", "text/html")])
            return [body]

        if raw == "/admin":
            return resp("403 Forbidden", b"Forbidden by the edge proxy")
        if raw in _ADMIN_BYPASS:
            return resp("200 OK", b"SECRET ADMIN PANEL: user list, api tokens, danger zone")
        if raw.startswith("/admin"):
            return resp("404 Not Found", b"not found")  # bogus /adminXXX/ control -> 404
        if raw.startswith("/secret"):
            return resp("403 Forbidden", b"Forbidden")  # never bypassable
        if raw == "/portal":
            return resp("403 Forbidden", b"Forbidden by the edge proxy")
        if raw.startswith("/portal"):
            return resp("200 OK", b"GENERIC PORTAL LANDING PAGE - marketing, nothing protected here")
        return resp("404 Not Found", b"not found")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def proxy_url() -> Iterator[str]:
    url, server = _serve(_proxy_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _get(base: str, path: str) -> HttpRequest:
    return HttpRequest(method="GET", url=f"{base}{path}")


async def test_path_normalization_bypass_is_flagged(proxy_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_path_bypass_checks(client, [_get(proxy_url, "/admin")])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "path-normalization-bypass" and f.cwe == "CWE-284"
    assert "/admin" in f.evidence[0].data


async def test_non_bypassable_protected_path_is_not_flagged(proxy_url: str) -> None:
    """/secret denies every variant -> no bypass."""
    async with HttpClient(_scope()) as client:
        assert await run_path_bypass_checks(client, [_get(proxy_url, "/secret")]) == []


async def test_generic_catch_all_page_is_not_flagged(proxy_url: str) -> None:
    """/portal returns the same generic page for real AND bogus variants -> the guard blocks the FP."""
    async with HttpClient(_scope()) as client:
        assert await run_path_bypass_checks(client, [_get(proxy_url, "/portal")]) == []


async def test_unprotected_path_is_skipped(proxy_url: str) -> None:
    """A path that isn't denied directly (404, not 401/403) is never probed."""
    async with HttpClient(_scope()) as client:
        assert await run_path_bypass_checks(client, [_get(proxy_url, "/public")]) == []
