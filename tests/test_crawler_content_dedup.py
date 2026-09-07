"""Content-based location identity (Burp-style): a page reached at an ever-changing URL (a per-request
token in the link) is recognised as ONE location by its normalized content, so the crawler doesn't loop
on it or bloat the discovered set — while genuinely different pages are still crawled separately."""

from __future__ import annotations

import secrets
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.discovery.crawler_http import HttpCrawler


def _trap_app():
    from flask import Flask, Response

    app = Flask(__name__)

    @app.get("/")
    def index() -> Response:
        return Response('<a href="/trap">trap</a> <a href="/unique">unique</a>', mimetype="text/html")

    @app.get("/trap")
    def trap() -> Response:
        # Identical content every time except a fresh 32-hex token in the self-link — the classic
        # token-in-URL crawl trap. normalize_body masks the hex, so every visit fingerprints the same.
        tok = secrets.token_hex(16)
        return Response(
            f'<html><body><h1>Dashboard</h1><a href="/trap?token={tok}">refresh</a></body></html>',
            mimetype="text/html",
        )

    @app.get("/unique")
    def unique() -> Response:
        return Response(
            "<html><body><h1>Completely different page</h1><p>with its own distinctive words</p></body></html>",
            mimetype="text/html",
        )

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def trap_url() -> Iterator[str]:
    url, server = _serve(_trap_app())
    yield url
    server.shutdown()


async def test_token_in_url_page_is_one_location(trap_url: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        discovered = await HttpCrawler(client, max_pages=40, use_robots=False).crawl(f"{trap_url}/")

    trap_reqs = [r for r in discovered if "/trap" in r.url]
    # Without content dedup the crawler would follow a fresh /trap?token=… every time up to max_pages.
    assert len(trap_reqs) <= 2, [r.url for r in trap_reqs]
    # The genuinely different page is still discovered.
    assert any(r.url.endswith("/unique") for r in discovered)
