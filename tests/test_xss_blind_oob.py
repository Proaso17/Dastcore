"""Blind / stored XSS confirmed out-of-band: a beacon sprayed into an input executes when the browser
renders the page (the stored comment list, or the reflected echo) and calls the collaborator — proving
XSS that surfaces on another page, which the reflected/DOM checks miss. Needs Playwright + Chromium; a
sanitized app calls back nothing (zero false positives)."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest

pytest.importorskip("playwright.async_api")

from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.models import HttpRequest
from dastcore.discovery.crawler_headless import HeadlessEngine, HeadlessUnavailableError
from dastcore.engine.oast import LocalOastServer

_SCOPE = ScopeConfig(allow_domains=["127.0.0.1"])


def _app(*, sanitize: bool):
    from html import escape

    from flask import Flask, Response, request

    stored: list[str] = []
    app = Flask(__name__)

    @app.get("/")
    def index() -> Response:
        return Response('<a href="/comments">comments</a>', mimetype="text/html")

    @app.route("/comment", methods=["POST"])
    def comment() -> Response:
        stored.append(request.form.get("text", ""))
        return Response("<p>saved</p>", mimetype="text/html")

    @app.get("/comments")
    def comments() -> Response:
        body = "".join(f"<div>{escape(c) if sanitize else c}</div>" for c in stored)
        return Response(f"<html><body>{body}</body></html>", mimetype="text/html")

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
    url, server = _serve(_app(sanitize=False))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def safe_url() -> Iterator[str]:
    url, server = _serve(_app(sanitize=True))
    yield url
    server.shutdown()


def _requests(base: str) -> list[HttpRequest]:
    # The storing form (beacon sprayed into 'text') and the page that renders it (beacon executes there).
    return [
        HttpRequest(method="POST", url=f"{base}/comment", data={"text": "seed"}),
        HttpRequest(method="GET", url=f"{base}/comments"),
    ]


async def _run(base: str):
    server = LocalOastServer()
    await server.start()
    try:
        try:
            async with HeadlessEngine(_SCOPE) as engine:
                return await engine.scan_blind_xss_oob(_requests(base), server, max_points=5)
        except HeadlessUnavailableError as exc:
            pytest.skip(str(exc))
    finally:
        await server.stop()


async def test_stored_xss_beacon_calls_back(vuln_url: str) -> None:
    findings = await _run(vuln_url)
    blind = [f for f in findings if f.rule_id == "xss-blind-oob"]
    assert blind, "expected the stored-XSS beacon to execute and call back"
    assert blind[0].family == "xss" and blind[0].evidence[0].type == "oob"


async def test_sanitized_app_no_callback(safe_url: str) -> None:
    findings = await _run(safe_url)
    assert not any(f.rule_id == "xss-blind-oob" for f in findings)  # escaped output never executes
