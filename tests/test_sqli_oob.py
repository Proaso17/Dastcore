"""Blind SQL injection confirmed out-of-band: the database itself calls the collaborator (here via an
Oracle UTL_HTTP sink), so the finding is proven with zero false positives even with no error/boolean/
timing signal. A sink that doesn't call out yields nothing."""

from __future__ import annotations

import re
import socket
import threading
from collections.abc import Iterator

import httpx
import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.engine.oast import LocalOastServer
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner

_SCOPE = ScopeConfig(allow_domains=["127.0.0.1"])
_UTL_HTTP = re.compile(r"UTL_HTTP\.request\('(http://[^']+)'\)")


def _vuln_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/report")
    def report() -> Response:
        # Simulate a blind SQLi sink on Oracle: the injected UTL_HTTP makes the DB fetch a URL
        # out-of-band (only this payload shape calls out — a plain reflected URL does not).
        m = _UTL_HTTP.search(request.args.get("q", ""))
        if m:
            try:
                httpx.get(m.group(1), timeout=3)
            except httpx.HTTPError:
                pass
        return Response("<p>report generated</p>", mimetype="text/html")

    return app


def _safe_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/report")
    def report() -> Response:
        return Response(f"<p>you searched {request.args.get('q', '')}</p>", mimetype="text/html")  # reflects only

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
def safe_url() -> Iterator[str]:
    url, server = _serve(_safe_app())
    yield url
    server.shutdown()


async def test_blind_sqli_confirmed_via_oob(vuln_url: str) -> None:
    server = LocalOastServer()
    await server.start()
    try:
        request = HttpRequest(method="GET", url=f"{vuln_url}/report", params={"q": "seed"})
        async with HttpClient(_SCOPE) as client:
            findings = await Scanner(client, load_rules(), oast=server, oob_poll_attempts=6).scan([request])
    finally:
        await server.stop()
    sqli = [f for f in findings if f.rule_id == "sqli-oob"]
    assert sqli, [f.rule_id for f in findings]
    assert sqli[0].family == "sqli" and sqli[0].evidence[0].type == "oob"


async def test_no_sqli_oob_without_a_callback(safe_url: str) -> None:
    server = LocalOastServer()
    await server.start()
    try:
        request = HttpRequest(method="GET", url=f"{safe_url}/report", params={"q": "seed"})
        async with HttpClient(_SCOPE) as client:
            findings = await Scanner(client, load_rules(), oast=server, oob_poll_attempts=2).scan([request])
    finally:
        await server.stop()
    assert not any(f.rule_id == "sqli-oob" for f in findings)  # reflected, never called out -> no finding
