"""Shellshock detector: a simulated CGI that 'executes' a bash-function header is
flagged by the marker echo; a normal endpoint that ignores the header is not."""

from __future__ import annotations

import re
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.shellshock import check_shellshock

_INJECT = re.compile(r"\(\)\s*\{\s*:;\};\s*echo;\s*echo\s+(\S+);")


def _app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/cgi-bin/status")
    def cgi() -> Response:  # vulnerable: 'runs' the injected echo from a header
        for header in ("User-Agent", "Referer", "Cookie"):
            m = _INJECT.search(request.headers.get(header, ""))
            if m:
                return Response(f"{m.group(1)}\nnormal cgi output", mimetype="text/plain")
        return Response("normal cgi output", mimetype="text/plain")

    @app.get("/safe")
    def safe() -> Response:  # ignores request headers entirely
        return Response("hello", mimetype="text/html")

    return app


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = make_server("127.0.0.1", port, _app(), threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


async def test_detects_shellshock_on_cgi(server: str) -> None:
    reqs = [HttpRequest(method="GET", url=f"{server}/cgi-bin/status")]
    async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"])) as client:
        findings = await check_shellshock(client, reqs)
    assert len(findings) == 1
    assert findings[0].rule_id == "shellshock" and findings[0].cwe == "CWE-78"


async def test_no_finding_on_safe_endpoint(server: str) -> None:
    reqs = [HttpRequest(method="GET", url=f"{server}/safe")]
    async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"])) as client:
        assert await check_shellshock(client, reqs) == []
