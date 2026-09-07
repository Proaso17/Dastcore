"""End-to-end proof of the Burp-style nested insertion point: an endpoint that base64-decodes a
parameter and is SQL-injectable *inside* the decoded value is caught only because the scanner fuzzes
inside the encoding. The plain (un-encoded) payload can't reach the sink, so this pins the nested path."""

from __future__ import annotations

import base64
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner


def _vuln_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/api")
    def api() -> Response:
        raw = request.args.get("q", "")
        try:  # the server base64-decodes the parameter, then uses it in a query
            decoded = base64.b64decode(raw, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return Response("<p>ok</p>", mimetype="text/html")  # not base64 -> nothing reaches the sink
        if "'" in decoded:  # a quote in the DECODED value breaks the SQL -> error-based SQLi
            return Response(
                f"<pre>You have an error in your SQL syntax near '{decoded}'</pre>", status=500, mimetype="text/html"
            )
        return Response("<p>ok</p>", mimetype="text/html")

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


async def test_sqli_inside_a_base64_parameter_is_found(vuln_url: str) -> None:
    # The parameter value is base64 (of a realistic-length token) — the scanner detects the encoding and
    # fuzzes inside it. (Very short base64 is skipped to avoid coincidental matches, so use a real value.)
    token = base64.b64encode(b"hello-world-token").decode()
    request = HttpRequest(method="GET", url=f"{vuln_url}/api?q={token}", params={"q": token})
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        findings = await Scanner(client, load_rules(), concurrency=1).scan_request(request)
    sqli = [f for f in findings if f.family == "sqli"]
    assert sqli, "expected the base64-nested SQL injection to be detected"
