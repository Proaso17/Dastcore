"""DOM Clobbering. Flagged when a sanitizer blocks scripts but lets an attacker-controlled <a id=..>
survive as a literal tag in an HTML response (a named-global clobbering primitive). Full-XSS reflection
(script survives) is deferred to the XSS detector; fully-escaped and non-HTML responses are silent."""

from __future__ import annotations

import re as _re
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.dom_clobbering import run_dom_clobbering_checks


def _app():
    import json as _json

    from flask import Flask, Response, request
    from markupsafe import escape

    app = Flask(__name__)

    @app.get("/clobber")  # VULNERABLE: sanitizer strips scripts but keeps <a id=..>
    def clobber() -> Response:
        q = request.args.get("q", "")
        safe = _re.sub(r"<img\b[^>]*>", "", q, flags=_re.IGNORECASE)
        safe = _re.sub(r"onerror\s*=\s*\S+", "", safe, flags=_re.IGNORECASE)
        return Response(f"<html><body>{safe}</body></html>", mimetype="text/html")

    @app.get("/xss")  # reflects everything unescaped -> XSS territory, DOM-clobbering defers
    def xss() -> Response:
        return Response(f"<html><body>{request.args.get('q', '')}</body></html>", mimetype="text/html")

    @app.get("/escaped")  # HTML-encodes input -> nothing survives as a tag
    def escaped() -> Response:
        return Response(f"<html><body>{escape(request.args.get('q', ''))}</body></html>", mimetype="text/html")

    @app.get("/json")  # reflects into JSON (not text/html) -> a browser won't parse it as HTML
    def as_json() -> Response:
        return Response(_json.dumps({"q": request.args.get("q", "")}), mimetype="application/json")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def clob_url() -> Iterator[str]:
    url, server = _serve(_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _req(base: str, path: str) -> HttpRequest:
    return HttpRequest(method="GET", url=f"{base}{path}", params={"q": "hi"})


async def test_dom_clobbering_flagged_when_scripts_blocked_but_id_survives(clob_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_dom_clobbering_checks(client, [_req(clob_url, "/clobber")])
    assert len(findings) == 1
    assert findings[0].rule_id == "dom-clobbering" and findings[0].cwe == "CWE-79"


async def test_full_xss_reflection_is_deferred(clob_url: str) -> None:
    """When the script vector also survives, it's XSS — DOM clobbering must not double-report."""
    async with HttpClient(_scope()) as client:
        assert await run_dom_clobbering_checks(client, [_req(clob_url, "/xss")]) == []


async def test_escaped_output_is_not_flagged(clob_url: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await run_dom_clobbering_checks(client, [_req(clob_url, "/escaped")]) == []


async def test_non_html_response_is_not_flagged(clob_url: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await run_dom_clobbering_checks(client, [_req(clob_url, "/json")]) == []
