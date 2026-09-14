"""CSS Injection. Input reflected un-escaped into a <style> block or a style="" attribute is flagged
(raw CSS metacharacters survive → a new rule/declaration is injected). An endpoint that strips the
metacharacters, and one that reflects into plain HTML text (XSS territory), are silent → FP-free."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.css_injection import run_css_injection_checks


def _app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/style-block")  # VULNERABLE: reflects into a <style> block un-escaped
    def style_block() -> Response:
        q = request.args.get("q", "")
        return Response(f"<html><head><style>body {{ color: {q}; }}</style></head><body>x</body></html>",
                        mimetype="text/html")

    @app.get("/style-attr")  # VULNERABLE: reflects into a style="" attribute un-escaped
    def style_attr() -> Response:
        q = request.args.get("q", "")
        return Response(f'<html><body><div style="color:{q}">hi</div></body></html>', mimetype="text/html")

    @app.get("/style-safe")  # HARDENED: strips CSS metacharacters before reflecting into <style>
    def style_safe() -> Response:
        q = request.args.get("q", "").replace("{", "").replace("}", "").replace(";", "").replace(":", "")
        return Response(f"<html><head><style>body {{ color: {q}; }}</style></head></html>", mimetype="text/html")

    @app.get("/html-text")  # reflects into plain HTML text -> XSS territory, not CSS injection
    def html_text() -> Response:
        q = request.args.get("q", "")
        return Response(f"<html><body>hello {q}</body></html>", mimetype="text/html")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def css_url() -> Iterator[str]:
    url, server = _serve(_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _req(base: str, path: str) -> HttpRequest:
    return HttpRequest(method="GET", url=f"{base}{path}", params={"q": "blue"})


async def test_css_injection_in_style_block_is_flagged(css_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_css_injection_checks(client, [_req(css_url, "/style-block")])
    assert len(findings) == 1
    assert findings[0].rule_id == "css-injection" and findings[0].cwe == "CWE-116"
    assert "style" in findings[0].evidence[0].data.lower()


async def test_css_injection_in_style_attr_is_flagged(css_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_css_injection_checks(client, [_req(css_url, "/style-attr")])
    assert len(findings) == 1
    assert findings[0].rule_id == "css-injection"


async def test_escaped_css_context_is_not_flagged(css_url: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await run_css_injection_checks(client, [_req(css_url, "/style-safe")]) == []


async def test_html_text_reflection_is_not_flagged(css_url: str) -> None:
    """Reflection into plain HTML text is XSS, not CSS injection — this detector must stay out of it."""
    async with HttpClient(_scope()) as client:
        assert await run_css_injection_checks(client, [_req(css_url, "/html-text")]) == []
