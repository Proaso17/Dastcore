"""Code / Expression-Language injection: an engine that evaluates ${a*b} / #{a*b} / <%= a*b %> is
flagged (the product appears between our markers); a page that only reflects the payload is not."""

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
from dastcore.detectors.code_injection import run_code_injection_checks


def _eval_el(text: str) -> str:
    """Stand-in for an EL/template engine: evaluate ${a*b}, #{a*b}, and <%= a*b %>."""
    text = re.sub(r"\$\{(\d+)\*(\d+)\}", lambda m: str(int(m.group(1)) * int(m.group(2))), text)
    text = re.sub(r"#\{(\d+)\*(\d+)\}", lambda m: str(int(m.group(1)) * int(m.group(2))), text)
    text = re.sub(r"<%=\s*(\d+)\*(\d+)\s*%>", lambda m: str(int(m.group(1)) * int(m.group(2))), text)
    return text


def _vuln_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/render")
    def render() -> Response:
        return Response(f"<p>Hi {_eval_el(request.args.get('name', 'guest'))}</p>", mimetype="text/html")

    return app


def _safe_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/render")
    def render() -> Response:
        return Response(f"<p>Hi {request.args.get('name', 'guest')}</p>", mimetype="text/html")

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


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _req(base: str) -> HttpRequest:
    return HttpRequest(method="GET", url=f"{base}/render", params={"name": "guest"})


async def test_expression_language_is_flagged(vuln_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_code_injection_checks(client, [_req(vuln_url)])
    assert len(findings) == 1
    assert findings[0].rule_id == "expression-language-injection" and findings[0].cwe == "CWE-1327"
    assert findings[0].severity == "critical"


async def test_reflected_only_page_is_not_flagged(safe_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_code_injection_checks(client, [_req(safe_url)])
    assert findings == []
