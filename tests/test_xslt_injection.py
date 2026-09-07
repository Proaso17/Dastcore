"""Server-side XSLT injection: input that flows into a stylesheet's select is evaluated as XSLT, so
system-property('xsl:vendor') returns the processor name. A vulnerable transformer is flagged (the
vendor comes back bracketed by our markers); a page that reflects the input verbatim, and one that
errors, are not."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.xslt_injection import run_xslt_injection_checks


def _vuln_app():
    from flask import Flask, Response, request
    from lxml import etree

    app = Flask(__name__)
    _tmpl = (
        '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
        '<xsl:template match="/"><out><xsl:value-of select="{sel}"/></out></xsl:template></xsl:stylesheet>'
    )

    @app.get("/report")
    def report() -> Response:
        sel = request.args.get("field", "name")
        try:  # VULNERABLE: user input is spliced into the stylesheet and transformed
            transform = etree.XSLT(etree.fromstring(_tmpl.format(sel=sel).encode()))
            body = str(transform(etree.fromstring(b"<root><name>Ana</name></root>")))
        except etree.LxmlError as exc:
            body = f"<error>XSLT Transformer/Xalan error: {exc}</error>"  # errors even name a processor
        return Response(body, mimetype="text/html")

    return app


def _safe_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/report")
    def report() -> Response:
        # SAFE: the value is data, never part of a stylesheet.
        return Response(f"<out>{request.args.get('field', 'name')}</out>", mimetype="text/html")

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
    return HttpRequest(method="GET", url=f"{base}/report", params={"field": "name"})


async def test_xslt_injection_is_flagged(vuln_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_xslt_injection_checks(client, [_req(vuln_url)])
    assert len(findings) == 1
    assert findings[0].rule_id == "xslt-injection" and findings[0].cwe == "CWE-94"
    assert "libxslt" in findings[0].evidence[0].data


async def test_reflecting_page_is_not_flagged(safe_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_xslt_injection_checks(client, [_req(safe_url)])
    assert findings == []
