"""WAF effectiveness audit. Against a simulated WAF that blocks some families (some bypassable) and
lets others pass, the audit reports a factual matrix: vendor, blocked, passed, and bypasses. Against a
target with no filtering it reports an informational all-clear. It only states observed behaviour."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.detectors.waf_audit import run_waf_audit


def _waf_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/")
    def root() -> Response:
        q = request.args.get("q", "")
        # sqli signature: space-sensitive -> bypassable by comment/whitespace transforms
        if "union select" in q.lower():
            return Response("Attention Required: request blocked", status=403)
        # xss signature: case-sensitive -> bypassable by case-swap
        if "<script" in q:
            return Response("Attention Required", status=403)
        # lfi/cmdi/ssrf/ssti/log4shell are NOT filtered -> WAF gaps
        return Response("<html>ok</html>", status=200)

    return app


def _open_app():
    from flask import Flask, Response

    app = Flask(__name__)

    @app.get("/")
    def root() -> Response:
        return Response("<html>ok</html>", status=200)  # nothing is ever blocked

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}/", server


@pytest.fixture(scope="module")
def waf_url() -> Iterator[str]:
    url, server = _serve(_waf_app())
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def open_url() -> Iterator[str]:
    url, server = _serve(_open_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


async def test_waf_audit_reports_blocks_passes_and_bypasses(waf_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_waf_audit(client, waf_url, waf_vendor="test-waf")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "waf-audit" and f.cwe == "CWE-693"
    data = f.evidence[0].data
    assert "test-waf" in data
    assert "lfi" in data  # an unfiltered family is reported as passed
    assert "Bypasses" in data  # sqli/xss blocks are bypassable
    assert f.severity == "low"  # gaps present


async def test_waf_audit_no_filtering_reports_all_passed(open_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_waf_audit(client, open_url)
    assert len(findings) == 1
    # nothing blocked -> every family is an unfiltered gap -> severity low, "Bloquea (0)"
    assert findings[0].severity == "low"
    assert "Bloquea (0)" in findings[0].evidence[0].data
