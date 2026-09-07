"""Static DOM-XSS taint analysis: an attacker-controllable source (location.hash, document.referrer,
window.name) reaching a sink (innerHTML, document.write, eval, insertAdjacentHTML, jQuery .html) is
flagged; sanitized / textContent / static / unknown-function flows are not (zero false positives)."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.dom_xss_static import analyze_js, run_dom_xss_static_checks

# --- unit: the taint analyzer ---------------------------------------------------------------

@pytest.mark.parametrize("js", [
    "el.innerHTML = location.hash;",
    "var h = location.hash.substring(1); document.getElementById('o').innerHTML = h;",
    "document.write(location.href);",
    "eval(location.hash);",
    "el.insertAdjacentHTML('beforeend', document.referrer);",
    "el.innerHTML = '<b>' + window.name + '</b>';",
    "el.innerHTML = `hi ${location.search}`;",
    "$('#x').html(location.hash);",
    "var f = new Function(location.hash);",
])
def test_tainted_flows_are_detected(js: str) -> None:
    assert analyze_js(js), js


@pytest.mark.parametrize("js", [
    "el.textContent = location.hash;",
    "el.innerHTML = encodeURIComponent(location.search);",
    "el.innerHTML = '<b>static</b>';",
    "el.innerHTML = customSanitizer(location.hash);",       # unknown fn → untaint (no FP)
    "var x = 'safe'; el.innerHTML = x;",
    "var h = location.hash; h = 'safe'; el.innerHTML = h;",  # reassigned to safe
    "el.innerHTML = DOMPurify.sanitize(location.hash);",
    "el.innerHTML = location.hash.replace(/[<>]/g, '');",    # angle-bracket-stripping replace
    "function a(){var h=location.hash;} function b(){var h='x'; el.innerHTML=h;}",  # scoped separately
])
def test_safe_flows_are_not_flagged(js: str) -> None:
    assert analyze_js(js) == [], js


def test_unparseable_or_empty_is_silent() -> None:
    assert analyze_js("") == []
    assert analyze_js("const x = a?.b ?? c;  // modern syntax esprima rejects") == []  # no crash


# --- end-to-end: fetch pages + scripts and report -------------------------------------------

def _app():
    from flask import Flask, Response

    app = Flask(__name__)

    @app.get("/vuln")
    def vuln() -> Response:
        return Response(
            "<html><body><div id='o'></div>"
            "<script>document.getElementById('o').innerHTML = location.hash.substring(1);</script>"
            "</body></html>", mimetype="text/html")

    @app.get("/safe")
    def safe() -> Response:
        return Response(
            "<html><body><script>document.getElementById('o').textContent = location.hash;</script></body></html>",
            mimetype="text/html")

    @app.get("/ext")
    def ext() -> Response:
        return Response('<html><body><script src="/app.js"></script></body></html>', mimetype="text/html")

    @app.get("/app.js")
    def appjs() -> Response:
        return Response("window.onload=function(){document.write(document.referrer);};",
                        mimetype="application/javascript")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def app_url() -> Iterator[str]:
    url, server = _serve(_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


async def test_inline_script_taint_is_reported(app_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_dom_xss_static_checks(client, [HttpRequest(method="GET", url=f"{app_url}/vuln")])
    assert len(findings) == 1
    assert findings[0].rule_id == "dom-xss-static" and findings[0].cwe == "CWE-79"
    assert findings[0].confidence == "medium"  # static analysis → filterable via --min-confidence


async def test_external_script_taint_is_reported(app_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_dom_xss_static_checks(client, [HttpRequest(method="GET", url=f"{app_url}/ext")])
    assert any(f.rule_id == "dom-xss-static" for f in findings)


async def test_safe_page_yields_nothing(app_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_dom_xss_static_checks(client, [HttpRequest(method="GET", url=f"{app_url}/safe")])
    assert findings == []
