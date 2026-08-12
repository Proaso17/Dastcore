"""Hardcoded secrets in JS bundles: fetch discovered .js assets and flag baked-in credentials.
A bundle with an AWS/Stripe key is flagged; a clean bundle and non-.js assets are silent (the
high-signal secret patterns keep it false-positive-free)."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.js_secrets import run_js_secret_scan

_LEAKY_JS = 'const cfg={region:"us",key:"AKIAIOSFODNN7EXAMPLE",stripe:"sk_live_0123456789abcdef"};export default cfg;'
_CLEAN_JS = "const add=(a,b)=>a+b;export{add};// build hash 9f3a2b no secrets here"


def _app():
    from flask import Flask, Response

    app = Flask(__name__)

    @app.get("/static/app.js")
    def leaky() -> Response:
        return Response(_LEAKY_JS, mimetype="application/javascript")

    @app.get("/static/util.js")
    def clean() -> Response:
        return Response(_CLEAN_JS, mimetype="application/javascript")

    @app.get("/data.json")
    def data() -> Response:  # not a .js asset → never fetched by this detector
        return Response('{"key":"AKIAIOSFODNN7EXAMPLE"}', mimetype="application/json")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def js_server() -> Iterator[str]:
    url, server = _serve(_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


async def test_secrets_in_js_bundle_are_flagged(js_server: str) -> None:
    requests = [
        HttpRequest(method="GET", url=f"{js_server}/static/app.js"),
        HttpRequest(method="GET", url=f"{js_server}/static/util.js"),
        HttpRequest(method="GET", url=f"{js_server}/data.json"),
    ]
    async with HttpClient(_scope()) as client:
        findings = await run_js_secret_scan(client, requests)
    labels = {f.name for f in findings}
    assert any("AWS" in name for name in labels)
    assert any("Stripe" in name for name in labels)
    # the clean bundle and the .json (not a JS asset) produced nothing
    assert all(f.injection_point.request_template.url.endswith("app.js") for f in findings)
    assert all(f.rule_id == "js-secret-exposure" and f.cwe == "CWE-615" for f in findings)


async def test_secret_value_is_masked(js_server: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_js_secret_scan(client, [HttpRequest(method="GET", url=f"{js_server}/static/app.js")])
    assert findings
    for finding in findings:  # never re-leak the full secret in the evidence
        assert "AKIAIOSFODNN7EXAMPLE" not in finding.evidence[0].data
        assert "sk_live_0123456789abcdef" not in finding.evidence[0].data


async def test_no_js_assets_yields_nothing(js_server: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_js_secret_scan(client, [HttpRequest(method="GET", url=f"{js_server}/data.json")])
    assert findings == []
