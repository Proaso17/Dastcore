"""XML entity expansion: a parser that expands nested entities (modelled by a proportional delay) is
flagged via the time differential; an endpoint that doesn't parse the value as XML is not."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.xml_expansion import run_xml_expansion_checks


def _vuln_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.post("/parse")
    def parse() -> Response:
        body = request.form.get("xml", "")
        # A vulnerable parser stalls expanding nested entities; model that cost with a real delay.
        if "<!ENTITY" in body and "&e;" in body:
            time.sleep(1.3)
        return Response("parsed", mimetype="text/plain")

    return app


def _safe_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.post("/parse")
    def parse() -> Response:
        _ = request.form.get("xml", "")  # never parsed as XML -> no expansion, no delay
        return Response("parsed", mimetype="text/plain")

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
    return HttpRequest(method="POST", url=f"{base}/parse", data={"xml": "<r>ok</r>"})


async def test_entity_expansion_stall_is_flagged(vuln_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_xml_expansion_checks(client, [_req(vuln_url)])
    assert len(findings) == 1
    assert findings[0].rule_id == "xml-entity-expansion" and findings[0].cwe == "CWE-776"


async def test_non_xml_endpoint_is_not_flagged(safe_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_xml_expansion_checks(client, [_req(safe_url)])
    assert findings == []  # no XML parsing -> no delay -> no finding
