"""ReDoS: an endpoint whose regex backtracks catastrophically is flagged via super-linear scaling +
same-length control + reproducibility; a linear regex over the same inputs is not. Uses a *real*
vulnerable regex, so the blow-up is genuine (not a simulated delay)."""

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
from dastcore.detectors.redos import run_redos_checks

_EVIL_REGEX = re.compile(r"^(a+)+$")  # catastrophic backtracking on "a"*n + non-a
_SAFE_REGEX = re.compile(r"^[a-z0-9@. ]+$")  # linear, no nested quantifier


def _app(pattern: re.Pattern[str]):
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/check")
    def check() -> Response:
        q = request.args.get("q", "")
        return Response("match" if pattern.match(q) else "no", mimetype="text/plain")

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
    url, server = _serve(_app(_EVIL_REGEX))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def safe_url() -> Iterator[str]:
    url, server = _serve(_app(_SAFE_REGEX))
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _req(base: str) -> HttpRequest:
    return HttpRequest(method="GET", url=f"{base}/check", params={"q": "a"})


async def test_catastrophic_regex_is_flagged(vuln_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_redos_checks(client, [_req(vuln_url)])
    assert len(findings) == 1
    assert findings[0].rule_id == "redos" and findings[0].cwe == "CWE-1333"


async def test_linear_regex_is_not_flagged(safe_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_redos_checks(client, [_req(safe_url)])
    assert findings == []  # fast for every input size -> no super-linear stall
