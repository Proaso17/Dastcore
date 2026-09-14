"""HTTP verb tampering. An edge that blocks the literal DELETE method is bypassed when the backend
honours X-HTTP-Method-Override; flagged. An endpoint that ignores the override header, and one that
isn't denied at all, are silent -> FP-free."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.verb_tampering import check_verb_tampering


def _app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.route("/api/item/<i>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def item(i: str) -> Response:
        # Edge WAF blocks the literal DELETE method line...
        if request.method == "DELETE":
            return Response("Forbidden by the edge WAF", status=403)
        # ...but the backend honours the override header (the bypass).
        override = request.headers.get("X-HTTP-Method-Override", "")
        if override.upper() == "DELETE":
            return Response(f"DELETED item {i}: irreversible purge done", status=200)
        return Response(f"item {i} public view page", status=200)

    @app.route("/api/safe/<i>", methods=["GET", "DELETE"])
    def safe(i: str) -> Response:
        # Blocks DELETE and IGNORES the override header -> not bypassable.
        if request.method == "DELETE":
            return Response("Forbidden by the edge WAF", status=403)
        return Response(f"safe {i} view page", status=200)

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def verb_url() -> Iterator[str]:
    url, server = _serve(_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


async def test_method_override_bypass_is_flagged(verb_url: str) -> None:
    req = HttpRequest(method="DELETE", url=f"{verb_url}/api/item/1")
    async with HttpClient(_scope()) as client:
        finding = await check_verb_tampering(client, req)
    assert finding is not None
    assert finding.rule_id == "verb-tampering" and finding.cwe == "CWE-650"
    assert "override" in finding.evidence[0].data.lower() or "Override" in finding.evidence[0].data


async def test_endpoint_ignoring_override_is_not_flagged(verb_url: str) -> None:
    """DELETE is blocked but the override header is ignored -> GET-with-override == plain GET -> no bypass."""
    req = HttpRequest(method="DELETE", url=f"{verb_url}/api/safe/1")
    async with HttpClient(_scope()) as client:
        assert await check_verb_tampering(client, req) is None


async def test_non_denied_request_is_skipped(verb_url: str) -> None:
    """A GET that isn't denied (200) is never probed."""
    req = HttpRequest(method="GET", url=f"{verb_url}/api/item/1")
    async with HttpClient(_scope()) as client:
        assert await check_verb_tampering(client, req) is None
