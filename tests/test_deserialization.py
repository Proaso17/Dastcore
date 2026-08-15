"""Insecure deserialization confirmed out-of-band. An endpoint that base64-decodes and
`pickle.loads` a parameter runs our benign callback payload → OAST records it → flagged; an
endpoint that never deserializes makes no callback and is silent (zero FP by construction)."""

from __future__ import annotations

import base64
import pickle
import socket
import threading
import urllib.request
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.deserialization import run_deserialization_checks
from dastcore.engine.oast import LocalOastServer


def _vuln_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/load")
    def load() -> Response:
        # VULNERABLE: base64-decode + pickle.loads attacker input → the payload's __reduce__ runs.
        blob = request.args.get("data", "")
        try:
            pickle.loads(base64.b64decode(blob))  # noqa: S301 - deliberately vulnerable fixture
        except Exception:  # noqa: BLE001 - a non-pickle value just does nothing
            pass
        return Response("ok", status=200)

    return app


def _safe_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/load")
    def load() -> Response:
        return Response(f"got {len(request.args.get('data', ''))} bytes", status=200)  # never deserializes

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
    return HttpRequest(method="GET", url=f"{base}/load", params={"data": "x"})


async def test_pickle_deserialization_is_flagged_via_oast(vuln_url: str) -> None:
    oast = LocalOastServer()
    await oast.start()
    try:
        async with HttpClient(_scope()) as client:
            findings = await run_deserialization_checks(client, [_req(vuln_url)], oast)
    finally:
        await oast.stop()
    assert findings, "the pickle payload should have called back"
    f = findings[0]
    assert f.rule_id == "insecure-deserialization" and f.cwe == "CWE-502"
    assert f.evidence[0].type == "oob" and "Python pickle" in f.name


async def test_safe_endpoint_is_not_flagged(safe_url: str) -> None:
    oast = LocalOastServer()
    await oast.start()
    try:
        async with HttpClient(_scope()) as client:
            assert await run_deserialization_checks(client, [_req(safe_url)], oast) == []
    finally:
        await oast.stop()


async def test_no_oast_is_a_noop(vuln_url: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await run_deserialization_checks(client, [_req(vuln_url)], None) == []


def test_pickle_payload_calls_back_on_load() -> None:
    # The payload is benign: on unpickle it only opens a URL. Prove the mechanism directly.
    from dastcore.detectors.deserialization import _pickle_payload

    blob = base64.b64decode(_pickle_payload("http://oast.test/tok"))  # build with the real urlopen first
    calls: list[str] = []
    original = urllib.request.urlopen
    urllib.request.urlopen = lambda url, *a, **k: calls.append(url) or _FakeResp()  # type: ignore[assignment]
    try:
        pickle.loads(blob)  # noqa: S301 - our own benign payload
    finally:
        urllib.request.urlopen = original  # type: ignore[assignment]
    assert calls == ["http://oast.test/tok"]


class _FakeResp:
    def read(self) -> bytes:
        return b""
