"""Race-condition detection (Module 11). A concurrent burst against a TOCTOU single-use
endpoint double-spends and is flagged; a properly-locked single-use endpoint and a plain
multi-use endpoint are both silent (no false positives)."""

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
from dastcore.engine.race import check_race_condition


def _coupon_app():
    from flask import Flask, Response

    app = Flask(__name__)
    state = {"racy_used": False, "safe_used": False}
    lock = threading.Lock()

    @app.post("/redeem-racy")  # check-then-act with a window → double-spendable
    def redeem_racy() -> Response:
        if state["racy_used"]:
            return Response("already used", status=409)
        time.sleep(0.03)  # the TOCTOU window concurrent requests slip through
        state["racy_used"] = True
        return Response("redeemed", status=200)

    @app.post("/redeem-safe")  # atomic under a lock → only one ever succeeds
    def redeem_safe() -> Response:
        with lock:
            if state["safe_used"]:
                return Response("already used", status=409)
            state["safe_used"] = True
            return Response("redeemed", status=200)

    @app.post("/comment")  # plain multi-use endpoint (repeats are allowed)
    def comment() -> Response:
        return Response("ok", status=200)

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def coupon_server() -> Iterator[str]:
    url, server = _serve(_coupon_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _post(url: str) -> HttpRequest:
    return HttpRequest(method="POST", url=url, json_body={"coupon": "SAVE10"})


async def test_toctou_single_use_is_flagged(coupon_server: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_race_condition(client, _post(f"{coupon_server}/redeem-racy"), attempts=25)
    assert len(findings) == 1
    assert findings[0].rule_id == "race-condition" and findings[0].cwe == "CWE-362"


async def test_locked_single_use_is_not_flagged(coupon_server: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_race_condition(client, _post(f"{coupon_server}/redeem-safe"), attempts=25)
    assert findings == []  # only one succeeds even concurrently


async def test_multi_use_endpoint_is_not_flagged(coupon_server: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_race_condition(client, _post(f"{coupon_server}/comment"), attempts=10)
    assert findings == []  # a later request still succeeds → repeats allowed, not a race


async def test_get_requests_are_skipped(coupon_server: str) -> None:
    async with HttpClient(_scope()) as client:
        req = HttpRequest(method="GET", url=f"{coupon_server}/comment")
        assert await check_race_condition(client, req) == []
