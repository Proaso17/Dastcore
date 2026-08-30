"""Bug-bounty attribution header: many programs require an identifying header on every request. It must
actually be sent on in-scope traffic, and the program auto-derives X-Bug-Bounty from platform+handle."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.bugbounty.program import Program, ProgramScope
from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.web.app import _parse_headers, _program_from_form


@pytest.fixture(scope="module")
def echo_server() -> Iterator[str]:
    from flask import Flask, jsonify, request

    app = Flask(__name__)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def echo(path: str):
        return jsonify({k.lower(): v for k, v in request.headers.items()})

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


async def test_attribution_header_is_sent_on_every_request(echo_server: str) -> None:
    async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"]),
                          attribution={"X-Bug-Bounty": "HackerOne-migon"}) as client:
        resp = await client.get(echo_server + "/")
    import json
    assert json.loads(resp.text).get("x-bug-bounty") == "HackerOne-migon"


def test_program_auto_derives_x_bug_bounty() -> None:
    p = Program(handle="migon", platform="hackerone", scope=ProgramScope(wildcards=["*.x.mx"]))
    assert p.attribution_headers() == {"X-Bug-Bounty": "hackerone-migon"}
    # A private "self" target gets no attribution header by default.
    assert Program(handle="mine", platform="self").attribution_headers() == {}
    # An explicit required_headers wins.
    p2 = Program(handle="x", platform="hackerone", required_headers={"X-Custom": "v"})
    assert p2.attribution_headers() == {"X-Custom": "v"}


def test_parse_headers_accepts_colon_and_equals() -> None:
    assert _parse_headers("X-Bug-Bounty: HackerOne-migon\nX-Custom=abc") == {
        "X-Bug-Bounty": "HackerOne-migon", "X-Custom": "abc",
    }


def test_form_required_headers_reach_the_program() -> None:
    p = _program_from_form("bp", "hackerone", "*.bp.mx", "", allow_active=True,
                           required_headers="X-Bug-Bounty: HackerOne-migon")
    assert p.required_headers == {"X-Bug-Bounty": "HackerOne-migon"}
