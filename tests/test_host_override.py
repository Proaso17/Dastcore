"""HttpClient virtual-host override — a request for a name that isn't in DNS connects to the given IP
while the Host header keeps the real name, and scope is still enforced on the real name."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient, OutOfScopeError


def _echo_host_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/")
    def root() -> Response:
        return Response(f"host={request.headers.get('Host', '')}", mimetype="text/plain")

    return app


@pytest.fixture(scope="module")
def server() -> Iterator[int]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = make_server("127.0.0.1", port, _echo_host_app(), threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port
    srv.shutdown()


def test_apply_host_override_rewrites_connection_only() -> None:
    client = HttpClient(ScopeConfig(allow_domains=["acme.com"]), host_overrides={"vhost.acme.com": "127.0.0.1"})
    send_url, headers, ext = client._apply_host_override("https://vhost.acme.com:8443/a?b=1", {"X": "y"})
    assert send_url == "https://127.0.0.1:8443/a?b=1"
    assert headers is not None and headers["Host"] == "vhost.acme.com:8443" and headers["X"] == "y"
    assert ext == {"sni_hostname": "vhost.acme.com"}
    # A host with no override is untouched.
    assert client._apply_host_override("https://acme.com/", None) == ("https://acme.com/", None, None)


async def test_overridden_request_hits_ip_but_sends_real_host(server: int) -> None:
    # 'panel.acme.com' does not resolve; the override routes it to 127.0.0.1 while Host stays the vhost.
    scope = ScopeConfig(allow_domains=["acme.com"], allowed_ports=[server])
    async with HttpClient(scope) as client:
        client.add_host_override("panel.acme.com", "127.0.0.1")
        resp = await client.get(f"http://panel.acme.com:{server}/")
    assert resp.status_code == 200
    assert resp.text == f"host=panel.acme.com:{server}"  # server saw the vhost name, not the IP
    assert resp.url == f"http://panel.acme.com:{server}/"  # identity preserved for the scanner


async def test_override_still_enforces_scope_on_real_name(server: int) -> None:
    # The override target is 127.0.0.1, but scope is checked on the real name, which is NOT in scope.
    async with HttpClient(ScopeConfig(allow_domains=["acme.com"], allowed_ports=[server])) as client:
        client.add_host_override("evil.example.org", "127.0.0.1")
        with pytest.raises(OutOfScopeError):
            await client.get(f"http://evil.example.org:{server}/")
