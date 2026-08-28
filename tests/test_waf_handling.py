"""WAF handling: the scanner must look like a browser (not python-httpx, which WAFs block on sight) and
must tell the user when a WAF blocked most requests — instead of a WAF-blocked empty scan looking clean."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.cli import _waf_blocking_finding
from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient


def _serve(status: int) -> tuple[str, object]:
    from flask import Flask, Response

    app = Flask(__name__)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def any_path(path: str) -> Response:
        return Response("blocked" if status == 403 else "ok", status=status)

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def blocking_server() -> Iterator[str]:
    url, server = _serve(403)
    yield url
    server.shutdown()


def test_default_user_agent_is_a_real_browser() -> None:
    client = HttpClient(ScopeConfig(allow_domains=["x"]))
    ua = client._client.headers.get("user-agent", "")
    assert "python-httpx" not in ua and "Mozilla/5.0" in ua and "Chrome/" in ua


def test_custom_user_agent_overrides_default() -> None:
    client = HttpClient(ScopeConfig(allow_domains=["x"]), user_agent="MyRealBrowser/9.9")
    assert client._client.headers.get("user-agent") == "MyRealBrowser/9.9"


async def test_waf_block_ratio_counts_403s(blocking_server: str) -> None:
    async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"])) as client:
        for path in ("a", "b", "c", "d"):
            await client.get(f"{blocking_server}/{path}")
    assert client.response_count == 4 and client.blocked_count == 4
    assert client.waf_block_ratio() == 1.0


def test_waf_blocking_advisory_is_info_with_bypass_guidance() -> None:
    f = _waf_blocking_finding("https://bank.test/", 0.9, 45, 50)
    assert f.rule_id == "waf-blocking" and f.severity == "info"
    assert "cf_clearance" in f.remediation and "90%" in f.evidence[0].data


def test_scanfile_accepts_proxy_and_user_agent() -> None:
    from dastcore.config import ScanFile

    sf = ScanFile.model_validate(
        {"target": "https://x.test/", "proxy": "socks5://127.0.0.1:1080", "user_agent": "UA/1"}
    )
    assert sf.proxy == "socks5://127.0.0.1:1080" and sf.user_agent == "UA/1"


def test_http_client_and_headless_accept_proxy() -> None:
    from dastcore.config import ScopeConfig
    from dastcore.discovery.crawler_headless import HeadlessEngine

    HttpClient(ScopeConfig(allow_domains=["x"]), proxy="http://127.0.0.1:8080")  # constructs, no error
    engine = HeadlessEngine(ScopeConfig(allow_domains=["x"]), proxy="http://127.0.0.1:8080")
    assert engine._proxy == "http://127.0.0.1:8080"
