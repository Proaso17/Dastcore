"""WAF handling: the scanner must look like a browser (not python-httpx, which WAFs block on sight) and
must tell the user when a WAF blocked most requests — instead of a WAF-blocked empty scan looking clean."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.cli import _scan_interference_finding
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
    f = _scan_interference_finding("https://bank.test/", "waf", 0.9, 45, 50, 0, 0)
    assert f.rule_id == "waf-blocking" and f.severity == "info"
    assert "cf_clearance" in f.remediation and "90%" in f.evidence[0].data


def test_rate_limit_advisory_is_distinct_from_waf() -> None:
    """#12: self-inflicted rate-limiting (Vercel's per-IP limit) must NOT be reported as a WAF. It gets its
    own rule_id + a 'slow down / allowlist your IP' remediation, and names the served-then-refused onset."""
    f = _scan_interference_finding("https://app.example.com/", "rate-limit", 0.93, 3052, 3282, 40, 56)
    assert f.rule_id == "scan-rate-limited" and f.severity == "info"
    body = f.evidence[0].data.lower()
    assert "rate-limit" in body and "56" in f.evidence[0].data  # onset: served 56 ok, then refused
    assert "--rps" in f.remediation and "cf_clearance" not in f.remediation  # slow down, not a WAF bypass


def test_block_reason_rate_limit_when_429s_dominate() -> None:
    c = HttpClient(ScopeConfig(allow_domains=["x"]))
    c._response_count, c._blocked_count, c._rate_limited_count, c._successes_before_first_block = 100, 60, 60, 0
    assert c.block_reason() == "rate-limit"


def test_block_reason_rate_limit_on_late_onset() -> None:
    c = HttpClient(ScopeConfig(allow_domains=["x"]))
    # getnyma's real shape: served 56 requests fine, then 403s under sustained volume (Vercel per-IP
    # limit, all 403 not 429) — 3052/3282 refused. Not a WAF: the onset after real successes gives it away.
    c._response_count, c._blocked_count, c._rate_limited_count, c._successes_before_first_block = 3282, 3052, 0, 56
    assert c.block_reason() == "rate-limit"


def test_block_reason_waf_when_refused_from_the_start() -> None:
    c = HttpClient(ScopeConfig(allow_domains=["x"]))
    c._response_count, c._blocked_count, c._rate_limited_count, c._successes_before_first_block = 100, 90, 0, 1
    assert c.block_reason() == "waf"


def test_block_reason_none_below_threshold() -> None:
    c = HttpClient(ScopeConfig(allow_domains=["x"]))
    c._response_count, c._blocked_count, c._rate_limited_count, c._successes_before_first_block = 100, 20, 0, 0
    assert c.block_reason() == "none"


async def test_platform_internal_paths_excluded_from_block_ratio(blocking_server: str) -> None:
    """A Vercel/Next.js site's framework-internal paths 403 by default — they must not count as the app
    blocking the scan (the over-count that mislabelled getnyma.com as behind an aggressive WAF)."""
    async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"])) as client:
        await client.get(f"{blocking_server}/_next/static/chunk.js")  # platform-internal → excluded
        await client.get(f"{blocking_server}/_vercel/insights/view")  # platform-internal → excluded
        await client.get(f"{blocking_server}/real-app-path")          # app 403 → counted
    assert client.response_count == 1 and client.blocked_count == 1


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
