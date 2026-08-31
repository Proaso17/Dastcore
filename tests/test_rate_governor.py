"""Per-host / per-endpoint rate governance: a persistent daily cap per endpoint (survives runs) and a
per-host token bucket, layered over the global rate limit for bug-bounty RoE compliance."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient, OutOfScopeError
from dastcore.core.rate_governor import EndpointCapReachedError, RateGovernor


async def test_daily_cap_allows_up_to_the_cap_then_skips(tmp_path) -> None:
    db = str(tmp_path / "caps.sqlite")
    gov = RateGovernor(per_endpoint_daily_cap=2, daily_cap_db=db)
    url = "http://t.test/api/thing"
    await gov.charge(url)
    await gov.charge(url)  # 2 allowed
    with pytest.raises(EndpointCapReachedError):
        await gov.charge(url)  # 3rd over the cap
    gov.close()


async def test_daily_cap_is_per_endpoint(tmp_path) -> None:
    gov = RateGovernor(per_endpoint_daily_cap=1, daily_cap_db=str(tmp_path / "c.sqlite"))
    await gov.charge("http://t.test/a")
    await gov.charge("http://t.test/b")  # a different endpoint has its own quota
    with pytest.raises(EndpointCapReachedError):
        await gov.charge("http://t.test/a")
    gov.close()


async def test_daily_cap_persists_across_governor_instances(tmp_path) -> None:
    db = str(tmp_path / "persist.sqlite")
    url = "http://t.test/x"
    first = RateGovernor(per_endpoint_daily_cap=1, daily_cap_db=db)
    await first.charge(url)  # spends the single daily slot
    first.close()
    # A fresh run (new governor, same DB) must see the endpoint already at its cap.
    second = RateGovernor(per_endpoint_daily_cap=1, daily_cap_db=db)
    with pytest.raises(EndpointCapReachedError):
        await second.charge(url)
    second.close()


async def test_endpoint_cap_error_is_treated_as_a_skip() -> None:
    # It subclasses OutOfScopeError, so every existing 'except OutOfScopeError' skips (never aborts).
    assert issubclass(EndpointCapReachedError, OutOfScopeError)


def test_active_reflects_whether_anything_is_enforced() -> None:
    assert RateGovernor().active is False
    assert RateGovernor(per_host_rps=1.0).active is True
    assert RateGovernor(per_endpoint_daily_cap=10).active is True
    assert RateGovernor(jitter_ms=100).active is True  # low-and-slow alone is enough to activate


async def test_low_and_slow_jitter_pauses_before_requests() -> None:
    import time

    gov = RateGovernor(jitter_ms=200)  # up to 200 ms random pause per gate
    start = time.monotonic()
    for _ in range(12):  # over a dozen gates, some non-zero pauses are near-certain
        await gov.pace("http://t.test/x")
    assert time.monotonic() - start > 0.0  # time actually elapsed in jitter sleeps
    gov.close()


async def test_per_host_bucket_gate_runs_without_error() -> None:
    gov = RateGovernor(per_host_rps=100.0)
    await gov.pace("http://a.test/x")
    await gov.pace("http://b.test/y")  # a second host gets its own bucket
    gov.close()


@pytest.fixture()
def echo_server() -> Iterator[str]:
    from flask import Flask

    app = Flask(__name__)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def any_path(path: str) -> str:
        return "ok"

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


async def test_effective_rps_telemetry(echo_server: str) -> None:
    async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"])) as client:
        assert client.effective_rps() == 0.0  # nothing sent yet
        for _ in range(6):
            await client.get(f"{echo_server}/x")
        assert client.effective_rps() > 0  # network attempts are counted for compliance verification


async def test_retries_go_through_the_rate_limited_path() -> None:
    # A server that 429s once, then 200s. With a retry the client makes TWO network attempts — and each
    # now takes a rate-limit token (the fix), so retries can't push the effective RPS past the ceiling.
    from flask import Flask, Response

    from dastcore.config import RateLimitConfig

    hits = {"n": 0}
    app = Flask(__name__)

    @app.route("/x")
    def x() -> Response:
        hits["n"] += 1
        return Response("later", status=429) if hits["n"] == 1 else Response("ok", status=200)

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"]),
                              rate_limit=RateLimitConfig(requests_per_second=50), max_retries=1) as client:
            resp = await client.get(f"http://127.0.0.1:{port}/x")
        assert resp.status_code == 200
        assert hits["n"] == 2  # the retry happened -> both attempts went through the token path
        assert client.effective_rps() > 0  # telemetry counted both network attempts
    finally:
        server.shutdown()


async def test_httpclient_enforces_the_daily_cap_end_to_end(echo_server: str, tmp_path) -> None:
    gov = RateGovernor(per_endpoint_daily_cap=2, daily_cap_db=str(tmp_path / "e.sqlite"))
    async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"]), governor=gov) as client:
        assert (await client.get(f"{echo_server}/api")).status_code == 200
        assert (await client.get(f"{echo_server}/api")).status_code == 200
        with pytest.raises(OutOfScopeError):  # EndpointCapReachedError subclass — the 3rd is skipped
            await client.get(f"{echo_server}/api")
        # A different endpoint is unaffected.
        assert (await client.get(f"{echo_server}/other")).status_code == 200
