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
    await gov.gate(url)
    await gov.gate(url)  # 2 allowed
    with pytest.raises(EndpointCapReachedError):
        await gov.gate(url)  # 3rd over the cap
    gov.close()


async def test_daily_cap_is_per_endpoint(tmp_path) -> None:
    gov = RateGovernor(per_endpoint_daily_cap=1, daily_cap_db=str(tmp_path / "c.sqlite"))
    await gov.gate("http://t.test/a")
    await gov.gate("http://t.test/b")  # a different endpoint has its own quota
    with pytest.raises(EndpointCapReachedError):
        await gov.gate("http://t.test/a")
    gov.close()


async def test_daily_cap_persists_across_governor_instances(tmp_path) -> None:
    db = str(tmp_path / "persist.sqlite")
    url = "http://t.test/x"
    first = RateGovernor(per_endpoint_daily_cap=1, daily_cap_db=db)
    await first.gate(url)  # spends the single daily slot
    first.close()
    # A fresh run (new governor, same DB) must see the endpoint already at its cap.
    second = RateGovernor(per_endpoint_daily_cap=1, daily_cap_db=db)
    with pytest.raises(EndpointCapReachedError):
        await second.gate(url)
    second.close()


async def test_endpoint_cap_error_is_treated_as_a_skip() -> None:
    # It subclasses OutOfScopeError, so every existing 'except OutOfScopeError' skips (never aborts).
    assert issubclass(EndpointCapReachedError, OutOfScopeError)


def test_active_reflects_whether_anything_is_enforced() -> None:
    assert RateGovernor().active is False
    assert RateGovernor(per_host_rps=1.0).active is True
    assert RateGovernor(per_endpoint_daily_cap=10).active is True


async def test_per_host_bucket_gate_runs_without_error() -> None:
    gov = RateGovernor(per_host_rps=100.0)
    await gov.gate("http://a.test/x")
    await gov.gate("http://b.test/y")  # a second host gets its own bucket
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


async def test_httpclient_enforces_the_daily_cap_end_to_end(echo_server: str, tmp_path) -> None:
    gov = RateGovernor(per_endpoint_daily_cap=2, daily_cap_db=str(tmp_path / "e.sqlite"))
    async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"]), governor=gov) as client:
        assert (await client.get(f"{echo_server}/api")).status_code == 200
        assert (await client.get(f"{echo_server}/api")).status_code == 200
        with pytest.raises(OutOfScopeError):  # EndpointCapReachedError subclass — the 3rd is skipped
            await client.get(f"{echo_server}/api")
        # A different endpoint is unaffected.
        assert (await client.get(f"{echo_server}/other")).status_code == 200
