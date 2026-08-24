"""Port discovery — native connect scan with an injected connector (no real sockets), plus the
HTTP-confirmation + scope gate that turns an open port into a scan root."""

from __future__ import annotations

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.discovery.ports import _candidate_url, discover_http_ports, scan_ports


def _connector(open_ports: set[int]):
    async def connect(_host: str, port: int, _timeout: float) -> bool:
        return port in open_ports

    return connect


async def test_scan_ports_returns_only_open_sorted_deduped() -> None:
    ports = await scan_ports("host.acme.com", [8080, 443, 80, 8080, 9999], connector=_connector({80, 8080}))
    assert ports == [80, 8080]


async def test_scan_ports_empty_host() -> None:
    assert await scan_ports("", [80, 443], connector=_connector({80})) == []


def test_candidate_url_scheme_and_port() -> None:
    assert _candidate_url("h", 80) == "http://h/"
    assert _candidate_url("h", 443) == "https://h/"
    assert _candidate_url("h", 8080) == "http://h:8080/"
    assert _candidate_url("h", 8443) == "https://h:8443/"


async def test_discover_http_ports_confirms_http_and_gates_scope() -> None:
    # 8080 (in scope) speaks HTTP -> a root; 9200 is open but out of scope (port not allowed) -> dropped.
    scope = ScopeConfig(allow_domains=["127.0.0.1"], allowed_ports=[80, 443, 8080])

    class _FakeResp:
        status_code = 200

    class _FakeClient(HttpClient):
        def __init__(self) -> None:
            super().__init__(scope)

        async def get(self, url: str, **_kwargs: object):  # type: ignore[override]
            return _FakeResp()

    async with _FakeClient() as client:
        roots = await discover_http_ports(client, "127.0.0.1", ports=[8080, 9200], connector=_connector({8080, 9200}))
    assert roots == ["http://127.0.0.1:8080/"]  # 9200 filtered by allowed_ports scope gate
