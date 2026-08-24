"""Virtual-host discovery — offline via a fake client keyed on the Host header. Verifies the baseline
calibration (catch-all can't manufacture hits), the distinct-page detection, and the scope gate on the
Host value itself."""

from __future__ import annotations

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpResponse
from dastcore.discovery.subdomains import DiscoveredHost
from dastcore.discovery.vhosts import VhostDiscoverer, vhost_findings

_DEFAULT = "<html>default site</html>"
_PANELS = {
    "admin.acme.com": "<html>internal admin panel — login</html>",
    "staging.acme.com": "<html>staging environment build 42 xyzzy</html>",
}


class _FakeClient(HttpClient):
    """Serves a distinct page for a couple of known Host values, the default page for everything else."""

    def __init__(self, scope: ScopeConfig) -> None:
        super().__init__(scope)

    async def get(self, url: str, **kwargs: object) -> HttpResponse:  # type: ignore[override]
        headers = kwargs.get("headers") or {}
        host = str(headers.get("Host", "")).lower() if isinstance(headers, dict) else ""
        if host in _PANELS:  # a real vhost answers 200 with its page; unknown Host -> the default 404
            return HttpResponse(status_code=200, url=url, text=_PANELS[host])
        return HttpResponse(status_code=404, url=url, text=_DEFAULT)


async def test_finds_scope_gated_vhosts_and_ignores_default() -> None:
    scope = ScopeConfig(allow_domains=["acme.com", "127.0.0.1"])
    candidates = ["admin.acme.com", "staging.acme.com", "www.acme.com", "evil.example.org"]
    async with _FakeClient(scope) as client:
        found = await VhostDiscoverer(client, candidates=candidates).discover("http://127.0.0.1/")
    hosts = {h.host for h in found}
    # admin + staging serve distinct pages; www serves the default (not a hit); evil is out of scope.
    assert hosts == {"admin.acme.com", "staging.acme.com"}
    assert all(h.source == "vhost" for h in found)


async def test_catch_all_server_yields_no_vhosts() -> None:
    # A server that returns the same page for every Host (including the random baseline) manufactures nothing.
    class _CatchAll(HttpClient):
        async def get(self, url: str, **_kwargs: object) -> HttpResponse:  # type: ignore[override]
            return HttpResponse(status_code=200, url=url, text=_DEFAULT)

    async with _CatchAll(ScopeConfig(allow_domains=["acme.com", "127.0.0.1"])) as client:
        found = await VhostDiscoverer(client, candidates=["admin.acme.com"]).discover("http://127.0.0.1/")
    assert found == []


def test_vhost_findings_carry_host_and_are_info() -> None:
    found = [DiscoveredHost(host="admin.acme.com", url="http://127.0.0.1/", status_code=200, source="vhost")]
    findings = vhost_findings("http://127.0.0.1/", found)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "virtual-host" and f.severity == "info"
    assert f.request.headers.get("Host") == "admin.acme.com" and "admin.acme.com" in f.evidence[0].data
