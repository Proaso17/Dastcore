"""Subdomain discovery: DNS brute force + wildcard calibration, gated hard by scope.
Fully offline — the resolver and prober are injected, so no DNS or HTTP actually happens."""

from __future__ import annotations

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpResponse
from dastcore.discovery.subdomains import SubdomainDiscoverer, load_subdomain_wordlist


def _page(status: int, body: str) -> HttpResponse:
    return HttpResponse(method="GET", status_code=status, text=body, url="http://t/")


def _resolver(mapping: dict[str, list[str]]):
    async def resolve(host: str) -> list[str]:
        return mapping.get(host, [])

    return resolve


def _prober(pages: dict[str, HttpResponse]):
    async def probe(host: str):
        resp = pages.get(host)
        return (f"http://{host}/", resp) if resp is not None else None

    return probe


async def test_discovers_resolving_alive_subdomains() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], allow_subdomains=True)
    resolver = _resolver({
        "example.com": ["10.0.0.1"],
        "api.example.com": ["10.0.0.2"],
        "dev.example.com": ["10.0.0.3"],
        # random wildcard-probe name is absent -> not a wildcard domain
    })
    prober = _prober({
        "example.com": _page(200, "home"),
        "api.example.com": _page(200, "api root"),
        "dev.example.com": _page(200, "dev"),
    })
    async with HttpClient(scope) as client:
        disc = SubdomainDiscoverer(
            client, wordlist=["api", "dev", "nope"], resolver=resolver, prober=prober,
            use_passive=False, use_external=False,
        )
        found = await disc.discover("example.com")

    hosts = {h.host for h in found}
    assert hosts == {"example.com", "api.example.com", "dev.example.com"}  # "nope" didn't resolve


async def test_out_of_scope_subdomains_are_never_probed() -> None:
    # allow_subdomains disabled -> only the apex is in scope; subdomains must be dropped before probing
    scope = ScopeConfig(allow_domains=["example.com"], allow_subdomains=False)
    probed: list[str] = []

    async def prober(host: str):
        probed.append(host)
        return (f"http://{host}/", _page(200, "x"))

    resolver = _resolver({"example.com": ["10.0.0.1"], "api.example.com": ["10.0.0.2"]})
    async with HttpClient(scope) as client:
        disc = SubdomainDiscoverer(
            client, wordlist=["api"], resolver=resolver, prober=prober, use_passive=False, use_external=False
        )
        found = await disc.discover("example.com")

    assert {h.host for h in found} == {"example.com"}
    assert "api.example.com" not in probed  # scope gate ran before any probe


async def test_wildcard_dns_does_not_invent_hosts() -> None:
    # every name resolves (wildcard) and most serve the same default page; only a distinct host counts
    scope = ScopeConfig(allow_domains=["example.com"], allow_subdomains=True)

    async def resolver(host: str) -> list[str]:
        return ["10.0.0.9"]  # everything resolves -> wildcard

    default = _page(200, "WELCOME default vhost page " * 5)
    pages = {
        "admin.example.com": _page(200, "ADMIN CONTROL PANEL — totally different body, much longer " * 8),
    }

    async def prober(host: str):
        return (f"http://{host}/", pages.get(host, default))

    async with HttpClient(scope) as client:
        disc = SubdomainDiscoverer(
            client, wordlist=["admin", "www", "dev"], resolver=resolver, prober=prober,
            use_passive=False, use_external=False,
        )
        found = await disc.discover("example.com")

    assert {h.host for h in found} == {"admin.example.com"}  # www/dev/apex were just the wildcard page


def test_wordlist_depth_slicing() -> None:
    light = load_subdomain_wordlist("light")
    aggressive = load_subdomain_wordlist("aggressive")
    assert 0 < len(light) <= 50 < len(aggressive)
    assert light == aggressive[: len(light)]  # light is a prefix of the full list
