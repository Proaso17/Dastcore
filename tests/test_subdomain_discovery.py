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


async def test_passive_source_hosts_are_probed_and_scope_gated() -> None:
    # A host found only via a passive source (injected) is still resolved, probed, and scope-gated:
    # an in-scope one is discovered; an out-of-scope one is never probed.
    scope = ScopeConfig(allow_domains=["example.com"], allow_subdomains=True)
    resolver = _resolver({"example.com": ["10.0.0.1"], "hidden.example.com": ["10.0.0.9"]})
    prober = _prober({"example.com": _page(200, "home"), "hidden.example.com": _page(200, "secret admin")})

    async def gather(domain: str) -> set[str]:
        return {"hidden.example.com", "out.evil.com"}  # evil.com is out of scope

    async with HttpClient(scope) as client:
        disc = SubdomainDiscoverer(
            client, wordlist=[], resolver=resolver, prober=prober,
            use_passive=True, use_external=False, passive_gather=gather,
        )
        found = await disc.discover("example.com")

    hosts = {h.host for h in found}
    assert "hidden.example.com" in hosts  # discovered only via the passive source
    assert "out.evil.com" not in hosts    # out of scope -> never probed


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


async def test_recursive_discovery_finds_nested_subdomains() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], allow_subdomains=True)
    resolver = _resolver({
        "example.com": ["10.0.0.1"],
        "api.example.com": ["10.0.0.2"],
        "v2.api.example.com": ["10.0.0.3"],  # only reachable by recursing INTO api.example.com
    })
    prober = _prober({h: _page(200, h) for h in ("example.com", "api.example.com", "v2.api.example.com")})

    async with HttpClient(scope) as client:
        deep = SubdomainDiscoverer(
            client, wordlist=["api", "v2"], resolver=resolver, prober=prober,
            use_passive=False, use_external=False, recursion_depth=1,
        )
        found_deep = {h.host for h in await deep.discover("example.com")}
        flat = SubdomainDiscoverer(
            client, wordlist=["api", "v2"], resolver=resolver, prober=prober,
            use_passive=False, use_external=False, recursion_depth=0,
        )
        found_flat = {h.host for h in await flat.discover("example.com")}

    assert found_deep == {"example.com", "api.example.com", "v2.api.example.com"}  # recursion reached v2.api
    assert "v2.api.example.com" not in found_flat  # ...but a flat sweep never does
    assert "api.example.com" in found_flat


async def test_manual_seed_host_is_always_probed_and_scanned() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], allow_subdomains=True)
    # the seed isn't a wordlist word and only it resolves — a host the user already knows about
    resolver = _resolver({"secret.example.com": ["10.0.0.9"]})
    prober = _prober({"secret.example.com": _page(200, "secret internal app")})

    async with HttpClient(scope) as client:
        disc = SubdomainDiscoverer(
            client, wordlist=["www", "api"], resolver=resolver, prober=prober,
            use_passive=False, use_external=False, seeds=["secret.example.com"],
        )
        found = {h.host for h in await disc.discover("example.com")}

    assert "secret.example.com" in found  # the manual seed was included, probed and discovered


def test_generate_permutations() -> None:
    from dastcore.discovery.permutations import generate_permutations

    perms = generate_permutations({"api.example.com"}, "example.com", ["dev"])
    assert "api-dev.example.com" in perms
    assert "dev-api.example.com" in perms
    assert "dev.example.com" in perms  # environment swap
    assert "api2.example.com" in perms  # number suffix
    assert "api.example.com" not in perms  # never re-emit the input host


async def test_permutation_wave_finds_mutated_subdomains() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], allow_subdomains=True)
    resolver = _resolver({
        "example.com": ["10.0.0.1"],
        "api.example.com": ["10.0.0.2"],
        "api-dev.example.com": ["10.0.0.3"],  # only reachable by mutating the found "api"
    })
    prober = _prober({h: _page(200, h) for h in ("example.com", "api.example.com", "api-dev.example.com")})

    async with HttpClient(scope) as client:
        with_perm = SubdomainDiscoverer(
            client, wordlist=["api"], resolver=resolver, prober=prober,
            use_passive=False, use_external=False, use_permutations=True, permutation_words=["dev"],
        )
        found_perm = {h.host for h in await with_perm.discover("example.com")}
        without = SubdomainDiscoverer(
            client, wordlist=["api"], resolver=resolver, prober=prober,
            use_passive=False, use_external=False, use_permutations=False,
        )
        found_flat = {h.host for h in await without.discover("example.com")}

    assert found_perm == {"example.com", "api.example.com", "api-dev.example.com"}  # permutation reached api-dev
    assert "api-dev.example.com" not in found_flat  # ...which a flat sweep never does


def test_wordlist_depth_slicing() -> None:
    light = load_subdomain_wordlist("light")
    aggressive = load_subdomain_wordlist("aggressive")
    assert 0 < len(light) <= 50 < len(aggressive)
    assert light == aggressive[: len(light)]  # light is a prefix of the full list
