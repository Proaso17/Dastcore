"""Discovery-backed asset enumeration — the bridge that lets the recon/hunt flows reuse the rich
``discovery/`` engine instead of the thin adapter set.

``recon/`` historically enumerated the surface with a handful of tool adapters (crt.sh, subfinder,
httpx). The scan flow, meanwhile, grew a far richer engine in ``discovery/`` — multi-source passive
subdomains, DNS-calibrated brute force, permutations, DNS records, native port discovery, favicon
fingerprinting. This module runs *that* engine and shapes its output into the ``Asset`` model the
recon store and the hunt pipeline already speak, so ``dastcore recon`` and ``dastcore hunt`` inherit
everything the scan flow gained — one engine, not two.

Profile-scaled (and scope-safe):

- ``passive`` **or a no-active-scanning program** — only passive sources (CT logs, passive DNS, URL
  archives, cert SANs). No traffic to the target; assets have a host but no URL.
- ``standard`` — passive + DNS brute force, live-host probing, DNS records (IP), favicon (tech).
- ``deep`` — standard + subdomain permutations, recursion, and native port discovery (extra services).

Every host is scope-gated by the store's ``ScopeChecker`` before it is probed or stored, exactly as the
adapter path was.
"""

from __future__ import annotations

import time
from urllib.parse import urlsplit

from dastcore.core.http_client import HttpClient
from dastcore.core.scope import ScopeChecker
from dastcore.recon.models import Asset, ReconOptions
from dastcore.recon.store import AssetStore

# Recon profile -> discovery depth (drives wordlist size, recursion, permutations, ports).
_PROFILE_DEPTH = {"passive": "light", "standard": "balanced", "deep": "aggressive"}


def _seed_host(seed: str) -> str:
    """Normalise a seed (``acme.com``, ``https://acme.com/``, ``127.0.0.1``) to a bare host."""
    seed = seed.strip()
    if "://" in seed:
        seed = urlsplit(seed).hostname or ""
    return seed.lower().lstrip("*.").rstrip(".")


async def discover_assets(
    seeds: list[str], opts: ReconOptions, store: AssetStore, checker: ScopeChecker, *, allow_active: bool
) -> list[Asset]:
    """Enumerate the program's surface with the ``discovery/`` engine and persist in-scope ``Asset``s."""
    from dastcore.discovery.passive_sources import gather_passive_subdomains

    now = time.time()
    depth = _PROFILE_DEPTH.get(opts.profile, "balanced")
    hosts = [h for h in dict.fromkeys(_seed_host(s) for s in seeds) if h]
    stored: list[Asset] = []

    # Passive-only: gather names from public sources, never touch the target. Assets get a host, no URL.
    if not allow_active or opts.profile == "passive":
        names: set[str] = set()
        for host in hosts:
            try:
                names |= await gather_passive_subdomains(host)
            except Exception:  # noqa: BLE001 — a source failing must not abort enumeration
                continue
        names |= set(hosts)
        for name in sorted(names):
            if checker.is_asset_in_scope(name):
                asset = Asset(host=name, source="passive")
                store.upsert(asset, now)
                stored.append(asset)
        return stored

    # Active: the full discovery engine (probes live hosts) + record/port/tech enrichment.
    from dastcore.discovery.dns_records import gather_dns_records
    from dastcore.discovery.favicon import probe_favicon
    from dastcore.discovery.permutations import load_permutation_words
    from dastcore.discovery.ports import discover_http_ports
    from dastcore.discovery.subdomains import (
        SubdomainDiscoverer,
        load_subdomain_wordlist,
        subdomain_recursion_depth,
    )

    deep = depth == "aggressive"
    words = load_subdomain_wordlist(depth)
    async with HttpClient(checker.scope, timeout=8.0, max_retries=0) as client:
        found: dict[str, str] = {}  # host -> live URL
        for host in hosts:
            for discovered in await SubdomainDiscoverer(
                client,
                wordlist=words,
                seeds=[host],
                recursion_depth=subdomain_recursion_depth(depth),
                use_passive=True,
                use_external=True,
                use_permutations=deep,
                permutation_words=load_permutation_words() if deep else [],
            ).discover(host):
                found.setdefault(discovered.host, discovered.url)

        in_scope = {h: url for h, url in found.items() if checker.is_asset_in_scope(h)}
        records = await gather_dns_records(list(in_scope))
        for host, url in sorted(in_scope.items()):
            record_set = records.get(host)
            ip = record_set.a[0] if record_set and record_set.a else None
            favicon = await probe_favicon(client, url)
            tech = [favicon.product] if favicon and favicon.product else []
            asset = Asset(host=host, url=url, ip=ip, port=urlsplit(url).port, tech=tech, source="discovery")
            store.upsert(asset, now)
            stored.append(asset)

            # Deep: native port scan surfaces extra HTTP services (8080, 8443, 9200…) as their own assets.
            if deep:
                for port_url in await discover_http_ports(client, host):
                    if port_url == url:
                        continue
                    extra = Asset(host=host, url=port_url, ip=ip, port=urlsplit(port_url).port, source="ports")
                    store.upsert(extra, now)
                    stored.append(extra)

    return stored
