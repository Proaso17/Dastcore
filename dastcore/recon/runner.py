"""Recon orchestrator: run the adapters for a program's scope and persist only in-scope assets.

The scope gate runs **before anything is stored** — a discovered host that isn't in the program's
scope is dropped, never written and never probed. That is the single most important safety property of
recon (it's the easiest place to wander out of scope), so it lives in the orchestrator, not the caller.
"""

from __future__ import annotations

import time

from dastcore.core.scope import ScopeChecker
from dastcore.recon.adapters import default_adapters
from dastcore.recon.base import Adapter
from dastcore.recon.models import Asset, ReconOptions
from dastcore.recon.store import AssetStore


def _adapters_for(adapters: list[Adapter], profile: str, allow_active: bool) -> list[Adapter]:
    """Pick the adapters allowed by the profile and the program's no-automated-scanning flag."""
    chosen: list[Adapter] = []
    for adapter in adapters:
        if not adapter.passive and (profile == "passive" or not allow_active):
            continue  # active probe blocked by passive profile or a no-scan program
        chosen.append(adapter)
    return chosen


async def run_recon(
    seeds: list[str],
    opts: ReconOptions,
    store: AssetStore,
    checker: ScopeChecker,
    *,
    allow_active: bool = True,
    adapters: list[Adapter] | None = None,
) -> list[Asset]:
    """Enumerate subdomains from the seeds, probe them for liveness, and store the in-scope assets.

    Two engines behind one API. **Replay mode** (``opts.replay`` populated — tests/offline) runs the
    pure tool adapters against recorded output. **Real mode** (no replay) runs the rich ``discovery/``
    engine (multi-source passive + DNS-calibrated brute + permutations + DNS records + ports + favicon),
    so ``dastcore recon`` and ``dastcore hunt`` inherit everything the scan flow gained — one engine.
    The scope gate is identical in both paths: nothing out of scope is ever probed or stored.
    """
    if not opts.replay:
        from dastcore.recon.discovery_enum import discover_assets

        return await discover_assets(list(seeds), opts, store, checker, allow_active=allow_active)

    pool = _adapters_for(adapters or default_adapters(), opts.profile, allow_active)
    now = time.time()
    stored: list[Asset] = []
    hosts: set[str] = {h.lower().rstrip(".") for h in seeds}

    # Stage 1 — subdomain enumeration (per-seed).
    for adapter in pool:
        if adapter.stage != "subdomain":
            continue
        for asset in await adapter.collect(list(seeds), opts):
            if checker.is_asset_in_scope(asset.host):  # gate BEFORE storing
                store.upsert(asset, now)
                hosts.add(asset.host)
                stored.append(asset)

    # Stage 2 — live-host probing over every in-scope host discovered so far.
    probe_targets = sorted(hosts)
    for adapter in pool:
        if adapter.stage != "probe":
            continue
        for asset in await adapter.collect(probe_targets, opts):
            if checker.is_asset_in_scope(asset.host):
                store.upsert(asset, now)
                stored.append(asset)

    return stored
