"""Discovery-backed recon (real mode, no replay) — the bridge that gives recon/hunt the rich engine.
Offline: the passive source is monkeypatched, so no network. Validates seed normalisation, the scope
gate, and Asset shaping; the active path's components are covered by their own module tests."""

from __future__ import annotations

import dastcore.discovery.passive_sources as passive_sources
from dastcore.bugbounty import Program
from dastcore.core.scope import ScopeChecker
from dastcore.recon import AssetStore, ReconOptions, run_recon
from dastcore.recon.discovery_enum import _seed_host


def _checker() -> ScopeChecker:
    program = Program.model_validate(
        {"handle": "acme", "scope": {"domains": ["acme.com"], "wildcards": ["*.acme.com"]}, "seeds": ["acme.com"]}
    )
    return ScopeChecker(program.to_scope_config())


def test_seed_host_normalises() -> None:
    assert _seed_host("https://acme.com/path") == "acme.com"
    assert _seed_host("*.acme.com.") == "acme.com"
    assert _seed_host("  API.ACME.COM ") == "api.acme.com"


async def test_passive_profile_uses_discovery_and_gates_scope(tmp_path, monkeypatch) -> None:
    async def fake_gather(domain: str) -> set[str]:
        return {"api.acme.com", "www.acme.com", "evil.example.org"}  # last one is out of scope

    monkeypatch.setattr(passive_sources, "gather_passive_subdomains", fake_gather)
    store = AssetStore(tmp_path / "assets.db")
    stored = await run_recon(["acme.com"], ReconOptions(profile="passive"), store, _checker())
    hosts = {a.host for a in stored}
    assert {"api.acme.com", "www.acme.com", "acme.com"} <= hosts  # seed + in-scope passive names
    assert "evil.example.org" not in hosts  # scope gate dropped it
    assert all(a.source == "passive" and a.url is None for a in stored)  # passive: host only, no probe
    store.close()


async def test_no_active_program_is_passive_even_on_standard(tmp_path, monkeypatch) -> None:
    async def fake_gather(_domain: str) -> set[str]:
        return {"api.acme.com"}

    monkeypatch.setattr(passive_sources, "gather_passive_subdomains", fake_gather)
    store = AssetStore(tmp_path / "assets.db")
    # standard profile, but the program forbids active scanning -> passive branch, never probes.
    stored = await run_recon(["acme.com"], ReconOptions(profile="standard"), store, _checker(), allow_active=False)
    assert all(a.url is None for a in stored) and {"api.acme.com", "acme.com"} <= {a.host for a in stored}
    store.close()
