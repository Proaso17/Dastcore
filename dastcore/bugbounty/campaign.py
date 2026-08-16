"""The hunt pipeline: recon -> scan -> aggregate, governed by a bug-bounty ``Program``.

It reuses the existing engine end to end — ``run_recon`` for surface discovery and the CLI's
``_run_scan`` for the actual scanning — so nothing is reimplemented. Two safety rules are enforced
here: every live asset is re-checked against the program scope before it is scanned, and a program
that forbids automated scanning gets recon only (no active scan). The run is **resumable**: a per-asset
checkpoint means an interrupted hunt continues without rescanning what's already done.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from dastcore.bugbounty.program import Program
from dastcore.cli import _Budget, _run_scan
from dastcore.core.models import Finding
from dastcore.core.scope import ScopeChecker
from dastcore.recon import Asset, AssetStore, ReconOptions, run_recon


class CampaignCheckpoint:
    """Per-asset resume state: which asset URLs are scanned, and the findings gathered so far."""

    def __init__(self, path: str | Path | None) -> None:
        self._path = Path(path) if path else None
        self._done: set[str] = set()
        self._findings: list[Finding] = []
        if self._path and self._path.exists():
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self._done = set(data.get("done", []))
            self._findings = [Finding.model_validate(item) for item in data.get("findings", [])]

    def is_done(self, key: str) -> bool:
        return key in self._done

    def mark_done(self, key: str, findings: list[Finding]) -> None:
        self._done.add(key)
        self._findings.extend(findings)

    def findings(self) -> list[Finding]:
        return list(self._findings)

    def save(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"done": sorted(self._done), "findings": [f.model_dump(mode="json") for f in self._findings]}
        self._path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


@dataclass
class CampaignResult:
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    scanned: list[str] = field(default_factory=list)  # asset URLs actually scanned this run


async def run_campaign(
    program: Program,
    *,
    authorized: bool,
    asset_store: AssetStore,
    recon_opts: ReconOptions | None = None,
    engine: str = "http",
    max_pages: int = 200,
    checkpoint_path: str | Path | None = None,
    adapters: list | None = None,
) -> CampaignResult:
    """Discover the program's live in-scope surface and scan it. Recon-only if scanning is forbidden."""
    checker = ScopeChecker(program.to_scope_config())
    opts = recon_opts or ReconOptions()

    await run_recon(
        program.seeds,
        opts,
        asset_store,
        checker,
        allow_active=program.allows_active_scanning(),
        adapters=adapters,
    )
    assets = asset_store.all()

    # A program that forbids automated scanning gets recon + manual validation only.
    if not program.allows_active_scanning():
        return CampaignResult(assets=assets, findings=[], scanned=[])

    checkpoint = CampaignCheckpoint(checkpoint_path)
    budget = _Budget(None, None)
    scanned: list[str] = []
    for asset in asset_store.live():
        url = asset.url
        if not url or not checker.is_in_scope(url):  # scope re-checked before we ever scan
            continue
        if checkpoint.is_done(url):
            continue  # resume: already scanned in a previous run
        found = await _run_scan(program.to_scan_config(url, authorized=authorized), max_pages, engine, budget=budget)
        checkpoint.mark_done(url, found)
        checkpoint.save()
        scanned.append(url)

    return CampaignResult(assets=assets, findings=checkpoint.findings(), scanned=scanned)


def finding_hosts(findings: list[Finding]) -> set[str]:
    """The distinct hosts a set of findings came from (used to assert only in-scope was touched)."""
    return {urlsplit(f.request.url).hostname or "" for f in findings}
