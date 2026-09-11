"""BountyBot — the autonomous hunt orchestrator.

One cycle composes the pieces that already exist, reimplementing none of them: run the program's
campaign (recon → scan, scope- and RoE-enforced), triage the findings for a bounty (VRT + cross-asset
dedupe + the false-positive gate), and file each surviving candidate into the review queue as
``pending``. It never submits — there is deliberately no submit path here; advancing a candidate is a
human action on the queue. The campaign runner is injected so the orchestration is unit-testable
without a live scan (tests pass a fake that returns a fixed ``CampaignResult``).
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

from dastcore.bugbounty.campaign import CampaignResult, run_campaign
from dastcore.bugbounty.program import Program
from dastcore.bugbounty.queue import ReviewQueue
from dastcore.bugbounty.triage import triage_for_bounty
from dastcore.core.models import Finding
from dastcore.recon import AssetStore, ReconOptions

# A campaign runner has run_campaign's shape; injected so tests can substitute a fake (no live scan).
CampaignRunner = Callable[..., Awaitable[CampaignResult]]


@dataclass
class BotCycleResult:
    """What one bot cycle did — surfaced to the CLI/web and used to drive continuous runs (P1)."""

    assets: int            # assets known after this cycle's recon
    scanned: int           # assets actively scanned this cycle
    findings: int          # raw findings the scan produced
    candidates: int        # triaged submission candidates (deduped, FP-gated, VRT-rated)
    new_candidates: int    # candidates not previously in the queue (genuinely new to review)
    pending: int           # total candidates awaiting human review for this program


class BountyBot:
    """Runs authorized hunt cycles for a program and files candidates for human review. Never submits."""

    def __init__(
        self,
        asset_store: AssetStore,
        review_queue: ReviewQueue,
        *,
        campaign_runner: CampaignRunner = run_campaign,
    ) -> None:
        self._assets = asset_store
        self._queue = review_queue
        self._run_campaign = campaign_runner

    async def run_once(
        self,
        program: Program,
        *,
        authorized: bool,
        recon_opts: ReconOptions | None = None,
        engine: str = "http",
        max_pages: int = 200,
        checkpoint_path: str | None = None,
        on_status: Callable[[str], None] | None = None,
        on_finding: Callable[[Finding], None] | None = None,
        discover_depth: str = "light",
        seed_paths: Sequence[str] = (),
        discover_ports: bool = False,
        discover_vhosts: bool = False,
        osint: bool = False,
        screenshots: bool = False,
    ) -> BotCycleResult:
        """Run one full cycle: campaign → triage → file candidates as ``pending``.

        ``authorized`` carries the operator's explicit ``--i-have-authorization`` through to the engine;
        the bot never bypasses the legal gate. Scope, rate limits and attribution all come from
        ``program`` (enforced inside the campaign/scanner), so the bot adds orchestration, not new reach.
        """
        result = await self._run_campaign(
            program,
            authorized=authorized,
            asset_store=self._assets,
            recon_opts=recon_opts,
            engine=engine,
            max_pages=max_pages,
            checkpoint_path=checkpoint_path,
            on_status=on_status,
            on_finding=on_finding,
            discover_depth=discover_depth,
            seed_paths=seed_paths,
            discover_ports=discover_ports,
            discover_vhosts=discover_vhosts,
            osint=osint,
            screenshots=screenshots,
        )
        candidates = triage_for_bounty(result.findings, program)
        now = time.time()
        new = sum(1 for bf in candidates if self._queue.upsert_candidate(program.handle, bf, now))
        return BotCycleResult(
            assets=len(result.assets),
            scanned=len(result.scanned),
            findings=len(result.findings),
            candidates=len(candidates),
            new_candidates=new,
            pending=self._queue.counts(program.handle).get("pending", 0),
        )
