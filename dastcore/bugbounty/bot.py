"""BountyBot — the autonomous hunt orchestrator.

One cycle composes the pieces that already exist, reimplementing none of them: run the program's
campaign (recon → scan, scope- and RoE-enforced), triage the findings for a bounty (VRT + cross-asset
dedupe + the false-positive gate), and file each surviving candidate into the review queue as
``pending``. It never submits — there is deliberately no submit path here; advancing a candidate is a
human action on the queue. The campaign runner is injected so the orchestration is unit-testable
without a live scan (tests pass a fake that returns a fixed ``CampaignResult``).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field

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
    new_asset_hosts: list[str] = field(default_factory=list)  # hosts that appeared THIS cycle (monitoring)


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
        dedupe_assets: bool = True,
    ) -> BotCycleResult:
        """Run one full cycle: campaign → triage → file candidates as ``pending``.

        ``authorized`` carries the operator's explicit ``--i-have-authorization`` through to the engine;
        the bot never bypasses the legal gate. Scope, rate limits and attribution all come from
        ``program`` (enforced inside the campaign/scanner), so the bot adds orchestration, not new reach.
        """
        # Snapshot the known surface so we can report what recon *adds* this cycle — the signal that drives
        # continuous monitoring. A key-set diff is robust (no reliance on wall-clock timestamp resolution).
        before = {a.dedupe_key() for a in self._assets.all()}
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
            dedupe_assets=dedupe_assets,
        )
        new_hosts = sorted(
            {a.host for a in self._assets.all() if a.url and a.dedupe_key() not in before}
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
            new_asset_hosts=new_hosts,
        )

    async def run_continuous(
        self,
        program: Program,
        *,
        authorized: bool,
        interval_s: float,
        max_cycles: int | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        on_cycle: Callable[[BotCycleResult], None] | None = None,
        **run_once_kwargs: object,
    ) -> list[BotCycleResult]:
        """Run cycles forever on an interval (continuous monitoring): each cycle re-runs recon, hunts the
        newly-discovered surface, and files candidates for review. ``on_cycle`` is called after each cycle
        (drive alerts/logging from it). ``sleep`` and ``max_cycles`` are injected so tests drive it
        deterministically without wall-clock waits; ``max_cycles=None`` runs until cancelled (the CLI).

        Efficiency comes from the caller passing a persistent ``checkpoint_path`` in ``run_once_kwargs``:
        already-scanned assets are skipped, so after the first cycle only genuinely new surface is scanned.
        """
        results: list[BotCycleResult] = []
        cycle = 0
        while max_cycles is None or cycle < max_cycles:
            result = await self.run_once(program, authorized=authorized, **run_once_kwargs)  # type: ignore[arg-type]
            results.append(result)
            if on_cycle is not None:
                on_cycle(result)
            cycle += 1
            if max_cycles is not None and cycle >= max_cycles:
                break
            await sleep(interval_s)
        return results
