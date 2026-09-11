"""BountyBot orchestration: one cycle runs campaign → triage → queue, files candidates as ``pending``,
dedups across cycles, preserves a human's decision, and has no path to submit anything. The campaign
runner is injected with a fake so this tests the wiring without a live scan."""

from __future__ import annotations

import time

from dastcore.bugbounty.bot import BountyBot
from dastcore.bugbounty.campaign import CampaignResult
from dastcore.bugbounty.program import Program
from dastcore.bugbounty.queue import ReviewQueue
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.recon import Asset, AssetStore


def _finding(family: str, host: str, param: str) -> Finding:
    req = HttpRequest(method="GET", url=f"https://{host}/p?{param}=x", params={param: "x"})
    point = InjectionPoint(location="query", name=param, base_value="x", request_template=req)
    return Finding(
        id=f"{family}:{host}:{param}", rule_id=f"{family}-x", name=f"{family} on {host}", severity="high",
        cwe="CWE-89", owasp="WSTG-INPV-05", injection_point=point,
        evidence=[Evidence(type="differential", data="confirmed", confidence="high")],
        request=req, response=HttpResponse(status_code=500, url=req.url), remediation="fix", family=family,
    )


def _asset(host: str) -> Asset:
    return Asset(host=host, url=f"https://{host}", source="crtsh")


class _FakeCampaign:
    """Stands in for run_campaign: upserts its assets into the store (as recon would), returns fixed
    findings, and records the kwargs it was called with. ``asset_waves`` feeds a different surface per
    cycle (the last wave repeats) so continuous monitoring can be driven deterministically."""

    def __init__(self, findings: list[Finding], asset_waves: list[list[Asset]] | None = None) -> None:
        self.findings = findings
        self.asset_waves = asset_waves or [[_asset("a.example.com")]]
        self.calls: list[dict] = []

    async def __call__(self, program: Program, **kwargs: object) -> CampaignResult:
        wave = self.asset_waves[min(len(self.calls), len(self.asset_waves) - 1)]
        self.calls.append(kwargs)
        store: AssetStore = kwargs["asset_store"]  # type: ignore[assignment]
        now = time.time()
        for asset in wave:
            store.upsert(asset, now)
        return CampaignResult(
            assets=list(wave), findings=list(self.findings), scanned=[a.url for a in wave if a.url]  # type: ignore[misc]
        )


def _bot(tmp_path, findings):
    store = AssetStore(tmp_path / "assets.db")
    queue = ReviewQueue(tmp_path / "queue.db")
    return BountyBot(store, queue, campaign_runner=_FakeCampaign(findings)), queue


def _program() -> Program:
    return Program(platform="self", handle="acme", seeds=["https://a.example.com"])


async def test_cycle_files_candidates_as_pending(tmp_path) -> None:
    findings = [_finding("sqli", "a.example.com", "id"), _finding("xss", "a.example.com", "q")]
    bot, queue = _bot(tmp_path, findings)
    result = await bot.run_once(_program(), authorized=True)
    assert result.findings == 2 and result.candidates == 2 and result.new_candidates == 2
    assert result.pending == 2
    assert all(c.status == "pending" for c in queue.pending("acme"))


async def test_second_cycle_dedups_no_new_candidates(tmp_path) -> None:
    findings = [_finding("sqli", "a.example.com", "id")]
    bot, queue = _bot(tmp_path, findings)
    await bot.run_once(_program(), authorized=True)
    result = await bot.run_once(_program(), authorized=True)  # same surface again
    assert result.new_candidates == 0 and result.pending == 1  # re-found, not re-filed


async def test_human_decision_survives_next_cycle(tmp_path) -> None:
    findings = [_finding("sqli", "a.example.com", "id")]
    bot, queue = _bot(tmp_path, findings)
    await bot.run_once(_program(), authorized=True)
    sig = queue.pending("acme")[0].signature
    queue.set_status("acme", sig, "dismissed")  # a human rejects it
    result = await bot.run_once(_program(), authorized=True)
    assert result.pending == 0  # the dismissed candidate is not resurrected as pending
    assert queue.get("acme", sig).status == "dismissed"


async def test_bot_passes_authorization_through_and_never_submits(tmp_path) -> None:
    fake = _FakeCampaign([_finding("sqli", "a.example.com", "id")])
    store = AssetStore(tmp_path / "assets.db")
    queue = ReviewQueue(tmp_path / "queue.db")
    bot = BountyBot(store, queue, campaign_runner=fake)
    await bot.run_once(_program(), authorized=True, engine="both")
    assert fake.calls[0]["authorized"] is True and fake.calls[0]["engine"] == "both"
    assert fake.calls[0]["dedupe_assets"] is True  # coordinator on by default (collapse duplicate surface)
    # The human gate: the bot exposes no submit path, and nothing it does reaches a terminal sent state.
    assert not hasattr(bot, "submit")
    assert queue.counts("acme")["submitted"] == 0


async def test_run_continuous_detects_new_assets_and_alerts(tmp_path) -> None:
    # Cycle 1 sees only a.example.com; before cycle 2 recon discovers b.example.com. Continuous monitoring
    # must flag b as new on cycle 2 (and not re-flag a), and call on_cycle once per cycle — all without
    # real wall-clock waits (sleep is injected as a no-op).
    a, b = _asset("a.example.com"), _asset("b.example.com")
    fake = _FakeCampaign([_finding("sqli", "a.example.com", "id")], asset_waves=[[a], [a, b]])
    store = AssetStore(tmp_path / "assets.db")
    queue = ReviewQueue(tmp_path / "queue.db")
    bot = BountyBot(store, queue, campaign_runner=fake)

    seen: list = []

    async def _no_sleep(_seconds: float) -> None:
        return None

    results = await bot.run_continuous(
        _program(), authorized=True, interval_s=3600, max_cycles=2, sleep=_no_sleep, on_cycle=seen.append
    )
    assert len(results) == 2
    assert results[0].new_asset_hosts == ["a.example.com"]   # cycle 1: a just appeared
    assert results[1].new_asset_hosts == ["b.example.com"]   # cycle 2: only b is new; a is already known
    assert seen == results                                   # on_cycle fired once per cycle (drives alerts)
    assert len(fake.calls) == 2
