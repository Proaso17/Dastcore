"""BountyBot orchestration: one cycle runs campaign → triage → queue, files candidates as ``pending``,
dedups across cycles, preserves a human's decision, and has no path to submit anything. The campaign
runner is injected with a fake so this tests the wiring without a live scan."""

from __future__ import annotations

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


class _FakeCampaign:
    """Stands in for run_campaign: returns fixed findings and records the kwargs it was called with."""

    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings
        self.calls: list[dict] = []

    async def __call__(self, program: Program, **kwargs: object) -> CampaignResult:
        self.calls.append(kwargs)
        return CampaignResult(
            assets=[Asset(host="a.example.com")], findings=list(self.findings), scanned=["https://a.example.com/"]
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
    # The human gate: the bot exposes no submit path, and nothing it does reaches a terminal sent state.
    assert not hasattr(bot, "submit")
    assert queue.counts("acme")["submitted"] == 0
