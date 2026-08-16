"""Phase 11 hunt pipeline: recon (replayed) -> scan the local vuln target. Only in-scope live assets
are scanned; an out-of-scope asset is never touched; 'no automated scanning' yields recon-only; and the
per-asset checkpoint resumes. No network — recon is fed recorded output; the scan hits the local app."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from dastcore.bugbounty.campaign import CampaignCheckpoint, finding_hosts, run_campaign
from dastcore.bugbounty.program import Program, ProgramLimits, ProgramScope
from dastcore.core.models import Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.recon import AssetStore, ReconOptions


def _program(*, no_scan: bool = False) -> Program:
    return Program(
        handle="local",
        scope=ProgramScope(domains=["127.0.0.1"]),
        seeds=["127.0.0.1"],
        limits=ProgramLimits(no_automated_scanning=no_scan),
    )


def _replay(target_url: str) -> ReconOptions:
    port = urlsplit(target_url).port
    live = json.dumps({"url": target_url, "host": "127.0.0.1", "port": port, "status_code": 200})
    evil = json.dumps({"url": "https://evil.example", "host": "evil.example", "status_code": 200})  # out of scope
    return ReconOptions(replay={"crtsh": "[]", "httpx": f"{live}\n{evil}"})


async def test_hunt_scans_only_in_scope_live_assets(mini_target_url: str, tmp_path) -> None:
    store = AssetStore(tmp_path / "assets.db")
    result = await run_campaign(
        _program(),
        authorized=True,
        asset_store=store,
        recon_opts=_replay(mini_target_url),
        engine="http",
        max_pages=40,
        checkpoint_path=tmp_path / "cp.json",
    )
    assert result.findings, "the planted vuln on the local target should be found"
    assert finding_hosts(result.findings) == {"127.0.0.1"}  # evil.example never scanned
    assert result.scanned == [mini_target_url]
    # the out-of-scope asset was dropped by the recon gate and never stored
    assert all(a.host != "evil.example" for a in store.all())
    store.close()


async def test_no_automated_scanning_is_recon_only(mini_target_url: str, tmp_path) -> None:
    store = AssetStore(tmp_path / "assets.db")
    result = await run_campaign(
        _program(no_scan=True),
        authorized=True,
        asset_store=store,
        recon_opts=_replay(mini_target_url),
        checkpoint_path=tmp_path / "cp.json",
    )
    assert result.findings == [] and result.scanned == []  # active scanning disabled by the program
    store.close()


def _finding(rule_id: str) -> Finding:
    req = HttpRequest(method="GET", url="http://127.0.0.1/x", params={"q": "1"})
    point = InjectionPoint(location="query", name="q", base_value="1", request_template=req)
    return Finding(
        id=rule_id,
        rule_id=rule_id,
        name=rule_id,
        severity="high",
        cwe="CWE-0",
        owasp="x",
        injection_point=point,
        request=req,
        response=HttpResponse(status_code=200),
        remediation="x",
    )


def test_checkpoint_round_trips_and_resumes(tmp_path) -> None:
    path = tmp_path / "cp.json"
    cp = CampaignCheckpoint(path)
    assert not cp.is_done("http://127.0.0.1/")
    cp.mark_done("http://127.0.0.1/", [_finding("sqli-injection")])
    cp.save()

    resumed = CampaignCheckpoint(path)  # a fresh run reads the checkpoint back
    assert resumed.is_done("http://127.0.0.1/")  # -> would be skipped
    assert [f.rule_id for f in resumed.findings()] == ["sqli-injection"]  # findings survived the round-trip
