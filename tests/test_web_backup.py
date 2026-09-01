"""Crash-safe backup: findings are persisted the moment they're confirmed, so a stop/restart never
loses what was found; an interrupted scan shows its partial findings, and a hunt can be resumed."""

from __future__ import annotations

import httpx
from httpx import ASGITransport

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.web.app import create_app
from dastcore.web.store import Store


def _finding(fid: str, severity: str = "high") -> Finding:
    req = HttpRequest(method="GET", url="http://t.test/x", params={"q": "1"})
    pt = InjectionPoint(location="query", name="q", base_value="1", request_template=req)
    return Finding(id=fid, rule_id="sqli-injection", name="SQL Injection", severity=severity, cwe="CWE-89",
                   owasp="", family="sqli", injection_point=pt,
                   evidence=[Evidence(type="differential", data="x", confidence="high")],
                   request=req, response=HttpResponse(status_code=500), remediation="x")


def test_append_scan_findings_persists_dedups_and_survives_interruption(tmp_path) -> None:
    store = Store(db_path=tmp_path / "d.sqlite")
    store.insert_running("s1", "http://t.test", "http", None, 1.0)
    store.append_scan_findings("s1", [_finding("a", "high")])
    store.append_scan_findings("s1", [_finding("b", "critical"), _finding("a", "high")])  # 'a' dedups
    row = store.get_scan("s1")
    assert row is not None and row.status == "running" and row.num_findings == 2  # persisted while running
    assert row.severity_counts.get("critical") == 1 and row.severity_counts.get("high") == 1
    assert {f.id for f in store.get_findings("s1")} == {"a", "b"}

    store.mark_interrupted_running()  # a restart flips running -> interrupted
    row2 = store.get_scan("s1")
    assert row2 is not None and row2.status == "interrupted"
    assert {f.id for f in store.get_findings("s1")} == {"a", "b"}  # nothing lost


async def test_interrupted_scan_panel_shows_partial_findings(tmp_path) -> None:
    db = tmp_path / "d.sqlite"
    seed = Store(db_path=db)
    seed.insert_running("s1", "http://t.test", "http", None, 1.0)
    seed.append_scan_findings("s1", [_finding("a", "high")])
    seed.mark_interrupted_running()

    app = create_app(db_path=db)
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        panel = (await client.get("/scans/s1/panel")).text
    assert "Interrumpido" in panel and "resultados parciales" in panel  # partial results, not "lost"
    assert "SQL Injection" in panel  # the finding found before the stop is shown
    assert "/scans/s1/resume" not in panel  # a plain scan is not resumable


async def test_interrupted_hunt_panel_offers_resume(tmp_path) -> None:
    db = tmp_path / "d.sqlite"
    seed = Store(db_path=db)
    seed.insert_running("h1", "acme", "hunt", "standard", 1.0, kind="hunt", program_id="prog123")
    seed.append_scan_findings("h1", [_finding("a", "critical")])
    seed.mark_interrupted_running()

    app = create_app(db_path=db)
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        panel = (await client.get("/scans/h1/panel")).text
    assert "Reanudar donde se quedó" in panel  # a hunt offers resume
    assert 'action="/scans/h1/resume"' in panel
