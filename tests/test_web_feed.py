"""Verbose live scan feed: the running panel accumulates what the scan is doing/discovering and the
findings as they're confirmed, instead of only showing the latest phase."""

from __future__ import annotations

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.web.jobs import LiveJob, _JobProgress


def test_add_log_dedups_consecutive_and_caps_length() -> None:
    job = LiveJob(id="s1", target="http://t")
    job.add_log("a")
    job.add_log("a")  # consecutive duplicate ignored
    job.add_log("b")
    assert job.log == ["a", "b"]
    for i in range(200):
        job.add_log(f"line-{i}")
    assert len(job.log) == 80 and job.log[-1] == "line-199"  # capped to the last 80


def test_progress_status_accumulates_into_the_feed() -> None:
    job = LiveJob(id="s1", target="http://t")
    prog = _JobProgress(job)
    prog.status("Crawleando http://t/…")
    prog.status("Probando ficheros sensibles…")
    assert job.phase == "Probando ficheros sensibles…"  # phase is the latest
    assert job.log == ["Crawleando http://t/…", "Probando ficheros sensibles…"]  # the stream is kept


def test_progress_finding_surfaces_live_with_a_count() -> None:
    job = LiveJob(id="s1", target="http://t")
    prog = _JobProgress(job)
    req = HttpRequest(method="GET", url="http://t/search", params={"q": "1"})
    pt = InjectionPoint(location="query", name="q", base_value="1", request_template=req)
    f = Finding(id="x", rule_id="sqli-injection", name="SQL Injection", severity="high", cwe="CWE-89", owasp="",
                family="sqli", injection_point=pt,
                evidence=[Evidence(type="differential", data="x", confidence="high")],
                request=req, response=HttpResponse(status_code=500), remediation="x")
    prog.finding(f)
    assert job.found == 1
    assert job.log[-1] == "⚠ [high] SQL Injection · /search"  # severity + name + path, flagged with ⚠
