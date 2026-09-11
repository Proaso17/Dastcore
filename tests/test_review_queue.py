"""The bounty review queue: the human gate. Candidates land as ``pending`` and dedup across runs by
(program, signature); a status a human set is never dragged back by a later re-find, and the bot has no
way to mark anything ``submitted`` — only a human does."""

from __future__ import annotations

import pytest

from dastcore.bugbounty.queue import ReviewQueue
from dastcore.bugbounty.triage import triage_for_bounty
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint


def _finding(rule_id: str, family: str, host: str, param: str, name: str, sev: str = "high") -> Finding:
    req = HttpRequest(method="GET", url=f"https://{host}/p?{param}=x", params={param: "x"})
    point = InjectionPoint(location="query", name=param, base_value="x", request_template=req)
    return Finding(
        id=f"{rule_id}:{host}:{param}", rule_id=rule_id, name=name, severity=sev,  # type: ignore[arg-type]
        cwe="CWE-89", owasp="WSTG-INPV-05", injection_point=point,
        evidence=[Evidence(type="differential", data="oracle confirmed", confidence="high")],
        request=req, response=HttpResponse(status_code=500, url=req.url), remediation="parameterize",
        family=family,
    )


def _queue(tmp_path) -> ReviewQueue:
    return ReviewQueue(tmp_path / "q.db")


def _one(finding: Finding):
    cands = triage_for_bounty([finding])
    assert cands, "the test finding must pass the FP gate to reach the queue"
    return cands[0]


def test_new_candidate_enters_pending(tmp_path) -> None:
    q = _queue(tmp_path)
    bf = _one(_finding("sqli-injection", "sqli", "a.example.com", "id", "SQL Injection"))
    assert q.upsert_candidate("acme", bf, now=100.0) is True
    stored = q.get("acme", bf.signature)
    assert stored is not None and stored.status == "pending" and stored.first_seen == 100.0
    assert q.counts("acme")["pending"] == 1


def test_reupsert_dedups_and_refreshes_without_new(tmp_path) -> None:
    q = _queue(tmp_path)
    bf = _one(_finding("sqli-injection", "sqli", "a.example.com", "id", "SQL Injection"))
    q.upsert_candidate("acme", bf, now=100.0)
    assert q.upsert_candidate("acme", bf, now=200.0) is False  # same (program, signature) → not new
    stored = q.get("acme", bf.signature)
    assert stored is not None and stored.first_seen == 100.0 and stored.last_seen == 200.0
    assert q.counts("acme")["pending"] == 1  # still one row, not two


def test_human_status_survives_a_later_refind(tmp_path) -> None:
    q = _queue(tmp_path)
    bf = _one(_finding("sqli-injection", "sqli", "a.example.com", "id", "SQL Injection"))
    q.upsert_candidate("acme", bf, now=100.0)
    assert q.set_status("acme", bf.signature, "approved") is True
    q.upsert_candidate("acme", bf, now=300.0)  # the bot re-finds it on a later run
    stored = q.get("acme", bf.signature)
    assert stored is not None and stored.status == "approved"  # NOT dragged back to pending
    assert q.counts("acme") == {"pending": 0, "approved": 1, "submitted": 0, "dismissed": 0}


def test_candidates_ordered_by_priority_and_filtered_by_program(tmp_path) -> None:
    q = _queue(tmp_path)
    sqli = _one(_finding("sqli-injection", "sqli", "a.example.com", "id", "SQL Injection", "critical"))
    xss = _one(_finding("xss-reflected", "xss", "a.example.com", "q", "Reflected XSS", "medium"))
    q.upsert_candidate("acme", sqli, now=1.0)
    q.upsert_candidate("acme", xss, now=1.0)
    q.upsert_candidate("other", sqli, now=1.0)
    acme = q.candidates("acme")
    assert [c.finding.family for c in acme] == ["sqli", "xss"]  # P1 sqli outranks P3 xss
    assert len(q.candidates("acme")) == 2 and len(q.candidates("other")) == 1  # program-scoped


def test_set_status_validates_and_reports_missing(tmp_path) -> None:
    q = _queue(tmp_path)
    bf = _one(_finding("sqli-injection", "sqli", "a.example.com", "id", "SQL Injection"))
    q.upsert_candidate("acme", bf, now=1.0)
    with pytest.raises(ValueError):
        q.set_status("acme", bf.signature, "sent")  # type: ignore[arg-type]
    assert q.set_status("acme", "no-such-signature", "approved") is False
