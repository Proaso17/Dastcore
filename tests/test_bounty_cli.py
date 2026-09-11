"""The CLI human gate resolves a candidate from a short signature prefix. A unique prefix resolves; an
unknown or ambiguous one aborts (so a status change never hits the wrong finding)."""

from __future__ import annotations

import pytest
import typer

from dastcore.bugbounty.queue import ReviewQueue
from dastcore.bugbounty.triage import triage_for_bounty
from dastcore.cli import _resolve_candidate
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint


def _seed(queue: ReviewQueue, family: str, host: str, param: str) -> str:
    req = HttpRequest(method="GET", url=f"https://{host}/p?{param}=x", params={param: "x"})
    point = InjectionPoint(location="query", name=param, base_value="x", request_template=req)
    finding = Finding(
        id=f"{family}:{host}:{param}", rule_id=f"{family}-x", name=f"{family} on {host}", severity="high",
        cwe="CWE-89", owasp="WSTG-INPV-05", injection_point=point,
        evidence=[Evidence(type="differential", data="confirmed", confidence="high")],
        request=req, response=HttpResponse(status_code=500, url=req.url), remediation="fix", family=family,
    )
    bf = triage_for_bounty([finding])[0]
    queue.upsert_candidate("acme", bf, now=1.0)
    return bf.signature


def test_unique_prefix_resolves(tmp_path) -> None:
    queue = ReviewQueue(tmp_path / "q.db")
    sig = _seed(queue, "sqli", "a.example.com", "id")
    resolved = _resolve_candidate(queue, "acme", "sqli|a.example.com")
    assert resolved.signature == sig


def test_unknown_prefix_aborts(tmp_path) -> None:
    queue = ReviewQueue(tmp_path / "q.db")
    _seed(queue, "sqli", "a.example.com", "id")
    with pytest.raises(typer.Exit):
        _resolve_candidate(queue, "acme", "nope")


def test_ambiguous_prefix_aborts(tmp_path) -> None:
    queue = ReviewQueue(tmp_path / "q.db")
    _seed(queue, "sqli", "a.example.com", "id")
    _seed(queue, "sqli", "a.example.com", "name")
    with pytest.raises(typer.Exit):
        _resolve_candidate(queue, "acme", "sqli|a.example.com")  # matches both params
