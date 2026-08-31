"""Benchmark scorer: precision/recall/F1 against ground-truth labels, and scoring an external tool's
findings on the same target (the comparison harness). Pure — no scan runs here."""

from __future__ import annotations

import json

from dastcore.benchmark.scorer import (
    detected_from_findings,
    markdown_table,
    score,
    score_external,
)
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_EXPECTED = {"/sqli": "sqli", "/xss": "xss", "/safe1": None, "/safe2": None}


def test_perfect_score() -> None:
    detected = {"/sqli": {"sqli"}, "/xss": {"xss"}}
    r = score(detected, _EXPECTED, label="dastcore")
    assert (r.tp, r.fp, r.fn) == (2, 0, 0)
    assert r.precision == 1.0 and r.recall == 1.0 and r.f1 == 1.0
    assert r.positives == 2 and r.decoys == 2


def test_false_positive_on_a_decoy_drops_precision() -> None:
    detected = {"/sqli": {"sqli"}, "/xss": {"xss"}, "/safe1": {"sqli"}}
    r = score(detected, _EXPECTED)
    assert r.fp == 1 and r.false_positives == [("/safe1", ["sqli"])]
    assert r.precision < 1.0 and r.recall == 1.0


def test_false_negative_drops_recall() -> None:
    detected = {"/sqli": {"sqli"}}  # missed /xss
    r = score(detected, _EXPECTED)
    assert r.fn == 1 and r.false_negatives == ["/xss (expected xss)"]
    assert r.recall < 1.0 and r.precision == 1.0


def test_to_dict_and_scorecard() -> None:
    r = score({"/sqli": {"sqli"}, "/xss": {"xss"}}, _EXPECTED, label="dastcore")
    d = r.to_dict()
    assert d["precision"] == 1.0 and d["label"] == "dastcore" and d["tp"] == 2
    assert "precision=1.000" in r.scorecard() and "dastcore" in r.scorecard()


def test_markdown_table_has_a_row_per_tool() -> None:
    a = score({"/sqli": {"sqli"}, "/xss": {"xss"}}, _EXPECTED, label="dastcore")
    b = score({"/sqli": {"sqli"}}, _EXPECTED, label="othertool")
    md = markdown_table([a, b])
    assert "| dastcore |" in md and "| othertool |" in md and md.startswith("| Tool |")


def _finding(path: str, family: str) -> Finding:
    req = HttpRequest(method="GET", url=f"http://127.0.0.1{path}", params={"q": "1"})
    pt = InjectionPoint(location="query", name="q", base_value="1", request_template=req)
    return Finding(id=f"{family}:{path}", rule_id=family, name=family, severity="high", cwe="", owasp="",
                   family=family, injection_point=pt,
                   evidence=[Evidence(type="differential", data="x", confidence="high")],
                   request=req, response=HttpResponse(status_code=500), remediation="x")


def test_detected_from_findings_ignores_passive_families() -> None:
    findings = [_finding("/sqli", "sqli"), _finding("/x", "tls")]  # tls is not an active family
    detected = detected_from_findings(findings)
    assert detected["/sqli"] == {"sqli"} and "/x" not in detected


def test_score_external_accepts_findings_json_and_simple_pairs(tmp_path) -> None:
    # dastcore Finding[] JSON
    fjson = tmp_path / "f.json"
    fjson.write_text(json.dumps([_finding("/sqli", "sqli").model_dump(mode="json")]), encoding="utf-8")
    r1 = score_external(str(fjson), _EXPECTED, label="zap")
    assert r1.label == "zap" and r1.tp == 1 and r1.fn == 1  # only caught /sqli

    # simple [{path, family}] shape
    pjson = tmp_path / "p.json"
    pjson.write_text(json.dumps([{"path": "/sqli", "family": "sqli"}, {"path": "/xss", "family": "xss"}]), encoding="utf-8")
    r2 = score_external(str(pjson), _EXPECTED)
    assert r2.tp == 2 and r2.fp == 0 and r2.label == "p"  # label falls back to the filename stem
