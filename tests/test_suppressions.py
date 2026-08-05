"""Triage suppressions: `.dastcore-ignore` matching, expiry, and report wiring."""

from __future__ import annotations

import datetime as _dt
import json

import pytest
from pydantic import ValidationError

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.report import render_json
from dastcore.report.sarif import build_sarif
from dastcore.suppressions import (
    Suppression,
    apply_suppressions,
    load_suppressions,
    resolve_suppressions,
)

TODAY = _dt.date(2026, 8, 6)


def _finding(fid: str, rule_id: str, url: str = "http://target.test/x") -> Finding:
    request = HttpRequest(method="GET", url=url, params={"q": "'"})
    return Finding(
        id=fid,
        rule_id=rule_id,
        name="Test finding",
        severity="high",
        cwe="CWE-89",
        owasp="WSTG-INPV-05",
        injection_point=InjectionPoint(location="query", name="q", request_template=request),
        evidence=[Evidence(type="response_match", data="boom")],
        request=request,
        response=HttpResponse(status_code=500),
        remediation="fix it",
    )


# --- model / matching ----------------------------------------------------------------


def test_suppression_requires_a_selector() -> None:
    with pytest.raises(ValidationError):
        Suppression(reason="no selector at all")


def test_matches_by_rule_id() -> None:
    supp = Suppression(rule_id="sqli-injection", reason="accepted")
    assert supp.matches(_finding("a", "sqli-injection"), TODAY)
    assert not supp.matches(_finding("a", "xss-reflected"), TODAY)


def test_matches_by_exact_id() -> None:
    supp = Suppression(id="finding-123")
    assert supp.matches(_finding("finding-123", "any-rule"), TODAY)
    assert not supp.matches(_finding("finding-999", "any-rule"), TODAY)


def test_matches_by_url_glob() -> None:
    supp = Suppression(url="*/legacy/*")
    assert supp.matches(_finding("a", "r", "http://target.test/legacy/page"), TODAY)
    assert not supp.matches(_finding("a", "r", "http://target.test/app/page"), TODAY)


def test_combined_criteria_are_anded() -> None:
    supp = Suppression(rule_id="xss-reflected", url="*/legacy/*")
    assert supp.matches(_finding("a", "xss-reflected", "http://t/legacy/p"), TODAY)
    # right rule, wrong url -> no match (both must hold)
    assert not supp.matches(_finding("a", "xss-reflected", "http://t/app/p"), TODAY)


def test_expired_suppression_does_not_match() -> None:
    supp = Suppression(rule_id="sqli-injection", expires=_dt.date(2026, 1, 1))
    assert not supp.matches(_finding("a", "sqli-injection"), TODAY)
    # still valid before it expires
    future = Suppression(rule_id="sqli-injection", expires=_dt.date(2026, 12, 31))
    assert future.matches(_finding("a", "sqli-injection"), TODAY)


# --- apply ---------------------------------------------------------------------------


def test_apply_marks_matching_findings_with_reason() -> None:
    findings = [_finding("a", "sqli-injection"), _finding("b", "xss-reflected")]
    apply_suppressions(findings, [Suppression(rule_id="sqli-injection", reason="known FP")], today=TODAY)
    assert findings[0].suppressed and findings[0].suppression_reason == "known FP"
    assert not findings[1].suppressed


def test_apply_is_noop_without_suppressions() -> None:
    findings = [_finding("a", "sqli-injection")]
    apply_suppressions(findings, [], today=TODAY)
    assert not findings[0].suppressed


# --- loading -------------------------------------------------------------------------


def test_load_mapping_format(tmp_path) -> None:
    path = tmp_path / ".dastcore-ignore"
    path.write_text(
        "suppressions:\n"
        "  - rule_id: sqli-injection\n"
        "    reason: accepted\n"
        "  - id: finding-1\n"
        "    url: '*/legacy/*'\n"
        "    expires: 2026-12-31\n",
        encoding="utf-8",
    )
    supps = load_suppressions(path)
    assert len(supps) == 2
    assert supps[0].rule_id == "sqli-injection"
    assert supps[1].expires == _dt.date(2026, 12, 31)


def test_load_bare_list_format(tmp_path) -> None:
    path = tmp_path / "ignore.yaml"
    path.write_text("- rule_id: xss-reflected\n", encoding="utf-8")
    assert load_suppressions(path)[0].rule_id == "xss-reflected"


def test_resolve_explicit_missing_raises(tmp_path) -> None:
    with pytest.raises(OSError):
        resolve_suppressions(str(tmp_path / "nope.yaml"))


def test_resolve_autodetects_default(tmp_path, monkeypatch) -> None:
    (tmp_path / ".dastcore-ignore").write_text("- rule_id: sqli-injection\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert resolve_suppressions("")[0].rule_id == "sqli-injection"
    # and returns empty when the default file is absent
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.chdir(empty)
    assert resolve_suppressions("") == []


# --- report wiring -------------------------------------------------------------------


def test_suppressed_finding_flagged_in_json() -> None:
    findings = [_finding("a", "sqli-injection")]
    apply_suppressions(findings, [Suppression(rule_id="sqli-injection", reason="accepted")], today=TODAY)
    data = json.loads(render_json(findings))
    assert data[0]["suppressed"] is True
    assert data[0]["suppression_reason"] == "accepted"


def test_sarif_marks_suppressed_result_as_dismissed() -> None:
    findings = [_finding("a", "sqli-injection"), _finding("b", "xss-reflected")]
    apply_suppressions(findings, [Suppression(rule_id="sqli-injection", reason="accepted")], today=TODAY)
    results = build_sarif(findings)["runs"][0]["results"]
    suppressed = next(r for r in results if r["ruleId"] == "sqli-injection")
    active = next(r for r in results if r["ruleId"] == "xss-reflected")
    assert suppressed["suppressions"][0]["kind"] == "external"
    assert suppressed["suppressions"][0]["justification"] == "accepted"
    assert "suppressions" not in active
