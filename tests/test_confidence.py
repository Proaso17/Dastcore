"""Confidence scoring by oracle agreement."""

from __future__ import annotations

from dastcore.core.models import Evidence, Finding
from dastcore.validation.confidence import score_confidence


def _ev(type_: str, confidence: str = "medium") -> Evidence:
    return Evidence(type=type_, data="x", confidence=confidence)  # type: ignore[arg-type]


def test_no_evidence_is_low() -> None:
    assert score_confidence([]) == ("low", 0.3)


def test_oob_and_dom_execution_are_self_sufficient() -> None:
    assert score_confidence([_ev("oob", "high")]) == ("high", 0.98)
    assert score_confidence([_ev("dom_execution", "high")]) == ("high", 0.98)


def test_single_strong_signal_is_high() -> None:
    assert score_confidence([_ev("response_match", "high")]) == ("high", 0.75)


def test_single_medium_signal_is_medium() -> None:
    label, score = score_confidence([_ev("time_based", "medium")])
    assert label == "medium" and score == 0.55


def test_two_distinct_signals_corroborate_to_high() -> None:
    label, score = score_confidence([_ev("response_match", "high"), _ev("time_based", "medium")])
    assert label == "high" and score >= 0.9  # agreement boost


def test_reproduction_of_a_medium_signal_boosts_it() -> None:
    # same type twice = confirmed on a second request -> +0.1
    label, score = score_confidence([_ev("time_based", "medium"), _ev("time_based", "medium")])
    assert score == 0.65 and label == "medium"


def test_finding_exposes_confidence(sample_finding: Finding) -> None:
    # the fixture has one high-confidence response_match evidence
    assert sample_finding.confidence == "high"
    assert sample_finding.confidence_score == 0.75
    # confidence is serialized in the JSON output
    assert sample_finding.model_dump(mode="json")["confidence"] == "high"
