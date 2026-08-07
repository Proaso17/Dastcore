"""Confidence scoring by oracle agreement.

A finding is more trustworthy when *independent* signals agree on it. This turns a
finding's evidence into a single confidence label + score: an out-of-band callback
or real DOM execution is high on its own; otherwise confidence rises with the number
of distinct signal types that fired (e.g. a SQL error string *and* a time delay) and
with reproduction (the same signal confirmed on a second, independent request).

Kept dependency-free of the models module (it only reads ``.type``/``.confidence`` off
each evidence) so `Finding` can call it from a computed field without an import cycle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from dastcore.core.models import Confidence, Evidence

# Signals that, on their own, already confirm a vulnerability with high certainty.
_SELF_SUFFICIENT = {"oob", "dom_execution"}
_EVIDENCE_WEIGHT = {"low": 0.35, "medium": 0.55, "high": 0.75}


def score_confidence(evidences: list[Evidence], *, corroborated: int = 0) -> tuple[Confidence, float]:
    """Return (label, score in 0..1) for a finding's evidence.

    - out-of-band / DOM-execution evidence → high (0.98).
    - otherwise: start from the strongest single evidence, add for each *extra* distinct
      signal type that agreed, add for reproduction (same type seen twice), and add when
      the same scenario is confirmed by another *independent technique/rule* at the same
      injection point (``corroborated`` = how many other rules cross-confirmed it).
    """
    if not evidences:
        return "low", 0.3

    types = [e.type for e in evidences]
    distinct = set(types)
    reproduced = len(types) > len(distinct)  # a repeated type == confirmed twice

    if distinct & _SELF_SUFFICIENT:
        return "high", 0.98

    score = max(_EVIDENCE_WEIGHT.get(e.confidence, 0.5) for e in evidences)
    if len(distinct) >= 2:
        score += 0.2  # independent signals agree
    if reproduced:
        score += 0.1
    if corroborated >= 1:
        score += 0.2  # a second technique/rule confirmed the same scenario
    score = min(round(score, 2), 0.97)

    label: Literal["low", "medium", "high"] = "high" if score >= 0.75 else "medium" if score >= 0.5 else "low"
    return label, score
