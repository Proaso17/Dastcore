"""Deterministic exploitability scoring and prioritisation (Module 15).

Whether a finding is *real* is decided by the oracle that confirmed it (differential,
time-based, OAST); this module never revisits that. It only ranks already-confirmed
findings by how urgently they should be fixed, combining three objective inputs:

- the CVSS 3.1 base score (impact + attack feasibility),
- the engine's own confidence in the finding (agreement of its evidence signals), and
- a per-family exploitability weight (how directly a class is weaponised in practice).

Pure and deterministic — no network, no AI. The AI layer (``triage.ai``) builds on top of
this ordering but never changes it.
"""

from __future__ import annotations

from dataclasses import dataclass

from dastcore.core.models import Finding

# How readily each family is turned into a working exploit in the wild. Injection classes
# that yield code/query execution and authorization flaws (direct data access) rank highest;
# reflected/redirect/info-exposure classes need more to land, so they sit at or below parity.
_FAMILY_WEIGHT: dict[str, float] = {
    "cmdi": 1.20,
    "authz": 1.20,
    "sqli": 1.15,
    "ssti": 1.15,
    "xxe": 1.10,
    "ssrf": 1.10,
    "llm": 1.10,
    "race": 1.05,
    "crlf": 1.00,
    "xss": 1.00,
    "graphql": 0.95,
    "exposure": 0.90,
    "open_redirect": 0.90,
}


def family_weight(family: str) -> float:
    """Exploitability multiplier for a vulnerability family (1.0 for unknown families)."""
    return _FAMILY_WEIGHT.get(family, 1.0)


def exploitability_score(finding: Finding) -> float:
    """A 0.0–10.0 urgency score: CVSS base, tempered by confidence, scaled by family.

    Confidence never *raises* a finding above its CVSS impact; it only discounts a
    lower-confidence one (mapped to a 0.6–1.0 band so a fully-confirmed finding keeps its
    full CVSS weight). The result is clamped to the 0–10 CVSS range.
    """
    base = finding.cvss_score
    confidence_factor = 0.6 + 0.4 * finding.confidence_score
    score = base * confidence_factor * family_weight(finding.family)
    return round(min(score, 10.0), 1)


def priority_band(score: float) -> str:
    """Map an exploitability score to a fix-priority band (P1 = fix first)."""
    if score >= 9.0:
        return "P1"
    if score >= 7.0:
        return "P2"
    if score >= 4.0:
        return "P3"
    return "P4"


@dataclass
class TriagedFinding:
    """A finding with its deterministic urgency score and priority band."""

    finding: Finding
    exploitability: float
    band: str


def prioritize(findings: list[Finding]) -> list[TriagedFinding]:
    """Rank findings most-urgent first, by exploitability then raw CVSS as a tie-break."""
    triaged = [
        TriagedFinding(finding=f, exploitability=(score := exploitability_score(f)), band=priority_band(score))
        for f in findings
    ]
    triaged.sort(key=lambda t: (t.exploitability, t.finding.cvss_score), reverse=True)
    return triaged
