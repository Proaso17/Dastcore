"""Triage: rank and explain already-confirmed findings (Module 15).

Two layers, both strictly *downstream* of the oracle that confirmed a finding:

- ``scoring`` — a deterministic exploitability score and priority band, computed from the
  finding's CVSS base score, the engine's own confidence, and a per-family weight. No
  network, no AI.
- ``ai`` — an optional ``--ai-triage`` layer (Claude API) that receives ONLY confirmed
  findings and their evidence, and produces an executive narrative, root-cause grouping,
  and an advisory *business* severity. It never confirms, creates, or elevates a finding —
  the ground truth stays the oracle.
"""

from __future__ import annotations

from dastcore.triage.ai import (
    AiTriageResult,
    BusinessSeverity,
    RootCauseGroup,
    build_triage_input,
    triage_findings,
)
from dastcore.triage.digest import TriageCluster, TriageDigest, build_digest
from dastcore.triage.scoring import (
    TriagedFinding,
    exploitability_score,
    family_weight,
    prioritize,
    priority_band,
)

__all__ = [
    "AiTriageResult",
    "BusinessSeverity",
    "RootCauseGroup",
    "TriageCluster",
    "TriageDigest",
    "TriagedFinding",
    "build_digest",
    "build_triage_input",
    "exploitability_score",
    "family_weight",
    "priority_band",
    "prioritize",
    "triage_findings",
]
