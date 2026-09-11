"""Evidence pack — the review-ready bundle a human vets before anything is submitted.

For one queued candidate this assembles everything needed to make a submit/dismiss decision: the
per-platform Markdown draft (PoC + oracle evidence + impact + VRT/CVSS + remediation), whether it clears
the false-positive gate (so it wouldn't be closed N/A), and, when it doesn't, the concrete blockers to
fix first. It is a pure function over a ``QueuedCandidate`` — no network, no submission — so it renders
identically in the CLI and the web review queue, and the human stays the one who decides.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dastcore.bugbounty.program import Program
from dastcore.bugbounty.queue import QueuedCandidate
from dastcore.bugbounty.report import render_bounty_report
from dastcore.bugbounty.triage import BountyFinding, fp_checklist


@dataclass
class EvidencePack:
    """A candidate packaged for human review — never auto-submitted."""

    candidate: QueuedCandidate
    platform: str
    draft: str                 # the per-platform Markdown submission draft
    ready_to_submit: bool      # clears the FP gate → wouldn't be an obvious N/A
    blockers: list[str] = field(default_factory=list)  # why it is not ready (empty when ready)


def _to_bounty_finding(candidate: QueuedCandidate) -> BountyFinding:
    """Rebuild the BountyFinding the report renderer expects from a stored queue candidate."""
    return BountyFinding(
        finding=candidate.finding,
        vrt_category=candidate.vrt_category,
        vrt_priority=candidate.vrt_priority,
        cvss_vector=candidate.finding.cvss or "",
        expected_payout=0.0,
        signature=candidate.signature,
        variants=candidate.variants,
        priority_score=candidate.priority_score,
        checklist=fp_checklist(candidate.finding),
    )


def build_evidence_pack(
    candidate: QueuedCandidate, program: Program | None = None, platform: str = "generic"
) -> EvidencePack:
    """Assemble the review-ready evidence pack for one candidate (pure; no network, no submission)."""
    bf = _to_bounty_finding(candidate)
    draft = render_bounty_report(bf, program, platform)
    checklist = bf.checklist
    blockers: list[str] = []
    if not checklist.exploitable_now:
        blockers.append("Explotabilidad no confirmada: la confianza del motor está por debajo del umbral.")
    if not checklist.deterministic_repro:
        blockers.append("Sin PoC/oráculo determinista (falta señal differential/OAST/time/DOM o corroboración).")
    if not checklist.evidence_attached:
        blockers.append("Sin evidencia adjunta.")
    return EvidencePack(
        candidate=candidate, platform=platform, draft=draft,
        ready_to_submit=checklist.passes, blockers=blockers,
    )
