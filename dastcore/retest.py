"""Retest mode: re-verify a prior scan's findings to see which were fixed.

Given the JSON report of an earlier ``scan`` run, retest re-issues *only* the
requests that produced those findings and re-runs the same in-band + passive
rules over them. Each prior finding is then classified by whether it reappears:

- **open** — the finding fired again (still vulnerable). Carries the *fresh*
  finding, with new evidence/response from this run.
- **fixed** — the request was re-issued and the finding did not reappear.
- **unverified** — the finding could not be judged automatically. Today that is
  the out-of-band class (blind SSRF/RCE/XXE): without an active OAST collector a
  missing callback is not evidence of a fix, so we refuse to call it fixed.

Matching is by ``Finding.id`` (``rule:method:path:location:name``), which is
stable across runs for the same vulnerability, so a re-scan of the same endpoint
produces the same id — that is what lets us line prior and current findings up.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from dastcore.core.models import Finding, HttpRequest

RetestStatus = Literal["open", "fixed", "unverified"]


@dataclass
class RetestOutcome:
    """The verdict for one prior finding, plus the fresh finding when still open."""

    prior: Finding
    status: RetestStatus
    current: Finding | None = None


def load_prior_findings(data: object) -> list[Finding]:
    """Parse the findings from a prior ``scan`` JSON report.

    Accepts the report's bare array of findings, or a ``{"findings": [...]}``
    object (as produced by the ``--resume`` state file) for convenience.
    """
    if isinstance(data, dict):
        items = data.get("findings", [])
    elif isinstance(data, list):
        items = data
    else:
        raise ValueError("el reporte de hallazgos debe ser una lista o un objeto con 'findings'")
    if not isinstance(items, list):
        raise ValueError("'findings' debe ser una lista de hallazgos")
    return [Finding.model_validate(item) for item in items]


def base_requests_for(findings: list[Finding]) -> list[HttpRequest]:
    """The de-duplicated base requests to re-issue to reproduce these findings.

    Uses each finding's injection-point template (the pre-mutation request), so the
    scanner re-derives injection points and re-applies payloads exactly as it did
    originally, rather than replaying a single baked-in payload.
    """
    seen: dict[str, HttpRequest] = {}
    for finding in findings:
        template = finding.injection_point.request_template
        seen.setdefault(template.signature(), template)
    return list(seen.values())


def _is_oob(finding: Finding) -> bool:
    """Whether this finding was confirmed out-of-band (needs OAST to retest)."""
    return any(ev.type == "oob" for ev in finding.evidence)


# CORS is checked inside the scanner's per-request pass, so a re-scan reproduces it.
_REPRODUCIBLE_EXTRA = frozenset({"active-cors-reflected-origin"})


def _reproducible_by_rescan(finding: Finding, active_rule_ids: frozenset[str]) -> bool:
    """Whether re-issuing this finding's request through the scanner can re-emit it.

    The retest re-runs in-band active rules + passive checks + the CORS check. It does
    *not* re-run standalone probes (sensitive files, GraphQL introspection), authz,
    DOM-XSS or AI checks — so an absent finding of those classes is *unverified*, not
    fixed: we simply didn't retest it, and claiming "fixed" would be misleading.
    """
    rid = finding.rule_id
    return rid in active_rule_ids or rid in _REPRODUCIBLE_EXTRA or rid.startswith("passive-")


def classify(
    prior_findings: list[Finding],
    new_findings: list[Finding],
    *,
    oast_attempted: bool,
    active_rule_ids: frozenset[str] | None = None,
) -> list[RetestOutcome]:
    """Line up each prior finding against a fresh scan of its request.

    ``new_findings`` is everything the retest scan produced; only ids present in the
    prior set are considered (retest verifies the prior findings, it does not report
    newly-discovered issues). ``oast_attempted`` says whether an OAST collector was
    active this run — when it wasn't, out-of-band findings are left *unverified*.

    ``active_rule_ids`` (the ids from ``load_rules()``) lets classify tell apart a
    genuinely-fixed finding from one the re-scan simply can't reproduce: an absent
    finding whose class isn't reproducible is *unverified*, not fixed. When omitted,
    every absent non-OOB finding is treated as fixed (legacy behaviour).
    """
    current_by_id = {finding.id: finding for finding in new_findings}
    outcomes: list[RetestOutcome] = []
    for prior in prior_findings:
        current = current_by_id.get(prior.id)
        if current is not None:
            outcomes.append(RetestOutcome(prior=prior, status="open", current=current))
        elif _is_oob(prior) and not oast_attempted:
            outcomes.append(RetestOutcome(prior=prior, status="unverified"))
        elif active_rule_ids is not None and not _reproducible_by_rescan(prior, active_rule_ids):
            outcomes.append(RetestOutcome(prior=prior, status="unverified"))
        else:
            outcomes.append(RetestOutcome(prior=prior, status="fixed"))
    return outcomes


def open_findings(outcomes: list[RetestOutcome]) -> list[Finding]:
    """The fresh findings for prior issues that are still open."""
    return [outcome.current for outcome in outcomes if outcome.status == "open" and outcome.current is not None]


def summarize(outcomes: list[RetestOutcome]) -> dict[RetestStatus, int]:
    """Count outcomes by status (always includes all three keys)."""
    counts: dict[RetestStatus, int] = {"open": 0, "fixed": 0, "unverified": 0}
    for outcome in outcomes:
        counts[outcome.status] += 1
    return counts
