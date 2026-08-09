"""Deduplication and correlation of findings.

`deduplicate` drops exact repeats (same finding id) that can slip in when the
same request is reached by more than one path (e.g. `--engine both` or a resume
+ rescan). `correlate` groups findings by rule into a single logical *issue* with
an instance count and the affected locations — the at-a-glance view a pentester
wants instead of a flat list of near-identical rows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from dastcore.config import Severity
from dastcore.core.models import Confidence, Finding
from dastcore.severity import severity_rank


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Return findings with exact duplicates (same id) removed, order preserved."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        unique.append(finding)
    return unique


def _scenario_key(finding: Finding) -> tuple[str, str, str, str, str] | None:
    """The vulnerability *scenario* a finding belongs to: same family + injection point,
    regardless of which rule/technique found it. None for findings that can't correlate."""
    if not finding.family:
        return None
    path = urlsplit(finding.request.url).path or "/"
    point = finding.injection_point
    return (finding.family, finding.request.method, path, point.location, point.name)


def cross_correlate(findings: list[Finding]) -> list[Finding]:
    """Cross-technique confirmation: when the *same* injection point is confirmed by more
    than one rule of the same family (e.g. SQLi by both an error string and a boolean
    differential), annotate each finding with the other techniques that corroborate it.
    That raises its confidence — one vuln confirmed several independent ways.

    Pure and idempotent: returns copies with ``corroborated_by`` recomputed from scratch.
    """
    by_scenario: dict[tuple[str, str, str, str, str], set[str]] = {}
    for finding in findings:
        key = _scenario_key(finding)
        if key is not None:
            by_scenario.setdefault(key, set()).add(finding.rule_id)

    result: list[Finding] = []
    for finding in findings:
        key = _scenario_key(finding)
        others = sorted(by_scenario.get(key, set()) - {finding.rule_id}) if key is not None else []
        result.append(finding.model_copy(update={"corroborated_by": others}))
    return result


@dataclass
class IssueGroup:
    """One logical issue (a rule) and every place it was confirmed."""

    rule_id: str
    name: str
    severity: Severity
    cwe: str
    owasp: str
    cvss_score: float = 0.0
    count: int = 0
    locations: list[str] = field(default_factory=list)
    confidence: Confidence = "low"
    confidence_score: float = 0.0
    family: str = ""  # lets guide_for() resolve remediation for this issue
    remediation: str = ""  # the rule's one-line fix, used as the guide summary


def _location_label(finding: Finding) -> str:
    path = urlsplit(finding.request.url).path or "/"
    point = finding.injection_point
    return f"{finding.request.method} {path} ({point.location}:{point.name})"


def correlate(findings: list[Finding]) -> list[IssueGroup]:
    """Group deduplicated findings by rule, most-severe (then most-frequent) first."""
    groups: dict[str, IssueGroup] = {}
    for finding in deduplicate(findings):
        group = groups.get(finding.rule_id)
        if group is None:
            group = IssueGroup(
                rule_id=finding.rule_id,
                name=finding.name,
                severity=finding.severity,
                cwe=finding.cwe,
                owasp=finding.owasp,
                cvss_score=finding.cvss_score,
                family=finding.family,
                remediation=finding.remediation,
            )
            groups[finding.rule_id] = group
        group.count += 1
        if finding.confidence_score > group.confidence_score:  # keep the strongest instance's confidence
            group.confidence_score = finding.confidence_score
            group.confidence = finding.confidence
        label = _location_label(finding)
        if label not in group.locations:
            group.locations.append(label)
    return sorted(groups.values(), key=lambda g: (severity_rank(g.severity), g.count), reverse=True)
