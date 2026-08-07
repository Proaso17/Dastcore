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
