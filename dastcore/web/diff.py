"""Scan-to-scan diff: what changed between two runs of the same target.

Both sides are full scans with the same rule coverage, so comparing by the stable
`Finding.id` is honest: a finding present in the older run but absent in the newer
one is genuinely fixed (unlike a retest, where coverage differs). Findings are
partitioned into new (regressions/appeared), fixed (gone), and persistent (both).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from dastcore.core.models import Finding


@dataclass
class FindingDiff:
    """Findings partitioned by how they changed from a base run to a head run."""

    new: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    persistent: list[Finding] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return {"new": len(self.new), "fixed": len(self.fixed), "persistent": len(self.persistent)}


def diff_findings(base: list[Finding], head: list[Finding]) -> FindingDiff:
    """Diff two finding sets by id: base = older run, head = newer run."""
    base_ids = {f.id for f in base}
    head_ids = {f.id for f in head}
    return FindingDiff(
        new=[f for f in head if f.id not in base_ids],
        fixed=[f for f in base if f.id not in head_ids],
        persistent=[f for f in head if f.id in base_ids],
    )


def location_label(finding: Finding) -> str:
    """A compact 'METHOD /path (location:name)' label for a finding."""
    path = urlsplit(finding.request.url).path or "/"
    point = finding.injection_point
    return f"{finding.request.method} {path} ({point.location}:{point.name})"
