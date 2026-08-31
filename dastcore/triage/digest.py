"""Triage copilot: a deterministic digest that turns a raw finding list into "handle these first".

The real bottleneck of a scan is not finding count — it is deciding *what to look at*. This layer sits
strictly downstream of the oracle (it never confirms, creates, or elevates a finding) and reorganises
the confirmed findings for a human:

* **Cluster across hosts** — the same vulnerability class on the same injection point, seen on many
  hosts, collapses into one cluster that rolls up every affected host. One line instead of thirty.
* **Rank by urgency** — clusters are ordered by the deterministic exploitability band (``triage.scoring``)
  and then by how many hosts they hit.
* **Separate likely false-positives** — clusters whose representative finding is below the engine's
  confidence bar are split into a "review" bucket, so the "priority" bucket is submission-grade.

Pure and deterministic: no network, no AI. It reuses the existing ``triage.scoring`` ordering and the
engine's own ``confidence_score``; it does not touch the scanner, the report, or the AI-triage layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from dastcore.core.models import Finding
from dastcore.triage.scoring import exploitability_score, priority_band

_CONFIDENCE_BAR = 0.5  # below this, a finding is routed to the "review / possible FP" bucket
_BAND_WEIGHT = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}


def _host(finding: Finding) -> str:
    return (urlsplit(finding.request.url).hostname or "").lower()


def _cluster_key(finding: Finding) -> str:
    """Identity that collapses the same class+injection-point *across hosts* into one cluster."""
    point = finding.injection_point
    return f"{finding.rule_id}|{point.location}:{point.name}"


@dataclass
class TriageCluster:
    """One vulnerability class on one injection point, rolled up across every host it was seen on."""

    rule_id: str
    name: str
    family: str
    severity: str
    band: str  # deterministic fix-priority band of the representative (P1 = first)
    exploitability: float
    hosts: list[str]  # distinct affected hosts, sorted
    count: int  # raw findings collapsed into this cluster
    example: str  # a compact location label for the representative
    fp_risk: bool  # representative is below the confidence bar -> verify before trusting
    representative: Finding

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "name": self.name, "family": self.family, "severity": self.severity,
            "band": self.band, "exploitability": self.exploitability, "hosts": self.hosts,
            "host_count": self.host_count, "count": self.count, "example": self.example,
            "fp_risk": self.fp_risk,
        }


@dataclass
class TriageDigest:
    """The copilot's output: prioritised clusters, a review bucket, and headline counts."""

    priority: list[TriageCluster] = field(default_factory=list)  # submission-grade, ranked
    review: list[TriageCluster] = field(default_factory=list)  # below the confidence bar, ranked
    total_findings: int = 0
    distinct_hosts: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)

    @property
    def clusters(self) -> list[TriageCluster]:
        return self.priority + self.review

    def to_dict(self) -> dict:
        return {
            "total_findings": self.total_findings,
            "distinct_hosts": self.distinct_hosts,
            "cluster_count": len(self.clusters),
            "severity_counts": self.severity_counts,
            "priority": [c.to_dict() for c in self.priority],
            "review": [c.to_dict() for c in self.review],
        }


def _location_label(finding: Finding) -> str:
    path = urlsplit(finding.request.url).path or "/"
    point = finding.injection_point
    return f"{finding.request.method} {path} ({point.location}:{point.name})"


def _make_cluster(findings: list[Finding]) -> TriageCluster:
    rep = max(findings, key=exploitability_score)  # the most exploitable member speaks for the cluster
    score = exploitability_score(rep)
    hosts = sorted({_host(f) for f in findings if _host(f)})
    return TriageCluster(
        rule_id=rep.rule_id, name=rep.name, family=rep.family, severity=rep.severity,
        band=priority_band(score), exploitability=score, hosts=hosts, count=len(findings),
        example=_location_label(rep), fp_risk=rep.confidence_score < _CONFIDENCE_BAR, representative=rep,
    )


def _rank_key(cluster: TriageCluster) -> tuple[int, float, int]:
    return (_BAND_WEIGHT.get(cluster.band, 0), cluster.exploitability, cluster.host_count)


def build_digest(findings: list[Finding]) -> TriageDigest:
    """Cluster, rank, and bucket confirmed findings into a triage digest. Suppressed findings are
    skipped (already triaged out); nothing here changes a finding."""
    active = [f for f in findings if not f.suppressed]
    groups: dict[str, list[Finding]] = {}
    for finding in active:
        groups.setdefault(_cluster_key(finding), []).append(finding)
    clusters = [_make_cluster(group) for group in groups.values()]

    priority = sorted((c for c in clusters if not c.fp_risk), key=_rank_key, reverse=True)
    review = sorted((c for c in clusters if c.fp_risk), key=_rank_key, reverse=True)

    severity_counts: dict[str, int] = {}
    for finding in active:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
    distinct_hosts = len({h for c in clusters for h in c.hosts})

    return TriageDigest(
        priority=priority, review=review, total_findings=len(active),
        distinct_hosts=distinct_hosts, severity_counts=severity_counts,
    )
