"""Deduplication and correlation of findings.

`deduplicate` drops exact repeats (same finding id) that can slip in when the
same request is reached by more than one path (e.g. `--engine both` or a resume
+ rescan). `correlate` groups findings by rule into a single logical *issue* with
an instance count and the affected locations — the at-a-glance view a pentester
wants instead of a flat list of near-identical rows.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from dastcore.config import Severity
from dastcore.core.models import Confidence, Finding
from dastcore.severity import severity_rank

_CWE_RE = re.compile(r"cwe[-_/ ]?0*(\d+)", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")  # includes short param names (q, id, u)
_SAST_TAG = "SAST:"  # prefix on corroborated_by entries added by static-analysis correlation


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
    impact: str = ""  # proof-of-impact from the strongest instance, if any was demonstrated


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
        if finding.impact and not group.impact:  # surface the first proven impact for the issue
            group.impact = finding.impact
        label = _location_label(finding)
        if label not in group.locations:
            group.locations.append(label)
    return sorted(groups.values(), key=lambda g: (severity_rank(g.severity), g.count), reverse=True)


# --- SAST <-> DAST correlation ----------------------------------------------------------------
# Ingest a sibling static analyzer's SARIF and, where a static finding lines up with a dynamic one
# (same CWE + a shared parameter/route locator), raise the dynamic finding's confidence and mark it
# "confirmed by SAST+DAST". Correlation only *strengthens* an already-oracle-confirmed finding; it
# never creates one.


@dataclass
class SastFinding:
    """A static-analysis result parsed from SARIF, reduced to what correlation needs."""

    rule_id: str
    cwe: str  # normalized "CWE-<n>" ("" if none)
    file: str
    line: int | None
    message: str
    locators: set[str] = field(default_factory=set)  # lowercased tokens: params/routes/identifiers


def _norm_cwe(text: str) -> str:
    match = _CWE_RE.search(text or "")
    return f"CWE-{int(match.group(1))}" if match else ""


def parse_sarif(document: dict) -> list[SastFinding]:
    """Parse a SARIF 2.1.0 document into ``SastFinding``s (tolerant of missing fields / tools)."""
    findings: list[SastFinding] = []
    for run in document.get("runs", []) if isinstance(document, dict) else []:
        rule_cwe: dict[str, str] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            tags = " ".join(str(t) for t in rule.get("properties", {}).get("tags", []))
            rule_cwe[rule.get("id", "")] = _norm_cwe(f"{rule.get('id', '')} {tags} {rule.get('name', '')}")
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = str(result.get("message", {}).get("text", ""))
            props_cwe = _norm_cwe(" ".join(str(v) for v in result.get("properties", {}).values()))
            cwe = props_cwe or rule_cwe.get(rule_id, "") or _norm_cwe(rule_id)
            uri, line = "", None
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "") or uri
                line = phys.get("region", {}).get("startLine", line)
            locators = {t.lower() for t in _TOKEN_RE.findall(f"{message} {uri}")}
            locators |= {seg.lower() for seg in re.split(r"[/\\.]", uri) if seg}
            findings.append(SastFinding(rule_id, cwe, uri, line, message, locators))
    return findings


def _correlates(dast: Finding, sast: SastFinding) -> bool:
    """A dynamic and a static finding line up: same CWE, and a shared parameter or route locator."""
    if not sast.cwe or _norm_cwe(dast.cwe) != sast.cwe:
        return False
    param = dast.injection_point.name.lower()
    segments = [seg.lower() for seg in urlsplit(dast.request.url).path.split("/") if seg]
    return (bool(param) and param in sast.locators) or any(seg in sast.locators for seg in segments)


def correlate_sast_dast(dast_findings: list[Finding], sast_findings: list[SastFinding]) -> list[Finding]:
    """Annotate each dynamic finding confirmed by a static one (raises its confidence in place)."""
    for finding in dast_findings:
        for sast in sast_findings:
            if _correlates(finding, sast):
                tag = f"{_SAST_TAG}{sast.rule_id or sast.cwe}"
                if tag not in finding.corroborated_by:
                    finding.corroborated_by = [*finding.corroborated_by, tag]  # +confidence, marks SAST+DAST
                break
    return dast_findings


def is_sast_confirmed(finding: Finding) -> bool:
    """True if this finding was corroborated by a static-analysis (SAST) result."""
    return any(entry.startswith(_SAST_TAG) for entry in finding.corroborated_by)
