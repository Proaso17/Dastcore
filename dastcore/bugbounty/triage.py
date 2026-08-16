"""Bug-bounty triage: VRT priority + cross-asset dedupe + a false-positive gate + payout-aware ranking.

Layers bounty-specific judgement on top of the deterministic engine triage (``triage.scoring``), never
re-deciding whether a finding is real (the oracle already did that):

- **VRT**: map each finding to a Bugcrowd VRT category and priority (P1…P5), alongside its CVSS/CWE.
- **Dedupe**: collapse recurrences of the same ``(class, host, parameter)`` across assets/scans into one
  submission with a variant count.
- **FP gate**: an explicit checklist (exploitable now? deterministic repro? evidence attached?) backed by
  the finding's confidence and oracle evidence, plus an auto-discard list for informational noise.
- **Prioritise**: order by VRT band, then real impact (exploitability × expected payout).
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from dastcore.bugbounty.program import Program
from dastcore.core.models import Finding
from dastcore.triage.scoring import exploitability_score

# --- VRT mapping ------------------------------------------------------------------------------
# Specific rules win over the family default; unmapped classes fall back to a severity band.
_VRT_BY_RULE: dict[str, tuple[str, str]] = {
    "default-credentials": ("Broken Authentication - Weak/Default Credentials", "P1"),
    "insecure-deserialization": ("Server-Side Injection - Insecure Deserialization", "P1"),
    "log4shell-jndi": ("Server-Side Injection - Remote Code Execution", "P1"),
    "authz-bola": ("Broken Access Control - IDOR", "P2"),
    "authz-bfla": ("Broken Access Control - Privilege Escalation", "P2"),
    "authz-missing-auth": ("Broken Authentication - Missing Authentication", "P2"),
    "session-fixation": ("Broken Authentication - Session Fixation", "P3"),
    "dom-xss": ("Cross-Site Scripting (XSS) - DOM", "P3"),
    "http-request-smuggling": ("Server-Side Injection - HTTP Request Smuggling", "P2"),
}
_VRT_BY_FAMILY: dict[str, tuple[str, str]] = {
    "sqli": ("Server-Side Injection - SQL Injection", "P1"),
    "cmdi": ("Server-Side Injection - Remote Code Execution", "P1"),
    "code-injection": ("Server-Side Injection - Remote Code Execution", "P1"),
    "ssi": ("Server-Side Injection - Remote Code Execution", "P1"),
    "ssti": ("Server-Side Injection - Server-Side Template Injection", "P1"),
    "deserialization": ("Server-Side Injection - Insecure Deserialization", "P1"),
    "nosqli": ("Server-Side Injection - NoSQL Injection", "P1"),
    "xxe": ("Server-Side Injection - XML External Entity (XXE)", "P2"),
    "ssrf": ("Server-Side Injection - Server-Side Request Forgery (SSRF)", "P2"),
    "lfi": ("Server-Side Injection - File Inclusion (LFI)", "P2"),
    "xpath": ("Server-Side Injection - XPath Injection", "P2"),
    "ldap": ("Server-Side Injection - LDAP Injection", "P2"),
    "authz": ("Broken Access Control - IDOR", "P2"),
    "auth": ("Broken Authentication", "P2"),
    "upload": ("Unrestricted File Upload", "P2"),
    "cache-poisoning": ("Server Security Misconfiguration - Web Cache Poisoning", "P2"),
    "smuggling": ("Server-Side Injection - HTTP Request Smuggling", "P2"),
    "xss": ("Cross-Site Scripting (XSS) - Reflected", "P3"),
    "crlf": ("Server-Side Injection - HTTP Response Splitting", "P3"),
    "graphql": ("Broken Access Control - IDOR", "P2"),
    "open_redirect": ("Broken Access Control - Open Redirect", "P4"),
    "dos": ("Server Security Misconfiguration - Denial of Service", "P4"),
    "exposure": ("Sensitive Data Exposure", "P3"),
}
_SEV_VRT = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P5"}
_PRIORITY_WEIGHT = {"P1": 5, "P2": 4, "P3": 3, "P4": 2, "P5": 1}

# Informational classes that are essentially never payable — auto-discarded from bounty triage.
_NOISE_RULES = {
    "tech-fingerprint",
    "waf-detected",
    "passive-tech-disclosure",
    "passive-missing-x-content-type-options",
    "passive-missing-x-frame-options",
    "passive-missing-hsts",
    "passive-missing-csp",
    "passive-insecure-cookie",
    "passive-cookie-samesite-none",
    "passive-reverse-tabnabbing",
    "passive-directory-listing",
    "passive-error-disclosure",
}
# Evidence types that constitute a deterministic, oracle-backed reproduction.
_STRONG_EVIDENCE = {"oob", "differential", "time_based", "dom_execution"}


def vrt_for(finding: Finding) -> tuple[str, str]:
    """(VRT category, priority P1..P5) for a finding — rule override, then family, then severity."""
    if finding.rule_id in _VRT_BY_RULE:
        return _VRT_BY_RULE[finding.rule_id]
    if finding.family in _VRT_BY_FAMILY:
        return _VRT_BY_FAMILY[finding.family]
    return (f"Other ({finding.family or finding.rule_id})", _SEV_VRT.get(finding.severity, "P5"))


@dataclass
class FpChecklist:
    """An explicit, human-auditable false-positive gate for a bounty submission."""

    exploitable_now: bool  # the engine's confidence clears the bar
    deterministic_repro: bool  # a differential/OAST/time/DOM oracle (or a corroborating rule) backs it
    evidence_attached: bool  # there is at least one evidence entry

    @property
    def passes(self) -> bool:
        return self.exploitable_now and self.deterministic_repro and self.evidence_attached


def fp_checklist(finding: Finding) -> FpChecklist:
    return FpChecklist(
        exploitable_now=finding.confidence_score >= 0.5,
        deterministic_repro=any(e.type in _STRONG_EVIDENCE for e in finding.evidence) or bool(finding.corroborated_by),
        evidence_attached=len(finding.evidence) > 0,
    )


def dedupe_signature(finding: Finding) -> str:
    """(class, normalized host, parameter) — the identity used to collapse recurrences across assets."""
    cls = finding.family or finding.rule_id
    host = (urlsplit(finding.request.url).hostname or "").lower()
    point = finding.injection_point
    return f"{cls}|{host}|{point.location}:{point.name}"


@dataclass
class BountyFinding:
    """One deduplicated, VRT-rated, payout-aware submission candidate."""

    finding: Finding
    vrt_category: str
    vrt_priority: str
    cvss_vector: str
    expected_payout: float
    signature: str
    variants: int  # how many raw findings collapsed into this one
    priority_score: float  # composite sort key (higher = handle first)
    checklist: FpChecklist


def _priority_score(finding: Finding, vrt_priority: str, payout: float) -> float:
    """VRT band dominates; within a band, exploitability nudged by expected payout breaks ties."""
    base = exploitability_score(finding)  # 0..10
    payout_factor = 1.0 + min(max(payout, 0.0), 100_000.0) / 100_000.0  # up to 2x for large payouts
    return round(_PRIORITY_WEIGHT.get(vrt_priority, 1) * 10 + base * payout_factor, 3)


def triage_for_bounty(
    findings: list[Finding], program: Program | None = None, *, drop_noise: bool = True
) -> list[BountyFinding]:
    """Dedupe, gate false positives, rate against VRT, and rank findings for a bounty submission."""
    payouts = program.payouts if program else {}

    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        if drop_noise and finding.rule_id in _NOISE_RULES:
            continue
        if not fp_checklist(finding).passes:
            continue
        groups.setdefault(dedupe_signature(finding), []).append(finding)

    result: list[BountyFinding] = []
    for signature, members in groups.items():
        rep = max(members, key=lambda f: f.confidence_score)  # strongest instance represents the group
        category, priority = vrt_for(rep)
        payout = float(payouts.get(rep.family, payouts.get(rep.rule_id, 0.0)))
        result.append(
            BountyFinding(
                finding=rep,
                vrt_category=category,
                vrt_priority=priority,
                cvss_vector=rep.cvss or "",
                expected_payout=payout,
                signature=signature,
                variants=len(members),
                priority_score=_priority_score(rep, priority, payout),
                checklist=fp_checklist(rep),
            )
        )
    result.sort(key=lambda b: b.priority_score, reverse=True)
    return result
