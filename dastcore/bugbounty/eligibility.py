"""Bug-bounty eligibility filter.

Bug-bounty programs (HackerOne Core's standard "ineligible findings" list, and most others) close a
whole class of results as invalid: security hardening / missing best-practices (headers, TLS config,
cookie flags), version/banner disclosure, tabnabbing, content spoofing / reflection without demonstrated
impact, permissive CORS/CSRF with no sensitive action, open redirects without extra impact. DASTCore
surfaces these by design (they matter for a hardening review), but in a bug-bounty context they are
noise that drowns the reportable, impactful findings and hurts a researcher's signal if submitted.

"Bug-bounty mode" doesn't delete them — it marks them ``suppressed`` with a clear reason, so the report
and the fail-gate count only the potentially-reportable findings, while the rest stay visible (and can be
promoted after a human verifies real-world impact). Impactful classes (SQLi, XSS, IDOR/BOLA, auth bypass,
SSRF, RCE, injection…) are never touched.
"""

from __future__ import annotations

from dastcore.core.models import Finding

# Exact rule ids a bug-bounty triage almost always closes as N/A (hardening / disclosure / no-impact),
# plus DASTCore's own informational advisories (fingerprint, WAF/ASN notes, coverage).
_INELIGIBLE_RULES: frozenset[str] = frozenset({
    # Missing security headers / hardening
    "passive-missing-csp",
    "passive-missing-hsts",
    "passive-missing-x-content-type-options",
    "passive-missing-x-frame-options",  # clickjacking on pages with no sensitive action
    # Tabnabbing
    "passive-reverse-tabnabbing",
    # Version / banner / descriptive-error disclosure
    "passive-tech-disclosure",
    "passive-error-disclosure",
    # Cookie flags
    "passive-insecure-cookie",
    "passive-cookie-samesite-none",
    # Permissive CORS / CSRF without demonstrated impact
    "passive-cors-wildcard-with-credentials",
    "csrf-token-not-enforced",
    # Content spoofing / Host-header reflection without demonstrated impact
    "host-header-injection",
    # DASTCore's own informational output (never a bounty finding)
    "tech-fingerprint",
    "waf-detected",
    "asn-footprint",
    "scan-coverage",
    "waf-blocking",
})

# Whole families that are ineligible: TLS/SSL configuration, and open redirects (without extra impact).
_INELIGIBLE_FAMILIES: frozenset[str] = frozenset({"tls", "open_redirect"})

_REASON = (
    "Inelegible en bug bounty (HackerOne Core: hardening / best-practice / disclosure / sin impacto "
    "demostrado). Verifica impacto real antes de reportar; si lo demuestras, promuévelo a mano."
)


def is_ineligible(finding: Finding) -> bool:
    """Whether a finding is in the class bug-bounty programs close as N/A (hardening/disclosure/no-impact)."""
    return finding.rule_id in _INELIGIBLE_RULES or finding.family in _INELIGIBLE_FAMILIES


def mark_ineligible(findings: list[Finding]) -> int:
    """Suppress (in place) every ineligible finding with a clear reason; return how many were marked.

    Already-suppressed findings (e.g. a ``.dastcore-ignore`` triage) keep their own reason — this never
    overrides an existing suppression, and never touches an eligible/impactful finding.
    """
    marked = 0
    for finding in findings:
        if not finding.suppressed and is_ineligible(finding):
            finding.suppressed = True
            finding.suppression_reason = _REASON
            marked += 1
    return marked
