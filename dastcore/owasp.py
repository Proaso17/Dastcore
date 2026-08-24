"""OWASP Top 10 (2021) coverage model — classify every finding into an OWASP category and describe,
per category, what dastcore dynamically tests. Drives the coverage summary shown in the CLI, the JSON/
SARIF report, and the web dashboard, so a user can see at a glance which OWASP risks were exercised
across the whole discovered surface and what turned up.

Classification is primarily by **rule/detector family** (intuitive and stable — we own the ids/names),
with the finding's **CWE** as a fallback for anything a keyword doesn't catch.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dastcore.core.models import Finding

# The ten categories, in order. Ids are the canonical OWASP 2021 short codes.
OWASP_2021: list[tuple[str, str]] = [
    ("A01", "Broken Access Control"),
    ("A02", "Cryptographic Failures"),
    ("A03", "Injection"),
    ("A04", "Insecure Design"),
    ("A05", "Security Misconfiguration"),
    ("A06", "Vulnerable and Outdated Components"),
    ("A07", "Identification and Authentication Failures"),
    ("A08", "Software and Data Integrity Failures"),
    ("A09", "Security Logging and Monitoring Failures"),
    ("A10", "Server-Side Request Forgery (SSRF)"),
]
_NAMES = dict(OWASP_2021)

# What dastcore can dynamically exercise per category (black-box):
#   full = strong active coverage · partial = meaningful but not exhaustive · none = not DAST-observable.
CAPABILITY: dict[str, str] = {
    "A01": "full",     # BOLA/IDOR/BFLA, access-bypass, path traversal/LFI, open redirect, CSRF
    "A02": "partial",  # insecure transport, insecure/HTTPOnly-less cookies, secret exposure (no full crypto audit)
    "A03": "full",     # SQLi/XSS/SSTI/LFI/CMDi/NoSQL/LDAP/XPath/CRLF/SSI/code/header injection
    "A04": "partial",  # some design smells (clickjacking, verbose errors); design review is largely not DAST
    "A05": "full",     # headers, CORS, sensitive files, TRACE, dangerous methods, actuator, XXE, default creds
    "A06": "partial",  # technology/version fingerprint (no full SCA/CVE database)
    "A07": "full",     # weak/default creds, JWT attacks, session fixation, auth bypass, user enumeration
    "A08": "full",     # insecure deserialization, mass assignment, prototype pollution, subdomain takeover
    "A09": "none",     # logging/monitoring failures aren't observable from the outside
    "A10": "full",     # SSRF confirmed out-of-band (OAST)
}

# Rule/detector family keywords -> category. Checked (as substrings) against rule_id then name, lowercased.
# Order matters: the first category with a matching keyword wins, so list the more specific ones first.
_KEYWORD_TO_CAT: list[tuple[str, tuple[str, ...]]] = [
    ("A10", ("ssrf",)),
    ("A07", ("jwt", "auth-bypass", "authentication", "login", "session", "weak-cred", "default-cred",
             "credential", "brute", "user-enum", "enumerat", "session-fixation", "mfa", "oauth",
             "password-reset", "reset-poison")),
    ("A08", ("deserial", "mass-assignment", "mass assignment", "proto-pollution", "prototype",
             "integrity", "takeover", "smuggling", "unsigned")),
    ("A03", ("sqli", "sql-injection", "xss", "ssti", "template-injection", "cmdi", "command-injection",
             "ldap", "xpath", "crlf", "code-injection", "ssi", "nosql", "response-splitting",
             "header-injection", "host-header", "injection")),
    ("A01", ("idor", "bola", "bfla", "authz", "access-bypass", "access-control", "path-traversal",
             "traversal", "lfi", "open-redirect", "redirect", "directory-listing", "csrf",
             "forced-browsing", "unauth-access")),
    ("A05", ("misconfig", "security-header", "missing-header", "cors", "sensitive-file", "exposed",
             "actuator", "trace-method", "dangerous-method", "clickjacking", "verbose-error",
             "stack-trace", "xxe", "xml-expansion", "redos", "default", "cache-poison",
             "cache-deception", "web-cache", "csp")),
    ("A02", ("cleartext", "insecure-transport", "hsts", "secret-exposure", "secret", "sensitive-cookie",
             "insecure-cookie", "cookie-secure", "tls")),
    ("A06", ("version-disclosure", "outdated", "component", "cve", "vulnerable-version", "version",
             "tech-fingerprint", "fingerprint")),
    ("A04", ("insecure-design", "business-logic", "race")),
]

# CWE -> category fallback (OWASP-2021-aligned; a few pragmatic choices for how the finding presents).
_CWE_TO_CAT: dict[str, str] = {
    # A01 Broken Access Control
    "22": "A01", "23": "A01", "35": "A01", "59": "A01", "200": "A01", "201": "A01", "275": "A01",
    "276": "A01", "284": "A01", "285": "A01", "352": "A01", "538": "A01", "540": "A01", "548": "A01",
    "601": "A01", "639": "A01", "668": "A01", "862": "A01", "863": "A01", "1275": "A01",
    # A02 Cryptographic Failures
    "311": "A02", "312": "A02", "319": "A02", "326": "A02", "327": "A02", "328": "A02", "522": "A02",
    "759": "A02", "760": "A02",
    # A03 Injection
    "78": "A03", "79": "A03", "89": "A03", "90": "A03", "91": "A03", "93": "A03", "94": "A03",
    "95": "A03", "96": "A03", "97": "A03", "98": "A03", "113": "A03", "564": "A03", "643": "A03",
    "644": "A03", "917": "A03", "943": "A03", "1336": "A03",
    # A04 Insecure Design
    "209": "A04", "501": "A04", "602": "A04", "807": "A04", "840": "A04", "1021": "A04", "1173": "A04",
    # A05 Security Misconfiguration
    "16": "A05", "260": "A05", "315": "A05", "520": "A05", "526": "A05", "537": "A05", "611": "A05",
    "614": "A05", "615": "A05", "693": "A05", "756": "A05", "776": "A05", "942": "A05", "1004": "A05",
    "1032": "A05", "1327": "A08",
    # A06 Vulnerable and Outdated Components
    "937": "A06", "1035": "A06", "1104": "A06",
    # A07 Identification and Authentication Failures
    "247": "A07", "287": "A07", "290": "A07", "294": "A07", "295": "A07", "306": "A07", "307": "A07",
    "346": "A07", "347": "A07", "384": "A07", "521": "A07", "524": "A07", "613": "A07", "620": "A07",
    "640": "A07", "798": "A07", "940": "A07", "1216": "A07", "1391": "A07",
    # A08 Software and Data Integrity Failures
    "345": "A08", "353": "A08", "444": "A08", "494": "A08", "502": "A08", "829": "A08", "915": "A08",
    "1321": "A08",
    # A10 SSRF
    "918": "A10",
}

_CWE_RE = re.compile(r"CWE[-_]?(\d+)", re.IGNORECASE)


# Match a keyword only at the *start* of a token (preceded by a non-letter), so a keyword can be a
# prefix ("deserial" → "deserialization") yet a short one like "ssi" never matches inside "mi**ssi**ng".
_KEYWORD_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (cat, re.compile(r"(?<![a-z])(?:" + "|".join(re.escape(k) for k in kws) + r")"))
    for cat, kws in _KEYWORD_TO_CAT
]

# dastcore-internal advisories (coverage notes, SPA/engine hints) — informational meta about the *scan*,
# not vulnerabilities of the target, so they're kept out of the OWASP rollup (they'd otherwise pollute a
# category via their generic CWE-200). WAF/tech-fingerprint stay: they say something about the target.
_ADVISORY_RULE_IDS: frozenset[str] = frozenset({"scan-coverage", "spa-detected", "spa-awareness"})


def is_advisory(finding: Finding) -> bool:
    """A dastcore meta/advisory finding (not a target vulnerability) — excluded from the OWASP rollup."""
    return finding.rule_id in _ADVISORY_RULE_IDS


def category_for(finding: Finding) -> str:
    """The OWASP 2021 category id (``A01``…``A10``) for a finding — family keyword first, then CWE."""
    haystack = f"{finding.rule_id or ''} {finding.name or ''}".lower()
    for cat, pattern in _KEYWORD_PATTERNS:
        if pattern.search(haystack):
            return cat
    match = _CWE_RE.search(finding.cwe or "")
    if match:
        cat = _CWE_TO_CAT.get(match.group(1))
        if cat:
            return cat
    return "A05"  # a sane default: an unclassified web finding is most often a misconfiguration


_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _worst(severities: Iterable[str]) -> str:
    present = set(severities)
    for sev in _SEV_ORDER:
        if sev in present:
            return sev
    return "info"


def summarize(findings: Sequence[Finding]) -> list[dict[str, object]]:
    """A per-category rollup for all ten OWASP categories, in canonical order.

    Each entry: id, name, capability, findings count, worst severity, and the finding ids — so a report
    can show every category (even those with zero findings) alongside what dastcore tested for it.
    """
    buckets: dict[str, list[Finding]] = {cat: [] for cat, _ in OWASP_2021}
    for finding in findings:
        if is_advisory(finding):
            continue  # scan meta (coverage notes, SPA hints) aren't target vulns — keep them out
        buckets.setdefault(category_for(finding), []).append(finding)
    summary: list[dict[str, object]] = []
    for cat, name in OWASP_2021:
        items = buckets.get(cat, [])
        summary.append({
            "id": f"{cat}:2021",
            "code": cat,
            "name": name,
            "capability": CAPABILITY.get(cat, "partial"),
            "count": len(items),
            "worst_severity": _worst(f.severity for f in items) if items else None,
            "finding_ids": [f.id for f in items],
        })
    return summary
