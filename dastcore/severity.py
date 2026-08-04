"""Severity ordering and cross-format mappings.

Single source of truth so the SARIF `level`, the HTML badges, and the CI/CD
exit-code gate all agree on how severities rank and translate.
"""
from __future__ import annotations

from dastcore.config import Severity

# Ordered low -> high; index gives the rank used for threshold comparisons.
SEVERITY_ORDER: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")

# SARIF 2.1.0 result levels.
_SARIF_LEVEL: dict[Severity, str] = {
    "info": "none",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}

# GitHub code-scanning reads this numeric CVSS-like score from result properties.
_SECURITY_SEVERITY: dict[Severity, str] = {
    "info": "0.0",
    "low": "3.0",
    "medium": "5.5",
    "high": "8.0",
    "critical": "9.5",
}


def severity_rank(severity: Severity) -> int:
    return SEVERITY_ORDER.index(severity)


def meets_threshold(severity: Severity, threshold: Severity) -> bool:
    """True if `severity` is at least as severe as `threshold`."""
    return severity_rank(severity) >= severity_rank(threshold)


def sarif_level(severity: Severity) -> str:
    return _SARIF_LEVEL[severity]


def security_severity_score(severity: Severity) -> str:
    return _SECURITY_SEVERITY[severity]
