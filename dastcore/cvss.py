"""CVSS 3.1 base-score calculation.

Implements the official CVSS v3.1 base-score formula so every finding can carry
an objective numeric score and vector alongside its qualitative severity. A
finding without an explicit vector falls back to a representative vector for its
severity band via ``default_vector``.
"""

from __future__ import annotations

import math

from dastcore.config import Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

# Representative canonical vectors per qualitative severity (used when a rule
# doesn't provide its own vector).
_DEFAULT_VECTORS: dict[Severity, str] = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",  # 10.0
    "high": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  # 6.1
    "low": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",  # 3.1
    "info": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",  # 0.0
}


def default_vector(severity: Severity) -> str:
    return _DEFAULT_VECTORS[severity]


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS vector string into a metric->value dict (the CVSS:3.x prefix is optional)."""
    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        key = key.strip().upper()
        if key in ("CVSS",):
            continue
        metrics[key] = value.strip().upper()
    return metrics


def _roundup(value: float) -> float:
    # Official CVSS 3.1 roundup: ceil to one decimal, float-safe.
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Compute the CVSS 3.1 base score (0.0–10.0) for a vector string."""
    m = parse_vector(vector)
    try:
        scope_changed = m["S"] == "C"
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except KeyError:
        return 0.0
    if impact <= 0:
        return 0.0
    combined = 1.08 * (impact + exploitability) if scope_changed else (impact + exploitability)
    return _roundup(min(combined, 10.0))


def severity_from_score(score: float) -> Severity:
    """Map a CVSS base score to its qualitative rating (CVSS 3.1 bands)."""
    if score == 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
