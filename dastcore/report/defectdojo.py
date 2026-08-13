"""DefectDojo "Generic Findings Import" JSON renderer.

DefectDojo (and, through it, Jira and other trackers) ingests findings via a generic import
format: a ``{"findings": [...]}`` object with a fixed field set. This maps each dastcore
``Finding`` onto it — Title-case severity, integer CWE, the stable ``Finding.id`` as
``unique_id_from_tool`` so re-imports deduplicate instead of piling up, the target URL as the
endpoint, and the remediation/OWASP reference carried across. Pure and deterministic.
"""

from __future__ import annotations

import datetime as _dt
import json
import re

from dastcore.core.models import Finding

# dastcore severities are lowercase; DefectDojo expects Title-case (Info, not "info").
_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def _cwe_int(cwe: str) -> int:
    """The numeric CWE id (``CWE-89`` → 89); 0 when the finding carries no CWE number."""
    match = re.search(r"\d+", cwe or "")
    return int(match.group(0)) if match else 0


def _finding_dict(finding: Finding, today: str) -> dict:
    location = finding.injection_point
    description = (
        f"{finding.name}\n\n"
        f"Location: {finding.request.method} {finding.request.url} "
        f"({location.location}:{location.name})\n"
        f"Evidence: " + " | ".join(f"{e.type}: {e.data}" for e in finding.evidence)
    )
    return {
        "title": finding.name,
        "description": description,
        "severity": _SEVERITY.get(finding.severity, "Info"),
        "cwe": _cwe_int(finding.cwe),
        "date": today,
        "references": finding.owasp,
        "mitigation": finding.remediation,
        "impact": f"CVSS {finding.cvss_score:.1f} ({finding.cvss_vector})",
        "unique_id_from_tool": finding.id,  # stable id → DefectDojo deduplicates re-imports
        "vuln_id_from_tool": finding.rule_id,
        "endpoints": [finding.request.url],
        "active": True,
        "verified": True,  # every dastcore finding is oracle-confirmed
        "false_p": finding.suppressed,
        "dynamic_finding": True,
    }


def render_defectdojo(findings: list[Finding]) -> str:
    """Serialize findings to DefectDojo's Generic Findings Import JSON."""
    today = _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%d")
    return json.dumps({"findings": [_finding_dict(f, today) for f in findings]}, indent=2, ensure_ascii=False)
