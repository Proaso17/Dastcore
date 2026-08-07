"""SARIF 2.1.0 report renderer.

Produces a static-analysis-interchange document consumable by CI/CD code
scanning (e.g. GitHub). Findings that share a `rule_id` collapse into a single
`reportingDescriptor` (rule) under the tool driver; each finding becomes one
`result` referencing that rule by id, carrying its own location and evidence.
"""

from __future__ import annotations

import json
import re

from dastcore import __version__
from dastcore.core.models import Finding
from dastcore.severity import sarif_level

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
_TOOL_URI = "https://github.com/dastcore/dastcore"

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _help_uri(finding: Finding) -> str:
    match = _CWE_RE.search(finding.cwe)
    if match:
        return f"https://cwe.mitre.org/data/definitions/{match.group(1)}.html"
    return _TOOL_URI


def _evidence_text(finding: Finding) -> str:
    if not finding.evidence:
        return "no evidence"
    return "; ".join(f"{ev.type}: {ev.data}" for ev in finding.evidence)


def _build_rule(finding: Finding) -> dict:
    return {
        "id": finding.rule_id,
        "name": finding.name,
        "shortDescription": {"text": finding.name},
        "fullDescription": {"text": finding.remediation},
        "helpUri": _help_uri(finding),
        "help": {"text": finding.remediation},
        "defaultConfiguration": {"level": sarif_level(finding.severity)},
        "properties": {
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            # GitHub code scanning reads this 0–10 number: use the real CVSS base score.
            "security-severity": f"{finding.cvss_score:.1f}",
            "tags": ["security", finding.cwe, finding.owasp],
        },
    }


def _build_result(finding: Finding) -> dict:
    point = finding.injection_point
    message = (
        f"{finding.name} at [{point.location}] parameter '{point.name}' "
        f"of {finding.request.method} {finding.request.url}. Evidence: {_evidence_text(finding)}."
    )
    result: dict = {
        "ruleId": finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.request.url},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": f"{point.location}:{point.name}", "kind": "parameter"}],
            }
        ],
        "partialFingerprints": {"dastcoreFindingId": finding.id},
        "properties": {
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            "severity": finding.severity,
            "security-severity": f"{finding.cvss_score:.1f}",
            "cvss": finding.cvss_vector,
            "cvss_score": finding.cvss_score,
            "confidence": finding.confidence,
            "confidence_score": finding.confidence_score,
            "evidence": [ev.model_dump(mode="json") for ev in finding.evidence],
            "repro": finding.request.to_curl(),
        },
    }
    if finding.suppressed:
        # GitHub code scanning reads this to show the alert as dismissed, not open.
        result["suppressions"] = [
            {"kind": "external", "justification": finding.suppression_reason or "suppressed via .dastcore-ignore"}
        ]
    return result


def build_sarif(findings: list[Finding]) -> dict:
    rules_by_id: dict[str, dict] = {}
    for finding in findings:
        rules_by_id.setdefault(finding.rule_id, _build_rule(finding))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dastcore",
                        "informationUri": _TOOL_URI,
                        "version": __version__,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": [_build_result(finding) for finding in findings],
            }
        ],
    }


def render_sarif(findings: list[Finding], *, indent: int = 2) -> str:
    return json.dumps(build_sarif(findings), indent=indent, ensure_ascii=False)
