"""Regression-alert notifications for the control-plane.

When a job finishes with findings that are NEW versus the project's previous scan of the same
target — and at or above the configured ``min_severity`` — the control-plane POSTs an alert to
the project's webhook. Two shapes: a Slack-compatible message (``slack``) ready for an incoming
webhook, and a structured JSON body (``generic``) for any other consumer. Sending is
best-effort: a webhook that is down or slow never fails or blocks the job it describes.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from dastcore.cloud.store import JobRow, NotificationRow
from dastcore.core.models import Finding
from dastcore.severity import SEVERITY_ORDER, meets_threshold, severity_rank

_SEND_TIMEOUT_S = 10.0


def filter_by_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    """Only the findings at or above ``min_severity`` (regression alerts skip the noise floor)."""
    return [f for f in findings if meets_threshold(f.severity, min_severity)]  # type: ignore[arg-type]


def _location(finding: Finding) -> str:
    path = urlsplit(finding.request.url).path or "/"
    point = finding.injection_point
    return f"{finding.request.method} {path} ({point.location}:{point.name})"


def _counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def build_slack_payload(project_name: str, job: JobRow, new_findings: list[Finding]) -> dict:
    """A Slack incoming-webhook message summarising the regression."""
    ordered = sorted(new_findings, key=lambda f: severity_rank(f.severity), reverse=True)
    header = f":rotating_light: dastcore: {len(new_findings)} nuevo(s) hallazgo(s) en *{project_name}*"
    lines = [f"Objetivo: `{job.target}` · job `{job.id}`", ""]
    lines += [f"• *{f.severity}* — {f.name} · `{_location(f)}`" for f in ordered[:20]]
    if len(ordered) > 20:
        lines.append(f"…y {len(ordered) - 20} más.")
    text = header + "\n" + "\n".join(lines)
    return {
        "text": text,
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": header}},
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
        ],
    }


def build_generic_payload(project_id: str, project_name: str, job: JobRow, new_findings: list[Finding]) -> dict:
    """A structured JSON body for any (non-Slack) webhook consumer."""
    return {
        "event": "regression",
        "project_id": project_id,
        "project": project_name,
        "job_id": job.id,
        "target": job.target,
        "new_findings_count": len(new_findings),
        "severity_counts": _counts(new_findings),
        "new_findings": [
            {
                "rule_id": f.rule_id,
                "name": f.name,
                "severity": f.severity,
                "cwe": f.cwe,
                "owasp": f.owasp,
                "location": _location(f),
            }
            for f in sorted(new_findings, key=lambda f: severity_rank(f.severity), reverse=True)
        ],
    }


async def send_regression_alert(
    notification: NotificationRow,
    project_id: str,
    project_name: str,
    job: JobRow,
    new_findings: list[Finding],
) -> bool:
    """POST the regression alert to the project's webhook. Best-effort: returns True on a 2xx,
    False on any error (a down/slow webhook must never fail the job it describes)."""
    if notification.format == "slack":
        payload = build_slack_payload(project_name, job, new_findings)
    else:
        payload = build_generic_payload(project_id, project_name, job, new_findings)
    try:
        async with httpx.AsyncClient(timeout=_SEND_TIMEOUT_S) as client:
            response = await client.post(notification.webhook_url, json=payload)
        return response.status_code < 400
    except httpx.HTTPError:
        return False
