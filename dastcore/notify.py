"""Delta alerting for the self-hosted path — "ping me only when something NEW appears".

Turns a scan's *new-since-last* findings into a webhook alert. Three payload shapes are supported so it
drops into whatever the operator already runs: a Slack incoming webhook, a Discord webhook, and a
structured ``generic`` JSON body for anything else. Sending is best-effort — a webhook that is down or
slow never fails or blocks the scan it describes.

Both the dashboard (scheduled + manual scans) and the CLI (`scan --notify-webhook`, cron-friendly) use
this, so a continuous-monitoring loop is just: schedule a scan → diff against the previous run → alert.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from dastcore.core.models import Finding
from dastcore.severity import SEVERITY_ORDER, meets_threshold, severity_rank

_SEND_TIMEOUT_S = 10.0
_MAX_LINES = 20
_DISCORD_LIMIT = 1900  # Discord webhook 'content' hard limit is 2000; leave headroom.

Format = str  # "slack" | "discord" | "generic"


def filter_by_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    """Only findings at or above ``min_severity`` — the alert's noise floor."""
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


def _ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: severity_rank(f.severity), reverse=True)


def _summary_lines(target: str, findings: list[Finding]) -> tuple[str, list[str]]:
    header = f":rotating_light: {len(findings)} hallazgo(s) nuevo(s) en `{target}`"
    ordered = _ordered(findings)
    lines = [f"• *{f.severity}* — {f.name} · `{_location(f)}`" for f in ordered[:_MAX_LINES]]
    if len(ordered) > _MAX_LINES:
        lines.append(f"…y {len(ordered) - _MAX_LINES} más.")
    return header, lines


def build_slack_payload(target: str, findings: list[Finding]) -> dict:
    header, lines = _summary_lines(target, findings)
    body = "\n".join(lines)
    return {
        "text": header + "\n" + body,
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": header}},
            {"type": "section", "text": {"type": "mrkdwn", "text": body or "_—_"}},
        ],
    }


def build_discord_payload(target: str, findings: list[Finding]) -> dict:
    header, lines = _summary_lines(target, findings)
    # Discord uses ** for bold, not * — and has a tight length cap.
    content = (header + "\n" + "\n".join(lines)).replace("*", "**").replace("::", ":")
    return {"content": content[:_DISCORD_LIMIT]}


def build_generic_payload(target: str, findings: list[Finding]) -> dict:
    return {
        "event": "regression",
        "target": target,
        "findings_count": len(findings),
        "severity_counts": _counts(findings),
        "findings": [
            {
                "rule_id": f.rule_id, "name": f.name, "severity": f.severity,
                "cwe": f.cwe, "owasp": f.owasp, "location": _location(f),
            }
            for f in _ordered(findings)
        ],
    }


def build_payload(fmt: Format, target: str, findings: list[Finding]) -> dict:
    if fmt == "slack":
        return build_slack_payload(target, findings)
    if fmt == "discord":
        return build_discord_payload(target, findings)
    return build_generic_payload(target, findings)


async def send_alert(webhook_url: str, fmt: Format, target: str, findings: list[Finding]) -> bool:
    """POST the alert. Best-effort: True on a 2xx, False on any error (never raises)."""
    if not webhook_url or not findings:
        return False
    payload = build_payload(fmt, target, findings)
    try:
        async with httpx.AsyncClient(timeout=_SEND_TIMEOUT_S) as client:
            response = await client.post(webhook_url, json=payload)
        return response.status_code < 400
    except httpx.HTTPError:
        return False
