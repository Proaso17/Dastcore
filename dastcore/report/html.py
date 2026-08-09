"""Self-contained HTML report renderer (Jinja2).

Autoescaping is ON: because findings embed attacker-controlled strings (the very
XSS/SQLi payloads that triggered them), the report must render them as inert
text, never as live markup. The output is a single file with inlined CSS and no
external assets, safe to email or archive.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from dastcore import __version__
from dastcore.core.models import Finding
from dastcore.report.correlation import correlate
from dastcore.report.remediation import guide_for
from dastcore.severity import SEVERITY_ORDER, severity_rank

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "j2", "html.j2"], default=True, default_for_string=True),
)
_env.globals["remediation_guide"] = guide_for


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def _group_by_category(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    """Group findings by OWASP category (used by the LLM report), most-severe first."""
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.owasp or "Otros", []).append(finding)
    for group in groups.values():
        group.sort(key=lambda f: severity_rank(f.severity), reverse=True)
    return sorted(
        groups.items(),
        key=lambda item: max(severity_rank(f.severity) for f in item[1]),
        reverse=True,
    )


def render_html(
    findings: list[Finding],
    *,
    target: str | None = None,
    title: str = "dastcore — Dynamic Security Report",
    group_by_category: bool = False,
) -> str:
    ordered = sorted(findings, key=lambda f: severity_rank(f.severity), reverse=True)
    template = _env.get_template("report.html.j2")
    return template.render(
        findings=ordered,
        issues=correlate(findings),
        grouped=_group_by_category(findings) if group_by_category else None,
        counts=_severity_counts(findings),
        total=len(findings),
        severity_order=list(reversed(SEVERITY_ORDER)),
        target=target,
        title=title,
        version=__version__,
        generated_at=_dt.datetime.now(_dt.UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
