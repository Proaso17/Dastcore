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
from dastcore.severity import SEVERITY_ORDER, severity_rank

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "j2", "html.j2"], default=True, default_for_string=True),
)


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def render_html(findings: list[Finding], *, target: str | None = None) -> str:
    ordered = sorted(findings, key=lambda f: severity_rank(f.severity), reverse=True)
    template = _env.get_template("report.html.j2")
    return template.render(
        findings=ordered,
        counts=_severity_counts(findings),
        total=len(findings),
        severity_order=list(reversed(SEVERITY_ORDER)),
        target=target,
        version=__version__,
        generated_at=_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
