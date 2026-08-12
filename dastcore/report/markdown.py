"""Markdown renderers for CI (Module 16).

Two audiences:

- ``render_markdown_diff`` — a PR comment. It leads with what *changed* since the baseline
  (new / fixed / persistent counts), then tables the NEW findings a reviewer must act on.
  This is what a GitHub Action posts back on a pull request.
- ``render_markdown`` — a flat Markdown report of a finding set, for logs or issue bodies.

Both are pure string builders — no network — so a CI job can render without a browser and a
test can assert on the output.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from dastcore.core.models import Finding
from dastcore.report.compliance import compliance_summary
from dastcore.severity import SEVERITY_ORDER, severity_rank
from dastcore.web.diff import FindingDiff

_SEV_EMOJI = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def _location(finding: Finding) -> str:
    path = urlsplit(finding.request.url).path or "/"
    point = finding.injection_point
    return f"`{finding.request.method} {path}` ({point.location}:{point.name})"


def _finding_rows(findings: list[Finding]) -> list[str]:
    rows = []
    for f in sorted(findings, key=lambda f: severity_rank(f.severity), reverse=True):
        emoji = _SEV_EMOJI.get(f.severity, "")
        rows.append(f"| {emoji} {f.severity} | {f.cvss_score:.1f} | {f.name} | {f.cwe} · {f.owasp} | {_location(f)} |")
    return rows


def _severity_line(findings: list[Finding]) -> str:
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for f in findings:
        counts[f.severity] += 1
    parts = [f"{_SEV_EMOJI[sev]} {counts[sev]} {sev}" for sev in SEVERITY_ORDER if counts[sev]]
    return " · ".join(parts) if parts else "sin hallazgos"


def render_markdown_diff(diff: FindingDiff, *, target: str | None = None) -> str:
    """A PR-comment Markdown summary: what changed, then the NEW findings to review."""
    lines: list[str] = ["## 🛡️ dastcore — cambios de seguridad"]
    if target:
        lines.append(f"Objetivo: `{target}`")
    c = diff.counts
    lines.append("")
    lines.append(f"**🆕 {c['new']} nuevos · ✅ {c['fixed']} corregidos · ➖ {c['persistent']} persistentes**")

    if diff.new:
        lines.append("")
        lines.append("### 🆕 Hallazgos nuevos (revisar antes de mergear)")
        lines.append("")
        lines.append("| Severidad | CVSS | Hallazgo | CWE / OWASP | Ubicación |")
        lines.append("| --- | --- | --- | --- | --- |")
        lines.extend(_finding_rows(diff.new))
    else:
        lines.append("")
        lines.append("✅ **Ningún hallazgo nuevo respecto a la línea base.**")

    if diff.fixed:
        lines.append("")
        lines.append(f"<details><summary>✅ {len(diff.fixed)} corregidos desde la línea base</summary>")
        lines.append("")
        for f in sorted(diff.fixed, key=lambda f: severity_rank(f.severity), reverse=True):
            lines.append(f"- {_SEV_EMOJI.get(f.severity, '')} {f.name} — {_location(f)}")
        lines.append("")
        lines.append("</details>")

    lines.append("")
    lines.append("<sub>dastcore · el diff compara por id estable de hallazgo contra la línea base.</sub>")
    return "\n".join(lines) + "\n"


def render_markdown(findings: list[Finding], *, target: str | None = None, include_compliance: bool = True) -> str:
    """A flat Markdown report of a finding set (issue body / CI log)."""
    lines: list[str] = ["# dastcore — reporte de seguridad"]
    if target:
        lines.append(f"Objetivo: `{target}`")
    lines.append("")
    lines.append(f"**{len(findings)} hallazgos** — {_severity_line(findings)}")

    if findings:
        lines.append("")
        lines.append("| Severidad | CVSS | Hallazgo | CWE / OWASP | Ubicación |")
        lines.append("| --- | --- | --- | --- | --- |")
        lines.extend(_finding_rows(findings))

    if include_compliance and findings:
        postures = compliance_summary(findings)
        if postures:
            lines.append("")
            lines.append("## Cumplimiento (indicativo)")
            for fp in postures:
                lines.append("")
                lines.append(f"### {fp.framework}")
                lines.append("")
                lines.append("| Control | Título | Hallazgos | Peor severidad |")
                lines.append("| --- | --- | --- | --- |")
                for cp in fp.controls:
                    lines.append(f"| {cp.tag.control} | {cp.tag.title} | {cp.count} | {cp.max_severity} |")

    return "\n".join(lines) + "\n"
