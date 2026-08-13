"""PDF report renderer (optional ``pdf`` extra → ``fpdf2``).

A self-contained PDF of the confirmed findings for sharing with people who won't open an HTML
file or a JSON blob. ``fpdf2`` is an optional dependency: import it lazily and raise a clear,
actionable error if it's missing, so the rest of the tool never depends on it.

``audience`` mirrors the HTML report: ``executive`` gives the summary, the issue table, the
compliance posture and remediation (no raw request/response); ``developer`` adds the per-finding
technical detail and reproduction curl.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from dastcore import __version__
from dastcore.core.models import Finding
from dastcore.report.compliance import compliance_summary
from dastcore.report.correlation import correlate
from dastcore.report.remediation import guide_for
from dastcore.severity import SEVERITY_ORDER, severity_rank

_MISSING = "El export a PDF requiere la dependencia opcional 'fpdf2'. Instálala con: pip install 'dastcore[pdf]'"
# RGB per severity, aligned with the HTML report's palette.
_SEV_RGB = {
    "critical": (180, 35, 24),
    "high": (217, 45, 32),
    "medium": (181, 71, 8),
    "low": (2, 106, 162),
    "info": (102, 112, 133),
}


def _ascii(text: str) -> str:
    """Core PDF fonts are latin-1 only; drop characters they can't encode."""
    return (text or "").encode("latin-1", "replace").decode("latin-1")


def _location(finding: Finding) -> str:
    path = urlsplit(finding.request.url).path or "/"
    point = finding.injection_point
    return f"{finding.request.method} {path} ({point.location}:{point.name})"


def render_pdf(
    findings: list[Finding],
    *,
    target: str | None = None,
    title: str = "dastcore — Dynamic Security Report",
    audience: str = "developer",
) -> bytes:
    """Render findings to a PDF document (bytes). Raises RuntimeError if ``fpdf2`` is absent."""
    try:
        from fpdf import FPDF
    except ImportError as exc:  # pragma: no cover - exercised via the missing-dep test path
        raise RuntimeError(_MISSING) from exc

    ordered = sorted(findings, key=lambda f: severity_rank(f.severity), reverse=True)
    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_ORDER}

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    def line(text: str, height: float = 5) -> None:
        # wrapmode CHAR so long unbroken tokens (URLs, curl commands, base64) still fit.
        pdf.multi_cell(0, height, _ascii(text), new_x="LMARGIN", new_y="NEXT", wrapmode="CHAR")

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, _ascii(title), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(102, 112, 133)
    meta = f"dastcore v{__version__}"
    if target:
        meta = f"Objetivo: {target}  ·  " + meta
    pdf.cell(0, 6, _ascii(meta), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # Summary line: total + per-severity counts.
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, _ascii(f"Resumen: {len(findings)} hallazgos"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    breakdown = "   ".join(f"{sev}: {counts[sev]}" for sev in SEVERITY_ORDER if counts[sev]) or "sin hallazgos"
    line(breakdown, 6)
    pdf.ln(6)

    # Issue overview (correlated by rule).
    issues = correlate(findings)
    if issues:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 7, "Issues", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        for issue in issues:
            pdf.set_text_color(*_SEV_RGB.get(issue.severity, (0, 0, 0)))
            line(f"[{issue.severity}] {issue.name}  [{issue.cwe} / {issue.owasp}]  x{issue.count}")
            pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

    # Compliance posture.
    postures = compliance_summary(findings)
    if postures:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 7, "Cumplimiento (indicativo)", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        for fp in postures:
            pdf.set_font("Helvetica", "B", 9)
            line(fp.framework)
            pdf.set_font("Helvetica", "", 9)
            for control in fp.controls:
                line(f"  {control.tag.control} - {control.tag.title} (x{control.count}, {control.max_severity})")
        pdf.ln(4)

    # Per-finding detail.
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, "Hallazgos", new_x="LMARGIN", new_y="NEXT")
    for finding in ordered:
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*_SEV_RGB.get(finding.severity, (0, 0, 0)))
        line(f"[{finding.severity}] {finding.name}")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 9)
        line(f"Regla: {finding.rule_id}  ·  {finding.cwe} / {finding.owasp}")
        line(f"CVSS: {finding.cvss_score:.1f}  ·  Ubicacion: {_location(finding)}")
        for ev in finding.evidence:
            line(f"Evidencia ({ev.type}): {ev.data}")
        if audience != "executive":
            pdf.set_text_color(102, 112, 133)
            line(f"Reproducir: {finding.repro_curl}")
            pdf.set_text_color(0, 0, 0)
        line(f"Remediacion: {guide_for(finding).summary}")

    out = pdf.output()
    return bytes(out)
