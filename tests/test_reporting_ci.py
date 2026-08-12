"""CI reporting (Module 16): compliance mapping, Markdown/diff renderers, audience HTML,
and the `dastcore diff` command that fails CI only on NEW findings."""

from __future__ import annotations

from typer.testing import CliRunner

from dastcore.cli import app
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.report import render_json
from dastcore.report.compliance import compliance_summary, compliance_tags
from dastcore.report.html import render_html
from dastcore.report.markdown import render_markdown, render_markdown_diff
from dastcore.web.diff import diff_findings

runner = CliRunner()


def _finding(rule_id: str, *, family: str = "sqli", severity: str = "high") -> Finding:
    request = HttpRequest(method="POST", url="http://t.test/api", params={"id": "1"})
    point = InjectionPoint(location="query", name="id", request_template=request)
    return Finding(
        id=f"{rule_id}:POST:/api:query:id",
        rule_id=rule_id,
        name=rule_id.upper(),
        severity=severity,  # type: ignore[arg-type]
        cwe="CWE-89",
        owasp="WSTG-INPV-05",
        family=family,
        injection_point=point,
        evidence=[Evidence(type="differential", data="baseline≠mutated")],
        request=request,
        response=HttpResponse(status_code=200, text="ok"),
        remediation="fix",
    )


# --- compliance ------------------------------------------------------------------------


def test_compliance_tags_map_family_to_frameworks() -> None:
    tags = compliance_tags(_finding("sqli", family="sqli"))
    frameworks = {t.framework for t in tags}
    assert frameworks == {"PCI-DSS 4.0", "OWASP ASVS 4.0.3", "ISO/IEC 27001:2022", "SOC 2"}


def test_compliance_unknown_family_falls_back() -> None:
    tags = compliance_tags(_finding("weird", family="does-not-exist"))
    assert any(t.control == "V1.1" for t in tags)  # secure_development ASVS control


def test_compliance_summary_counts_and_worst_severity() -> None:
    findings = [
        _finding("sqli", family="sqli", severity="high"),
        _finding("cmdi", family="cmdi", severity="critical"),  # same injection category
        _finding("authz", family="authz", severity="medium"),
    ]
    postures = compliance_summary(findings)
    pci = next(fp for fp in postures if fp.framework == "PCI-DSS 4.0")
    injection_control = next(c for c in pci.controls if c.tag.control == "6.2.4")
    assert injection_control.count == 2  # sqli + cmdi share PCI 6.2.4
    assert injection_control.max_severity == "critical"


def test_compliance_summary_excludes_suppressed() -> None:
    f = _finding("sqli")
    f.suppressed = True
    assert compliance_summary([f]) == []


# --- markdown --------------------------------------------------------------------------


def test_markdown_diff_lists_only_new_findings() -> None:
    base = [_finding("sqli")]
    head = [_finding("sqli"), _finding("authz", family="authz", severity="critical")]
    md = render_markdown_diff(diff_findings(base, head), target="http://t.test")
    assert "1 nuevos" in md
    assert "AUTHZ" in md  # the new finding
    assert "cambios de seguridad" in md


def test_markdown_report_includes_compliance_section() -> None:
    md = render_markdown([_finding("sqli")], include_compliance=True)
    assert "Cumplimiento" in md
    assert "PCI-DSS 4.0" in md


# --- audience HTML ---------------------------------------------------------------------


def test_html_developer_shows_curl_executive_hides_it() -> None:
    findings = [_finding("sqli")]
    dev = render_html(findings, audience="developer")
    exe = render_html(findings, audience="executive")
    assert "Reproducir (curl)" in dev
    assert "Reproducir (curl)" not in exe
    # both carry the compliance posture
    assert "Cumplimiento" in dev and "Cumplimiento" in exe


# --- diff CLI --------------------------------------------------------------------------


def _write(tmp_path, name: str, findings: list[Finding]) -> str:
    path = tmp_path / name
    path.write_text(render_json(findings), encoding="utf-8")
    return str(path)


def test_diff_cli_fails_only_on_new_findings(tmp_path) -> None:
    # baseline already has a critical; head keeps it and adds nothing new → no CI failure
    base = _write(tmp_path, "base.json", [_finding("authz", family="authz", severity="critical")])
    head = _write(tmp_path, "head.json", [_finding("authz", family="authz", severity="critical")])
    result = runner.invoke(app, ["diff", base, head, "--quiet", "-f", "json", "--fail-on", "high"])
    assert result.exit_code == 0  # preexisting debt does not fail CI


def test_diff_cli_fails_on_new_regression(tmp_path) -> None:
    base = _write(tmp_path, "base.json", [_finding("sqli", severity="high")])
    head = _write(
        tmp_path,
        "head.json",
        [_finding("sqli", severity="high"), _finding("cmdi", family="cmdi", severity="critical")],
    )
    result = runner.invoke(app, ["diff", base, head, "--quiet", "-f", "json", "--fail-on", "high"])
    assert result.exit_code == 2  # a NEW critical regresses → CI fails
    # the report carries only the new findings: cmdi is present, the preexisting sqli is not
    assert '"rule_id": "cmdi"' in result.stdout
    assert '"rule_id": "sqli"' not in result.stdout


def test_diff_cli_markdown_default_and_no_fail(tmp_path) -> None:
    base = _write(tmp_path, "base.json", [_finding("sqli")])
    head = _write(tmp_path, "head.json", [_finding("sqli"), _finding("xss", family="xss", severity="low")])
    result = runner.invoke(app, ["diff", base, head, "--quiet", "--fail-on", "none"])
    assert result.exit_code == 0
    assert "cambios de seguridad" in result.stdout  # markdown is the default format
