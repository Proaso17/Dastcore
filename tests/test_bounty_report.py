"""Phase 14: platform bug-bounty report drafts (impact-first, human-in-the-loop)."""

from __future__ import annotations

from dastcore.bugbounty import Program
from dastcore.bugbounty.report import PLATFORMS, render_bounty_report
from dastcore.bugbounty.triage import triage_for_bounty
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint


def _sqli_bounty():
    req = HttpRequest(method="GET", url="http://api.acme.com/search", params={"q": "1"})
    point = InjectionPoint(location="query", name="q", base_value="1", request_template=req)
    finding = Finding(
        id="sqli-injection:api.acme.com:q",
        rule_id="sqli-injection",
        name="SQL Injection (error-based)",
        severity="critical",
        cwe="CWE-89",
        owasp="WSTG-INPV-05",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        family="sqli",
        injection_point=point,
        evidence=[Evidence(type="differential", data="a boolean TRUE/FALSE pair differed", confidence="high")],
        request=req,
        response=HttpResponse(status_code=500),
        remediation="Usa consultas parametrizadas.",
        impact="Lectura de la base de datos confirmada (UNION): DBMS SQLite 3.49.1.",
    )
    return triage_for_bounty([finding], Program(handle="acme", payouts={"sqli": 3000}))[0]


def test_report_has_all_impact_first_sections() -> None:
    md = render_bounty_report(_sqli_bounty(), Program(handle="acme"), "generic")
    for needle in (
        "SQL Injection",
        "## Severity",
        "P1",
        "CVSS:3.1",
        "CWE-89",
        "## Steps to reproduce",
        "curl",
        "## Remediation",
    ):
        assert needle in md, needle
    assert "Lectura de la base de datos confirmada" in md  # proof-of-impact carried into the PoC


def test_platform_layouts_differ() -> None:
    bf = _sqli_bounty()
    h1 = render_bounty_report(bf, None, "hackerone")
    bc = render_bounty_report(bf, None, "bugcrowd")
    assert "## Steps To Reproduce" in h1  # HackerOne casing
    assert h1.splitlines()[0].startswith("# SQL Injection")
    assert "## Business Impact" in bc and "## Steps to Reproduce" in bc
    assert bc.splitlines()[0].startswith("# [P1]")  # Bugcrowd leads with the VRT band


def test_all_platforms_render_without_error() -> None:
    bf = _sqli_bounty()
    for platform in PLATFORMS:
        assert render_bounty_report(bf, None, platform).strip()
