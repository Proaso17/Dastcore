"""Remediation knowledge base: the rich 'How to fix' guidance behind each finding."""

from __future__ import annotations

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.report import render_html
from dastcore.report.remediation import guide_for


def _finding(*, rule_id: str, family: str = "", cwe: str = "CWE-89", remediation: str = "Fix it.") -> Finding:
    request = HttpRequest(method="GET", url="http://target.test/x", params={"p": "v"})
    point = InjectionPoint(location="query", name="p", base_value="", request_template=request)
    response = HttpResponse(status_code=200, text="ok", elapsed_ms=1.0)
    return Finding(
        id=f"{rule_id}:GET:/x:query:p",
        rule_id=rule_id,
        name="Sample",
        severity="high",
        cwe=cwe,
        owasp="WSTG-INPV-05",
        injection_point=point,
        evidence=[Evidence(type="response_match", data="hit", confidence="high")],
        request=request,
        response=response,
        remediation=remediation,
        family=family,
    )


# --- guide resolution -------------------------------------------------------------------


def test_family_guide_has_steps_example_and_references() -> None:
    guide = guide_for(_finding(rule_id="sqli-injection", family="sqli", remediation="Use prepared statements."))
    assert guide.summary == "Use prepared statements."  # the rule's own line stays authoritative
    assert guide.steps  # concrete actions
    assert guide.example is not None and guide.example.bad and guide.example.good
    labels = " ".join(r.label for r in guide.references)
    assert "SQL Injection Prevention" in labels


def test_cwe_reference_is_always_appended() -> None:
    guide = guide_for(_finding(rule_id="sqli-injection", family="sqli", cwe="CWE-89"))
    urls = [r.url for r in guide.references]
    assert "https://cwe.mitre.org/data/definitions/89.html" in urls


def test_detector_finding_resolves_by_rule_id_prefix() -> None:
    # passive header findings carry no family; they must still get header guidance.
    guide = guide_for(_finding(rule_id="passive-missing-csp", family="", cwe="CWE-693"))
    assert guide.steps
    assert any("Secure Headers" in r.label for r in guide.references)


def test_authz_and_cookie_and_secret_prefixes_resolve() -> None:
    assert guide_for(_finding(rule_id="authz-bola", cwe="CWE-639")).steps
    assert guide_for(_finding(rule_id="passive-insecure-cookie", cwe="CWE-614")).steps
    assert guide_for(_finding(rule_id="secret-exposure", cwe="CWE-798")).steps


def test_llm_findings_resolve_to_specific_guides_despite_shared_family() -> None:
    # All LLM findings share family "llm"; the rule_id must select the specific guide.
    stored = guide_for(_finding(rule_id="llm-stored-injection", family="llm", cwe="CWE-77"))
    assert stored.steps and any("retriev" in s.lower() for s in stored.steps)
    assert any("Prompt Injection" in r.label for r in stored.references)

    action = guide_for(_finding(rule_id="llm-cross-tenant-action", family="llm", cwe="CWE-862"))
    assert any("Function Level Authorization" in r.label for r in action.references)

    leak = guide_for(_finding(rule_id="llm-cross-tenant-leak", family="llm", cwe="CWE-639"))
    assert any("Object Level Authorization" in r.label for r in leak.references)


def test_unlisted_llm_rule_falls_back_to_generic_llm_guide() -> None:
    # A generic LLM rule (system-prompt leak, PII, denial-of-wallet) hits the "llm-" catch-all.
    guide = guide_for(_finding(rule_id="llm-system-prompt-leak", family="llm", cwe="CWE-200"))
    assert guide.steps and any("LLM Applications" in r.label for r in guide.references)


def test_unknown_family_still_yields_summary_and_cwe_link() -> None:
    guide = guide_for(
        _finding(rule_id="totally-unknown", family="mystery", cwe="CWE-1234", remediation="Do the thing.")
    )
    assert guide.summary == "Do the thing."
    assert guide.steps == ()
    assert guide.example is None
    assert [r.url for r in guide.references] == ["https://cwe.mitre.org/data/definitions/1234.html"]


def test_missing_cwe_produces_no_broken_reference() -> None:
    guide = guide_for(_finding(rule_id="whatever", family="mystery", cwe=""))
    assert guide.references == ()


# --- rendering --------------------------------------------------------------------------


def test_html_renders_the_fix_panel() -> None:
    html = render_html([_finding(rule_id="sqli-injection", family="sqli", remediation="Use prepared statements.")])
    assert "How to fix" in html
    assert 'class="fix-steps"' in html
    assert "Vulnerable" in html and "Secure" in html
    assert "cwe.mitre.org/data/definitions/89.html" in html


def test_html_renders_llm_fix_panel_with_owasp_llm_reference() -> None:
    html = render_html(
        [_finding(rule_id="llm-stored-injection", family="llm", cwe="CWE-77", remediation="Isolate retrieved data.")]
    )
    assert "How to fix" in html
    assert "genai.owasp.org" in html  # OWASP LLM Top 10 reference rendered


def test_html_fix_example_is_escaped_not_executed() -> None:
    # code examples may contain angle brackets / quotes; they must render inert.
    html = render_html([_finding(rule_id="xss-reflected", family="xss", cwe="CWE-79")])
    assert "<h1>Hello" not in html  # the example's raw HTML must not appear live
    assert "&lt;h1&gt;Hello" in html
