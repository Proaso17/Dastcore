"""Phase 13: SAST<->DAST correlation. A SastScore SARIF result that lines up with a dynamic finding
(same CWE + shared parameter/route) confirms it and raises its confidence; a mismatch does not."""

from __future__ import annotations

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.report.correlation import correlate_sast_dast, is_sast_confirmed, parse_sarif


def _sarif(rule_id: str, cwe_tag: str, uri: str, message: str) -> dict:
    return {
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": rule_id, "properties": {"tags": ["security", cwe_tag]}}]}},
                "results": [
                    {
                        "ruleId": rule_id,
                        "message": {"text": message},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 42}}}
                        ],
                    }
                ],
            }
        ]
    }


def _dast_sqli(param: str = "q", path: str = "/search") -> Finding:
    req = HttpRequest(method="GET", url=f"http://api.acme.com{path}", params={param: "1"})
    point = InjectionPoint(location="query", name=param, base_value="1", request_template=req)
    return Finding(
        id="sqli-injection:api.acme.com:q",
        rule_id="sqli-injection",
        name="SQL Injection",
        severity="critical",
        cwe="CWE-89",
        owasp="x",
        family="sqli",
        injection_point=point,
        evidence=[Evidence(type="differential", data="TRUE/FALSE differed", confidence="high")],
        request=req,
        response=HttpResponse(status_code=500),
        remediation="x",
    )


def test_parse_sarif_extracts_cwe_and_locators() -> None:
    sast = parse_sarif(_sarif("py/sql-injection", "external/cwe/cwe-089", "app/search.py", "tainted param q"))
    assert len(sast) == 1
    assert sast[0].cwe == "CWE-89" and "search" in sast[0].locators and "q" in sast[0].locators


def test_matching_sast_confirms_and_raises_confidence() -> None:
    finding = _dast_sqli()
    before = finding.confidence_score
    sast = parse_sarif(_sarif("py/sql-injection", "external/cwe/cwe-89", "app/search.py", "user input q reaches query"))
    correlate_sast_dast([finding], sast)
    assert is_sast_confirmed(finding)  # confirmed by SAST+DAST
    assert finding.confidence_score > before  # corroboration raised confidence
    assert any(tag.startswith("SAST:") for tag in finding.corroborated_by)


def test_wrong_cwe_does_not_correlate() -> None:
    finding = _dast_sqli()
    sast = parse_sarif(_sarif("py/xss", "external/cwe/cwe-79", "app/search.py", "param q reflected"))  # XSS, not SQLi
    correlate_sast_dast([finding], sast)
    assert not is_sast_confirmed(finding)


def test_same_cwe_but_no_shared_locator_does_not_correlate() -> None:
    finding = _dast_sqli(param="q", path="/search")
    # same CWE-89 but a different file/route/param -> no locator overlap -> no over-claim
    sast = parse_sarif(_sarif("py/sql-injection", "external/cwe/cwe-89", "app/billing.py", "field invoice_id"))
    correlate_sast_dast([finding], sast)
    assert not is_sast_confirmed(finding)
