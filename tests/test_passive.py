from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.passive import (
    check_cors_misconfiguration,
    check_directory_listing,
    check_error_disclosure,
    check_insecure_cookies,
    check_missing_csp,
    check_missing_security_headers,
    check_technology_disclosure,
    run_passive_checks,
)


def _request(url: str = "http://x/page") -> HttpRequest:
    return HttpRequest(method="GET", url=url)


def _response(**overrides) -> HttpResponse:
    defaults = {"status_code": 200, "headers": {}, "text": "ok", "elapsed_ms": 1.0, "url": "http://x/page"}
    defaults.update(overrides)
    return HttpResponse(**defaults)


def test_missing_security_headers_flagged_on_bare_response() -> None:
    findings = check_missing_security_headers(_request(), _response(headers={}))
    ids = {f.id for f in findings}
    assert "passive-missing-x-content-type-options" in ids
    assert "passive-missing-x-frame-options" in ids


def test_no_missing_header_findings_when_headers_present() -> None:
    findings = check_missing_security_headers(
        _request(),
        _response(headers={"x-content-type-options": "nosniff", "x-frame-options": "DENY"}),
    )
    assert findings == []


def test_hsts_only_checked_over_https() -> None:
    http_findings = check_missing_security_headers(_request("http://x/page"), _response())
    assert not any(f.id == "passive-missing-hsts" for f in http_findings)

    https_findings = check_missing_security_headers(
        _request("https://x/page"),
        _response(headers={"x-content-type-options": "nosniff", "x-frame-options": "DENY"}),
    )
    assert any(f.id == "passive-missing-hsts" for f in https_findings)


def test_insecure_cookie_missing_httponly_and_samesite() -> None:
    findings = check_insecure_cookies(_request(), _response(headers={"set-cookie": "session=abc123; Path=/"}))
    assert len(findings) == 1
    assert "HttpOnly" in findings[0].name
    assert "SameSite" in findings[0].name


def test_secure_cookie_produces_no_finding() -> None:
    findings = check_insecure_cookies(
        _request(),
        _response(headers={"set-cookie": "session=abc123; Path=/; HttpOnly; SameSite=Strict"}),
    )
    assert findings == []


def test_no_cookie_header_means_no_finding() -> None:
    assert check_insecure_cookies(_request(), _response(headers={})) == []


def test_cors_wildcard_with_credentials_flagged() -> None:
    findings = check_cors_misconfiguration(
        _request(),
        _response(headers={"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}),
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_cors_wildcard_alone_is_not_flagged() -> None:
    """Wildcard ACAO without credentials is common and not inherently exploitable."""
    findings = check_cors_misconfiguration(_request(), _response(headers={"access-control-allow-origin": "*"}))
    assert findings == []


def test_error_disclosure_detects_python_traceback() -> None:
    findings = check_error_disclosure(
        _request(), _response(text="Traceback (most recent call last):\n  File x, line 1")
    )
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-209"


def test_error_disclosure_none_on_normal_body() -> None:
    assert check_error_disclosure(_request(), _response(text="<h1>Results for demo</h1>")) == []


def test_technology_disclosure_flags_versioned_server_header() -> None:
    findings = check_technology_disclosure(_request(), _response(headers={"server": "Werkzeug/3.1.8 Python/3.12"}))
    assert len(findings) == 1
    assert findings[0].rule_id == "passive-tech-disclosure"


def test_technology_disclosure_ignores_bare_product_name() -> None:
    """A product name without a version number is low signal — don't flag it."""
    assert check_technology_disclosure(_request(), _response(headers={"server": "nginx"})) == []


def test_missing_csp_flagged_on_html_without_csp() -> None:
    findings = check_missing_csp(_request(), _response(headers={"content-type": "text/html"}))
    assert len(findings) == 1
    assert findings[0].rule_id == "passive-missing-csp"


def test_missing_csp_not_flagged_when_present_or_non_html() -> None:
    assert (
        check_missing_csp(
            _request(),
            _response(headers={"content-type": "text/html", "content-security-policy": "default-src 'self'"}),
        )
        == []
    )
    assert check_missing_csp(_request(), _response(headers={"content-type": "application/json"})) == []


def test_directory_listing_flagged() -> None:
    findings = check_directory_listing(_request(), _response(text="<title>Index of /uploads</title>"))
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_directory_listing_not_flagged_on_normal_page() -> None:
    assert check_directory_listing(_request(), _response(text="<h1>Welcome</h1>")) == []


def test_run_passive_checks_zero_findings_on_fully_hardened_response() -> None:
    """The zero-false-positive bar: a properly configured response must yield nothing."""
    hardened_response = _response(
        headers={
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "strict-transport-security": "max-age=63072000; includeSubDomains",
            "set-cookie": "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict",
        },
        text="<h1>All good</h1>",
    )
    assert run_passive_checks(_request("https://x/page"), hardened_response) == []
