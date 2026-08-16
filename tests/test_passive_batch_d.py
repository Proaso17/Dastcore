"""Batch D passive checks: SameSite=None cookies (CWE-1275) and reverse tabnabbing (CWE-1022)."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.passive import check_cookie_samesite_none, check_reverse_tabnabbing


def _resp(headers: dict[str, str], text: str = "") -> HttpResponse:
    return HttpResponse(status_code=200, headers=headers, text=text)


def _req() -> HttpRequest:
    return HttpRequest(method="GET", url="https://app.test/")


# --- SameSite=None (CWE-1275) ---------------------------------------------------------------


def test_samesite_none_without_secure_is_flagged() -> None:
    findings = check_cookie_samesite_none(_req(), _resp({"set-cookie": "sid=abc; Path=/; SameSite=None"}))
    assert len(findings) == 1
    assert findings[0].rule_id == "passive-cookie-samesite-none" and findings[0].cwe == "CWE-1275"
    assert "sin `Secure`" in findings[0].name


def test_samesite_none_with_secure_is_still_flagged() -> None:
    findings = check_cookie_samesite_none(_req(), _resp({"set-cookie": "sid=abc; Secure; SameSite=None"}))
    assert len(findings) == 1 and "sin `Secure`" not in findings[0].name


def test_samesite_lax_is_not_flagged() -> None:
    assert check_cookie_samesite_none(_req(), _resp({"set-cookie": "sid=abc; SameSite=Lax"})) == []


# --- reverse tabnabbing (CWE-1022) ----------------------------------------------------------

_HTML = {"content-type": "text/html"}


def test_external_blank_link_without_noopener_is_flagged() -> None:
    html = '<a href="https://evil.example/" target="_blank">click</a>'
    findings = check_reverse_tabnabbing(_req(), _resp(_HTML, html))
    assert len(findings) == 1
    assert findings[0].rule_id == "passive-reverse-tabnabbing" and findings[0].cwe == "CWE-1022"


def test_link_with_noopener_is_not_flagged() -> None:
    html = '<a href="https://evil.example/" target="_blank" rel="noopener noreferrer">ok</a>'
    assert check_reverse_tabnabbing(_req(), _resp(_HTML, html)) == []


def test_internal_blank_link_is_not_flagged() -> None:
    html = '<a href="/local/page" target="_blank">internal</a>'  # not an external origin
    assert check_reverse_tabnabbing(_req(), _resp(_HTML, html)) == []


def test_non_html_response_is_skipped() -> None:
    html = '<a href="https://evil.example/" target="_blank">x</a>'
    assert check_reverse_tabnabbing(_req(), _resp({"content-type": "application/json"}, html)) == []
