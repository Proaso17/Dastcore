"""Cleartext-credentials detector: a password form posting to an absolute http:// URL
is flagged; https, relative actions, and non-password forms are not."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.cleartext import check_cleartext_credentials

_REQ = HttpRequest(method="GET", url="http://t.test/login")


def _resp(text: str) -> HttpResponse:
    return HttpResponse(status_code=200, text=text)


def test_password_form_to_cleartext_url_is_flagged() -> None:
    body = '<form action="http://auth.example.com/login" method="post"><input type="password" name="pw"></form>'
    findings = check_cleartext_credentials(_REQ, _resp(body))
    assert len(findings) == 1
    assert findings[0].rule_id == "cleartext-credentials" and findings[0].cwe == "CWE-319"


def test_https_action_is_safe() -> None:
    body = '<form action="https://auth.example.com/login"><input type="password" name="pw"></form>'
    assert check_cleartext_credentials(_REQ, _resp(body)) == []


def test_relative_action_is_not_flagged() -> None:
    # relative action carries no explicit cleartext destination -> not flagged (avoids FP)
    body = '<form action="/login"><input type="password" name="pw"></form>'
    assert check_cleartext_credentials(_REQ, _resp(body)) == []


def test_non_password_form_to_http_is_not_flagged() -> None:
    body = '<form action="http://search.example.com/q"><input type="text" name="q"></form>'
    assert check_cleartext_credentials(_REQ, _resp(body)) == []


def test_only_one_finding_per_page() -> None:
    body = (
        '<form action="http://a.example/login"><input type="password"></form>'
        '<form action="http://b.example/login"><input type="password"></form>'
    )
    assert len(check_cleartext_credentials(_REQ, _resp(body))) == 1
