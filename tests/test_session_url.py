"""Session-token-in-URL detector: flags a session/auth token in the query string, and
ignores short values, non-session params and clean URLs (the false-positive boundary)."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.session_url import check_session_token_in_url

_RESP = HttpResponse(status_code=200, text="ok")


def _req(url: str) -> HttpRequest:
    return HttpRequest(method="GET", url=url)


def test_flags_sessionid_token_in_url() -> None:
    findings = check_session_token_in_url(_req("http://t.test/app?sessionid=8f3b1c2d9a7e4f60b1c2"), _RESP)
    assert len(findings) == 1
    assert findings[0].rule_id == "session-token-in-url" and findings[0].cwe == "CWE-598"


def test_flags_jsessionid_and_access_token() -> None:
    assert check_session_token_in_url(_req("http://t.test/?jsessionid=ABCDEF0123456789abcdef"), _RESP)
    assert check_session_token_in_url(_req("http://t.test/?access_token=ya29.a0AfH-longtokenvalue123"), _RESP)


def test_short_value_is_not_flagged() -> None:
    # a short value isn't a session token (e.g. a page id or a UI flag)
    assert check_session_token_in_url(_req("http://t.test/?sid=42"), _RESP) == []


def test_non_session_param_is_not_flagged() -> None:
    assert check_session_token_in_url(_req("http://t.test/search?q=averylongsearchqueryvalue"), _RESP) == []


def test_clean_url_is_not_flagged() -> None:
    assert check_session_token_in_url(_req("http://t.test/dashboard"), _RESP) == []
