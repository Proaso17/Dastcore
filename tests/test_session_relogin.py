"""Session expiry via redirect-to-login — the common real-world logout signal (302 -> /login) that a
default 401 check misses. Without this, an authenticated scan of bWAPP/DVWA/most apps silently scans the
login page after any session drop and finds nothing."""

from __future__ import annotations

from dastcore.config import AuthConfig, FormLoginConfig
from dastcore.core.models import HttpResponse
from dastcore.core.session import SessionManager


def _form_session() -> SessionManager:
    auth = AuthConfig(
        type="form",
        form=FormLoginConfig(login_url="http://app.test/login.php", credentials={"u": "a", "p": "b"}),
    )
    sm = SessionManager(auth)
    sm._established = True  # pretend we logged in already
    return sm


def _resp(status: int, location: str = "") -> HttpResponse:
    headers = {"location": location} if location else {}
    return HttpResponse(status_code=status, headers=headers, text="", url="http://app.test/x")


def test_redirect_to_login_is_treated_as_expired() -> None:
    sm = _form_session()
    assert sm.is_expired(_resp(302, "login.php")) is True  # relative Location
    assert sm.is_expired(_resp(302, "http://app.test/login.php")) is True  # absolute
    assert sm.is_expired(_resp(303, "/login.php?reason=timeout")) is True  # with query


def test_other_redirects_and_success_are_not_expiry() -> None:
    sm = _form_session()
    assert sm.is_expired(_resp(302, "/portal.php")) is False  # a normal redirect, not the login page
    assert sm.is_expired(_resp(200)) is False
    assert sm.is_expired(_resp(302, "")) is False  # no Location


def test_static_auth_never_flags_login_redirect() -> None:
    sm = SessionManager(AuthConfig(type="cookie", cookies={"s": "1"}))
    sm._established = True
    assert sm.is_expired(_resp(302, "login.php")) is False  # no login_url to match, no false re-login
