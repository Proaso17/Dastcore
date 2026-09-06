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


def _form_session_budget(max_relogin: int) -> SessionManager:
    auth = AuthConfig(
        type="form",
        form=FormLoginConfig(login_url="http://app.test/login.php", credentials={"u": "a"}),
        max_relogin=max_relogin,
    )
    sm = SessionManager(auth)
    sm._established = True
    return sm


async def test_relogin_budget_is_consecutive_not_total() -> None:
    """max_relogin caps re-logins that never yield a working session (broken auth), NOT the total over a
    long scan of an app that drops its session periodically and recovers. Regression: bWAPP dropped its
    PHP session under load, burned the total budget of 20, then silently scanned the login page for the
    rest of the run (2000+ requests) and reported a false 'all clear'."""

    async def ok_login(_client: object) -> bool:
        return True

    # Fragile-but-recoverable: far more re-logins than the budget, but each successful request resets
    # the counter, so the session keeps recovering indefinitely and never exhausts the budget.
    sm = _form_session_budget(3)
    sm._perform_login = ok_login  # type: ignore[assignment]
    for _ in range(10):
        assert await sm.ensure_logged_in(None) is True  # type: ignore[arg-type]
        sm.note_success()  # a later request came back with a live session
    assert sm._relogin_count == 0

    # Genuinely broken auth: re-login returns material but no request ever works (no note_success), so
    # after max_relogin CONSECUTIVE re-logins the budget is spent and we stop trying.
    sm2 = _form_session_budget(3)
    sm2._perform_login = ok_login  # type: ignore[assignment]
    assert await sm2.ensure_logged_in(None) is True   # count 0 -> 1  # type: ignore[arg-type]
    assert await sm2.ensure_logged_in(None) is True   # 1 -> 2  # type: ignore[arg-type]
    assert await sm2.ensure_logged_in(None) is True   # 2 -> 3  # type: ignore[arg-type]
    assert await sm2.ensure_logged_in(None) is False  # 3 >= 3 -> exhausted  # type: ignore[arg-type]
