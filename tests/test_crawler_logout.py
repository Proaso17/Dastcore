"""The crawler must never follow a logout link — doing so drops an authenticated session and makes the
rest of the scan hit the login page (finding nothing). Pins the logout-URL detection the crawlers use."""

from __future__ import annotations

from dastcore.discovery.crawler_http import _is_logout


def test_logout_urls_are_detected() -> None:
    for url in (
        "http://app.test/logout.php",
        "http://app.test/logout",
        "http://app.test/user/sign-out",
        "http://app.test/auth/signout",
        "http://app.test/logoff.aspx",
        "http://app.test/account/log-out",
        "http://app.test/session?action=logout",
    ):
        assert _is_logout(url) is True, url


def test_normal_urls_are_not_logout() -> None:
    for url in (
        "http://app.test/login.php",
        "http://app.test/sqli_1.php?title=x&action=search",
        "http://app.test/portal.php",
        "http://app.test/logout_history.php",  # contains 'logout' but as part of a word -> not a logout action
        "http://app.test/blog/rollout",  # 'logout' is not a path segment here
    ):
        assert _is_logout(url) is False, url
