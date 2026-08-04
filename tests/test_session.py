"""Phase 3: authentication & session management.

Unit tests pin down the SessionManager state machine (apply precedence, epoch
coalescing, relogin budget); integration tests drive real login flows against
the local target and prove the crawler and scanner operate authenticated.
"""
from __future__ import annotations

import httpx

from dastcore.config import AuthConfig, FormLoginConfig, OAuth2Config, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.core.session import SessionManager
from dastcore.discovery.crawler_http import HttpCrawler
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner

_SCOPE = ScopeConfig(allow_domains=["127.0.0.1"])


def _resp(status: int = 401, text: str = "") -> HttpResponse:
    return HttpResponse(status_code=status, text=text)


# --- unit: SessionManager state machine ------------------------------------------------

def test_static_bearer_seeds_authorization_header() -> None:
    session = SessionManager(AuthConfig(type="bearer", bearer_token="abc123"))
    headers = session.apply(None)
    assert headers["Authorization"] == "Bearer abc123"
    assert session.can_relogin is False
    assert session.is_established is True


def test_apply_lets_per_request_values_win() -> None:
    session = SessionManager(AuthConfig(type="header", headers={"X-Api": "session"}))
    headers = session.apply({"X-Api": "override"})
    assert headers["X-Api"] == "override"


def test_is_expired_only_after_established_and_on_signal() -> None:
    session = SessionManager(AuthConfig(type="form", form=FormLoginConfig(login_url="http://127.0.0.1/x")))
    # not established yet -> never considered expired (avoids thrashing before first login)
    assert session.is_expired(_resp(status=401)) is False
    session._established = True  # simulate a successful login
    assert session.is_expired(_resp(status=401)) is True
    assert session.is_expired(_resp(status=200)) is False


def test_is_expired_supports_body_pattern() -> None:
    auth = AuthConfig(
        type="form",
        form=FormLoginConfig(login_url="http://127.0.0.1/x"),
        logged_out_status=999,  # disable status-based detection
        logged_out_pattern="Please log in",
    )
    session = SessionManager(auth)
    session._established = True
    assert session.is_expired(_resp(status=200, text="<p>Please log in</p>")) is True
    assert session.is_expired(_resp(status=200, text="welcome")) is False


# --- integration: static cookie auth ---------------------------------------------------

async def test_static_cookie_auth_reaches_protected_page(vuln_app_url: str) -> None:
    login = httpx.post(f"{vuln_app_url}/auth/form-login", json={"username": "carol", "password": "carol-pw"})
    sid = login.cookies["sid"]

    session = SessionManager(AuthConfig(type="cookie", cookies={"sid": sid}))
    async with HttpClient(_SCOPE, session=session) as client:
        assert await session.ensure_logged_in(client, initial=True) is True
        response = await client.get(f"{vuln_app_url}/account")
    assert response.status_code == 200
    assert '"account"' in response.text


# --- integration: form login -----------------------------------------------------------

def _form_session(vuln_app_url: str) -> SessionManager:
    return SessionManager(
        AuthConfig(
            type="form",
            form=FormLoginConfig(
                login_url=f"{vuln_app_url}/auth/form-login",
                credentials={"username": "carol", "password": "carol-pw"},
            ),
        )
    )


async def test_form_login_establishes_session(vuln_app_url: str) -> None:
    session = _form_session(vuln_app_url)
    async with HttpClient(_SCOPE, session=session) as client:
        assert await session.ensure_logged_in(client, initial=True) is True
        assert session.is_established is True
        assert session.epoch == 1
        response = await client.get(f"{vuln_app_url}/account")
    assert response.status_code == 200


async def test_form_login_wrong_credentials_fails(vuln_app_url: str) -> None:
    session = SessionManager(
        AuthConfig(
            type="form",
            form=FormLoginConfig(
                login_url=f"{vuln_app_url}/auth/form-login",
                credentials={"username": "carol", "password": "WRONG"},
            ),
        )
    )
    async with HttpClient(_SCOPE, session=session) as client:
        assert await session.ensure_logged_in(client, initial=True) is False
        assert session.is_established is False


# --- integration: OAuth2 client credentials --------------------------------------------

async def test_oauth2_establishes_bearer_and_reaches_profile(vuln_app_url: str) -> None:
    session = SessionManager(
        AuthConfig(
            type="oauth2",
            oauth2=OAuth2Config(
                token_url=f"{vuln_app_url}/oauth/token",
                client_id="svc-client",
                client_secret="svc-secret",
            ),
        )
    )
    async with HttpClient(_SCOPE, session=session) as client:
        assert await session.ensure_logged_in(client, initial=True) is True
        headers = session.apply(None)
        assert headers["Authorization"].startswith("Bearer ")
        response = await client.get(f"{vuln_app_url}/api/profile")
    assert response.status_code == 200
    assert '"role"' in response.text


# --- integration: automatic re-login on dropped session --------------------------------

async def test_auto_relogin_after_session_dropped(vuln_app_url: str) -> None:
    session = _form_session(vuln_app_url)
    async with HttpClient(_SCOPE, session=session) as client:
        await session.ensure_logged_in(client, initial=True)
        assert (await client.get(f"{vuln_app_url}/account")).status_code == 200

        # Simulate the server expiring every session out from under us.
        httpx.post(f"{vuln_app_url}/auth/invalidate")

        # The scanner's own request should detect the 401, re-login, and retry -> 200.
        response = await client.get(f"{vuln_app_url}/account")
    assert response.status_code == 200
    assert session.epoch == 2  # initial login + one automatic re-login


async def test_relogin_budget_is_respected(vuln_app_url: str) -> None:
    auth = AuthConfig(
        type="form",
        form=FormLoginConfig(
            login_url=f"{vuln_app_url}/auth/form-login",
            credentials={"username": "carol", "password": "carol-pw"},
        ),
        max_relogin=0,  # forbid any re-login beyond the initial one
    )
    session = SessionManager(auth)
    async with HttpClient(_SCOPE, session=session) as client:
        await session.ensure_logged_in(client, initial=True)
        httpx.post(f"{vuln_app_url}/auth/invalidate")
        response = await client.get(f"{vuln_app_url}/account")
    assert response.status_code == 401  # budget exhausted, no re-login attempted
    assert session.epoch == 1


# --- integration: crawler & scanner operate authenticated ------------------------------

async def test_crawler_reaches_authenticated_only_pages(vuln_app_url: str) -> None:
    session = _form_session(vuln_app_url)
    async with HttpClient(_SCOPE, session=session) as client:
        await session.ensure_logged_in(client, initial=True)
        discovered = await HttpCrawler(client).crawl(f"{vuln_app_url}/dashboard")
    urls = {req.url for req in discovered}
    assert any(u.endswith("/dashboard/secret") for u in urls)
    assert any(u.endswith("/dashboard/lookup") for u in urls)


async def test_crawler_without_auth_cannot_see_authenticated_links(vuln_app_url: str) -> None:
    async with HttpClient(_SCOPE) as client:
        discovered = await HttpCrawler(client).crawl(f"{vuln_app_url}/dashboard")
    urls = {req.url for req in discovered}
    assert any(u.endswith("/dashboard") for u in urls)
    assert not any(u.endswith("/dashboard/secret") for u in urls)


async def test_scanner_finds_injection_behind_auth(vuln_app_url: str) -> None:
    request = HttpRequest(method="GET", url=f"{vuln_app_url}/dashboard/lookup", params={"q": "demo"})
    rules = load_rules()
    session = _form_session(vuln_app_url)
    async with HttpClient(_SCOPE, session=session) as client:
        await session.ensure_logged_in(client, initial=True)
        findings = await Scanner(client, rules).scan([request])
    assert any(f.id.startswith("sqli-injection:") for f in findings)


async def test_scanner_without_auth_finds_no_injection_behind_auth(vuln_app_url: str) -> None:
    request = HttpRequest(method="GET", url=f"{vuln_app_url}/dashboard/lookup", params={"q": "demo"})
    rules = load_rules()
    async with HttpClient(_SCOPE) as client:
        findings = await Scanner(client, rules).scan([request])
    assert not any(f.id.startswith("sqli-injection:") for f in findings)
