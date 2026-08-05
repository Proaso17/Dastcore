"""Sanity checks for the vulnerable test fixture itself (Phase 0.5).

These don't test dastcore — they confirm the fixture reliably exhibits the
vulnerabilities it's meant to plant, so later phases have known ground truth.
"""

from __future__ import annotations

import httpx


def test_health(vuln_app_url: str) -> None:
    resp = httpx.get(f"{vuln_app_url}/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_search_reflects_input_normally(vuln_app_url: str) -> None:
    resp = httpx.get(f"{vuln_app_url}/search", params={"q": "Laptop"})
    assert resp.status_code == 200
    assert "Laptop" in resp.text


def test_search_is_sql_injectable(vuln_app_url: str) -> None:
    resp = httpx.get(f"{vuln_app_url}/search", params={"q": "'"})
    assert resp.status_code == 500
    assert "SQLite3::error" in resp.text


def test_greet_is_reflected_xss(vuln_app_url: str) -> None:
    payload = "<script>alert(1)</script>"
    resp = httpx.get(f"{vuln_app_url}/greet", params={"name": payload})
    assert resp.status_code == 200
    assert payload in resp.text


def test_go_is_open_redirect(vuln_app_url: str) -> None:
    resp = httpx.get(f"{vuln_app_url}/go", params={"url": "http://attacker.example/"}, follow_redirects=False)
    assert resp.status_code in (301, 302, 303, 307, 308)
    assert resp.headers["location"] == "http://attacker.example/"


def test_orders_require_authentication(vuln_app_url: str) -> None:
    resp = httpx.get(f"{vuln_app_url}/api/orders/101")
    assert resp.status_code == 401


def test_form_login_sets_session_cookie_and_protects_account(vuln_app_url: str) -> None:
    unauth = httpx.get(f"{vuln_app_url}/account")
    assert unauth.status_code == 401

    login = httpx.post(f"{vuln_app_url}/auth/form-login", json={"username": "carol", "password": "carol-pw"})
    assert login.status_code == 200
    sid = login.cookies.get("sid")
    assert sid

    authed = httpx.get(f"{vuln_app_url}/account", cookies={"sid": sid})
    assert authed.status_code == 200
    assert authed.json()["account"] == "carol"


def test_invalidate_drops_sessions(vuln_app_url: str) -> None:
    login = httpx.post(f"{vuln_app_url}/auth/form-login", json={"username": "carol", "password": "carol-pw"})
    sid = login.cookies.get("sid")
    assert httpx.get(f"{vuln_app_url}/account", cookies={"sid": sid}).status_code == 200

    httpx.post(f"{vuln_app_url}/auth/invalidate")
    assert httpx.get(f"{vuln_app_url}/account", cookies={"sid": sid}).status_code == 401


def test_oauth_token_and_bearer_protected_profile(vuln_app_url: str) -> None:
    assert httpx.get(f"{vuln_app_url}/api/profile").status_code == 401

    token_resp = httpx.post(
        f"{vuln_app_url}/oauth/token",
        data={"grant_type": "client_credentials", "client_id": "svc-client", "client_secret": "svc-secret"},
    )
    assert token_resp.status_code == 200
    token = token_resp.json()["access_token"]

    authed = httpx.get(f"{vuln_app_url}/api/profile", headers={"Authorization": f"Bearer {token}"})
    assert authed.status_code == 200
    assert authed.json()["role"] == "service"


def test_orders_is_idor(vuln_app_url: str) -> None:
    login = httpx.post(
        f"{vuln_app_url}/login",
        json={"username": "bob", "password": "bob123"},
    )
    assert login.status_code == 200
    cookie = login.cookies.get("session_user_id")
    assert cookie == "2"

    # Bob (user_id=2) can read Alice's order (owner_id=1) — no ownership check (IDOR/BOLA).
    resp = httpx.get(f"{vuln_app_url}/api/orders/101", cookies={"session_user_id": cookie})
    assert resp.status_code == 200
    assert resp.json()["owner_id"] == 1
