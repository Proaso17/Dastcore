"""Phase 2 — self-service accounts on the control-plane: signup (email+password -> own project +
API key), email/password login, a real session decoupled from the raw API key, API-key regeneration,
and basic signup rate limiting."""

from __future__ import annotations

import re

import httpx
import pytest
from httpx import ASGITransport

from dastcore.cloud.app import create_app

ADMIN = "admin-secret"
_KEY_RE = re.compile(r"dast_[A-Za-z0-9_-]+")


@pytest.fixture
def app(tmp_path):
    return create_app(tmp_path / "cloud.db", admin_token=ADMIN)


@pytest.fixture
def client(app):
    return httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://cp")


def _api_key(html: str) -> str:
    match = _KEY_RE.search(html)
    assert match, "expected an API key in the page"
    return match.group(0)


async def test_signup_creates_account_project_and_session(app, client) -> None:
    async with client:
        resp = await client.post(
            "/signup", data={"email": "a@ex.com", "password": "supersecret", "project_name": "Mi web"}
        )
        assert resp.status_code == 200
        assert "dast_session" in resp.headers.get("set-cookie", "")  # a session was established
        api_key = _api_key(resp.text)

        # the session cookie (carried by the client) grants dashboard access, no API key needed
        dash = await client.get("/ui")
        assert dash.status_code == 200 and "Mi web" in dash.text

    # the account + project + key exist in the store
    project_id = app.state.store.project_for_key(api_key)
    assert project_id is not None
    assert app.state.store.account_project("a@ex.com", "supersecret") == project_id


async def test_signup_rejects_duplicate_and_invalid(app, client) -> None:
    async with client:
        await client.post("/signup", data={"email": "dup@ex.com", "password": "supersecret"})
        again = await client.post("/signup", data={"email": "dup@ex.com", "password": "supersecret"})
        assert again.status_code == 400 and "ya tiene una cuenta" in again.text

        bad_email = await client.post("/signup", data={"email": "nope", "password": "supersecret"})
        assert bad_email.status_code == 400
        short_pw = await client.post("/signup", data={"email": "x@ex.com", "password": "short"})
        assert short_pw.status_code == 400 and "8 caracteres" in short_pw.text


async def test_email_password_login(app, client) -> None:
    async with client:
        await client.post("/signup", data={"email": "u@ex.com", "password": "supersecret"})
        await client.post("/ui/logout")  # clear the signup session

        wrong = await client.post("/login", data={"email": "u@ex.com", "password": "WRONG"})
        assert wrong.status_code == 400

        ok = await client.post("/login", data={"email": "u@ex.com", "password": "supersecret"}, follow_redirects=False)
        assert ok.status_code == 303 and "dast_session" in ok.headers.get("set-cookie", "")
        assert (await client.get("/ui")).status_code == 200


async def test_regenerate_api_key_invalidates_old(app, client) -> None:
    async with client:
        signup = await client.post("/signup", data={"email": "r@ex.com", "password": "supersecret"})
        old_key = _api_key(signup.text)
        regen = await client.post("/ui/regenerate-key")  # uses the session cookie
        new_key = _api_key(regen.text)
    assert new_key != old_key
    store = app.state.store
    assert store.project_for_key(old_key) is None  # old key no longer authenticates
    assert store.project_for_key(new_key) is not None


async def test_logout_clears_the_session(app, client) -> None:
    async with client:
        await client.post("/signup", data={"email": "o@ex.com", "password": "supersecret"})
        assert (await client.get("/ui")).status_code == 200
        await client.post("/ui/logout")
        after = await client.get("/ui", follow_redirects=False)
    assert after.status_code == 303  # no session -> redirected to the login page


async def test_signup_is_rate_limited(app, client) -> None:
    async with client:
        statuses = []
        for i in range(7):
            resp = await client.post("/signup", data={"email": f"n{i}@ex.com", "password": "supersecret"})
            statuses.append(resp.status_code)
    assert 429 in statuses  # after a burst from one IP, signup is throttled
