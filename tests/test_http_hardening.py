"""Tier A production hardening shared by both FastAPI apps (dastcore.httpsec):

- CSRF: cross-origin state-changing requests are refused (Origin/Referer check).
- Login rate limiting: a burst of failed logins from one IP is throttled.
- Friendly error page: an unhandled exception renders a clean page / JSON, never a stack trace.
"""

from __future__ import annotations

import httpx
from httpx import ASGITransport

from dastcore.cloud.app import create_app as create_cloud_app
from dastcore.web.app import create_app as create_web_app

ADMIN = "admintok"


def _client(app: object, *, raise_exc: bool = True, base: str = "http://cp") -> httpx.AsyncClient:
    transport = ASGITransport(app=app, raise_app_exceptions=raise_exc)  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=transport, base_url=base)


# --- CSRF: cross-origin state-changing requests are refused -------------------------------


async def test_cross_origin_post_is_refused_on_control_plane(tmp_path) -> None:
    app = create_cloud_app(tmp_path / "c.db", admin_token=ADMIN)
    async with _client(app) as client:
        # a POST carrying a foreign Origin is rejected before it reaches the route
        evil = await client.post("/ui/login", data={"api_key": "x"}, headers={"Origin": "http://evil.test"})
        assert evil.status_code == 403 and "CSRF" in evil.text
        # a same-origin POST passes the CSRF gate (then fails on the bad key, not on CSRF)
        same = await client.post("/ui/login", data={"api_key": "x"}, headers={"Origin": "http://cp"})
        assert same.status_code == 400
        # a request with neither Origin nor Referer (API clients, curl, runners) is left alone
        plain = await client.post("/ui/login", data={"api_key": "x"})
        assert plain.status_code == 400


async def test_cross_origin_post_is_refused_on_dashboard(tmp_path) -> None:
    app = create_web_app(db_path=tmp_path / "w.db")
    async with _client(app, base="http://test") as client:
        # a malicious page can't make the local dashboard start a scan cross-site
        evil = await client.post(
            "/scans", data={"target": "http://t.test"}, headers={"Origin": "http://attacker.test"}
        )
        assert evil.status_code == 403
        # a foreign Referer (no Origin) is caught too
        ref = await client.post(
            "/scans", data={"target": "http://t.test"}, headers={"Referer": "http://attacker.test/x"}
        )
        assert ref.status_code == 403


# --- login rate limiting -----------------------------------------------------------------


async def test_login_is_rate_limited(tmp_path) -> None:
    app = create_cloud_app(tmp_path / "c.db", admin_token=ADMIN)
    async with _client(app) as client:
        statuses = [(await client.post("/ui/login", data={"api_key": "nope"})).status_code for _ in range(12)]
    assert 429 in statuses  # a brute-force burst from one IP is throttled


# --- friendly error page -----------------------------------------------------------------


async def test_unhandled_error_renders_friendly_page(tmp_path) -> None:
    app = create_web_app(db_path=tmp_path / "w.db")

    @app.get("/_boom")
    def _boom() -> None:
        raise RuntimeError("kaboom-secret-detail")

    @app.get("/api/_boom")
    def _boom_api() -> None:
        raise RuntimeError("kaboom-secret-detail")

    async with _client(app, raise_exc=False, base="http://test") as client:
        html = await client.get("/_boom")
        assert html.status_code == 500
        assert "Algo salió mal" in html.text  # a friendly page...
        assert "kaboom-secret-detail" not in html.text and "Traceback" not in html.text  # ...not a stack trace
        api = await client.get("/api/_boom")
        assert api.status_code == 500 and api.json()["detail"] == "internal server error"
