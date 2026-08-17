"""Tier B account recovery on the control-plane: password reset (via a one-time email link) and
non-blocking email verification. Uses a MemoryMailer so nothing touches the network."""

from __future__ import annotations

import re

import httpx
import pytest
from httpx import ASGITransport

from dastcore.cloud.app import create_app
from dastcore.cloud.mail import MemoryMailer

ADMIN = "admin-secret"


@pytest.fixture
def mailer() -> MemoryMailer:
    return MemoryMailer()


@pytest.fixture
def app(tmp_path, mailer):
    return create_app(tmp_path / "cloud.db", admin_token=ADMIN, mailer=mailer)


@pytest.fixture
def client(app):
    return httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://cp")


def _link_token(mailer: MemoryMailer, kind: str) -> str:
    for _to, _subject, body in reversed(mailer.outbox):
        match = re.search(kind + r"\?token=([A-Za-z0-9_-]+)", body)
        if match:
            return match.group(1)
    raise AssertionError(f"no {kind} link was emailed")


# --- password reset ----------------------------------------------------------------------


async def test_password_reset_flow(app, client, mailer) -> None:
    async with client:
        await client.post("/signup", data={"email": "u@ex.com", "password": "originalpw1"})
        await client.post("/ui/logout")

        asked = await client.post("/forgot", data={"email": "u@ex.com"})
        assert asked.status_code == 200 and "te hemos enviado" in asked.text

        token = _link_token(mailer, "reset")
        done = await client.post("/reset", data={"token": token, "password": "brandnewpw2"})
        assert done.status_code == 200 and "Contraseña actualizada" in done.text

    store = app.state.store
    assert store.account_project("u@ex.com", "originalpw1") is None  # old password revoked
    assert store.account_project("u@ex.com", "brandnewpw2") is not None  # new one works


async def test_forgot_does_not_reveal_whether_an_email_exists(app, client, mailer) -> None:
    async with client:
        resp = await client.post("/forgot", data={"email": "ghost@ex.com"})
        assert resp.status_code == 200 and "te hemos enviado" in resp.text  # same message as a real account
    assert all("ghost@ex.com" not in to for to, _s, _b in mailer.outbox)  # but nothing was actually sent


async def test_reset_with_invalid_token_is_rejected(app, client) -> None:
    async with client:
        resp = await client.post("/reset", data={"token": "not-a-real-token", "password": "whatever12"})
    assert resp.status_code == 400 and "no es válido" in resp.text


async def test_reset_token_is_single_use(app, client, mailer) -> None:
    async with client:
        await client.post("/signup", data={"email": "s@ex.com", "password": "firstpass1"})
        await client.post("/forgot", data={"email": "s@ex.com"})
        token = _link_token(mailer, "reset")

        first = await client.post("/reset", data={"token": token, "password": "secondpass2"})
        assert first.status_code == 200
        again = await client.post("/reset", data={"token": token, "password": "thirdpass33"})
        assert again.status_code == 400  # the link can't be replayed


# --- email verification (non-blocking) ---------------------------------------------------


async def test_email_verification_flow(app, client, mailer) -> None:
    async with client:
        await client.post("/signup", data={"email": "v@ex.com", "password": "supersecret"})
        # the account works immediately, but the dashboard nudges the user to verify
        assert "Verifica tu email" in (await client.get("/ui")).text

        token = _link_token(mailer, "verify")
        confirmed = await client.get(f"/verify?token={token}")
        assert confirmed.status_code == 200 and "verificado" in confirmed.text

        # once verified, the reminder is gone
        assert "Verifica tu email" not in (await client.get("/ui")).text


async def test_resend_verification_sends_a_fresh_link(app, client, mailer) -> None:
    async with client:
        await client.post("/signup", data={"email": "rv@ex.com", "password": "supersecret"})
        mailer.outbox.clear()
        resent = await client.post("/ui/resend-verification")
        assert resent.status_code == 200
    assert any("verify?token=" in body for _t, _s, body in mailer.outbox)
