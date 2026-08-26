"""Concurrent re-login must coalesce to ONE login, not a stampede — the fix for the cascade that
killed authenticated scans of bWAPP under concurrency (every stale-cookie request triggered its own
re-login, each minting a fresh cookie that invalidated the last, until max_relogin was spent)."""

from __future__ import annotations

import asyncio

from dastcore.config import AuthConfig, FormLoginConfig
from dastcore.core.session import SessionManager


def _session() -> SessionManager:
    auth = AuthConfig(
        type="form", form=FormLoginConfig(login_url="http://app.test/login", credentials={"u": "a"})
    )
    sm = SessionManager(auth)
    sm._established = True
    return sm


async def test_concurrent_relogin_coalesces_to_one() -> None:
    sm = _session()
    calls = 0

    async def fake_login(_client: object) -> bool:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.02)  # hold the lock so the burst piles up behind it
        return True

    sm._perform_login = fake_login  # type: ignore[assignment]
    # Ten tasks that all observed expiry at the same epoch (a concurrent drop wave).
    results = await asyncio.gather(*(sm.ensure_logged_in(None, seen_epoch=0) for _ in range(10)))  # type: ignore[arg-type]
    assert all(results)
    assert calls == 1  # exactly one real re-login; the other nine saw the advanced epoch and skipped


async def test_wait_until_ready_blocks_until_relogin_finishes() -> None:
    sm = _session()
    order: list[str] = []

    async def slow_login(_client: object) -> bool:
        await asyncio.sleep(0.05)
        order.append("login-done")
        return True

    sm._perform_login = slow_login  # type: ignore[assignment]

    async def waiter() -> None:
        await asyncio.sleep(0.01)  # ensure the re-login has taken the lock first
        await sm.wait_until_ready()
        order.append("ready-returned")

    await asyncio.gather(sm.ensure_logged_in(None, seen_epoch=0), waiter())  # type: ignore[arg-type]
    assert order == ["login-done", "ready-returned"]  # the waiter blocked until the re-login completed


async def test_wait_until_ready_returns_immediately_when_idle() -> None:
    sm = _session()
    await asyncio.wait_for(sm.wait_until_ready(), timeout=0.5)  # no re-login in flight -> instant
