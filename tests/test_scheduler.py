"""Recurring-scan scheduler: HTTP CRUD + tick() launching due schedules end to end."""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest
from httpx import ASGITransport

from dastcore.web.app import create_app


@pytest.fixture
def app(tmp_path):
    return create_app(db_path=tmp_path / "db.sqlite")


@pytest.fixture
def client(app):
    return httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def test_schedules_page_and_auth_gate(client: httpx.AsyncClient, mini_target_url: str) -> None:
    async with client:
        empty = await client.get("/schedules")
        assert empty.status_code == 200
        assert "Sin escaneos programados" in empty.text

        # without the authorization checkbox the schedule is rejected
        denied = await client.post("/schedules", data={"target": mini_target_url, "interval_minutes": "1440"})
        assert "autorización" in denied.text.lower()
        assert "Sin escaneos programados" in denied.text

        created = await client.post(
            "/schedules",
            data={"target": mini_target_url, "interval_minutes": "60", "authorization": "on"},
            follow_redirects=False,
        )
        assert created.status_code == 303
        page = await client.get("/schedules")
        assert mini_target_url in page.text
        assert "activo" in page.text  # the new schedule row is enabled
        assert "Sin escaneos programados" not in page.text


async def test_tick_launches_due_schedule(app, mini_target_url: str) -> None:
    store = app.state.store
    scheduler = app.state.scheduler

    now = time.time()
    store.add_schedule(
        target=mini_target_url,
        engine="http",
        profile=None,
        rps=50,
        auth_bearer="",
        auth_cookie="",
        interval_minutes=60,
        now=now,
    )
    # not due yet (first run is one interval away)
    assert await scheduler.tick(now=now) == 0
    assert store.list_scans() == []

    # once the interval has elapsed it fires exactly one scan and advances
    launched = await scheduler.tick(now=now + 3700)
    assert launched == 1
    scans = store.list_scans()
    assert len(scans) == 1

    sched = store.list_schedules()[0]
    assert sched.last_run_at is not None
    assert sched.next_run_at > now + 3700

    # let the launched scan finish on this event loop (generous under CI/system load)
    for _ in range(600):
        if store.get_scan(scans[0].id).status in ("done", "error"):
            break
        await asyncio.sleep(0.5)
    assert store.get_scan(scans[0].id).status == "done"


async def test_disabled_schedule_does_not_fire(app, mini_target_url: str) -> None:
    store = app.state.store
    scheduler = app.state.scheduler
    now = time.time()
    store.add_schedule(
        target=mini_target_url,
        engine="http",
        profile=None,
        rps=50,
        auth_bearer="",
        auth_cookie="",
        interval_minutes=60,
        now=now,
    )
    store.set_schedule_enabled(store.list_schedules()[0].id, False)
    assert await scheduler.tick(now=now + 3700) == 0
    assert store.list_scans() == []
