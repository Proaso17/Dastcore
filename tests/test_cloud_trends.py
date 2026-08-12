"""SaaS history + trends: per-target findings-over-time in the dashboard and /api/trends."""

from __future__ import annotations

import httpx
from httpx import ASGITransport

from dastcore.cloud.app import _build_trends, _sparkline_points, create_app
from dastcore.cloud.models import JobSpec
from dastcore.cloud.store import Store

ADMIN = "admintok"


def _complete(store: Store, project_id: str, target: str, counts: dict[str, int]) -> None:
    import json
    import time

    job_id = store.enqueue_job(project_id, JobSpec(target=target))
    store.claim_job(project_id, "r1")
    total = sum(counts.values())
    # complete_job derives counts from findings; write the aggregate row directly for the trend.
    store._db.execute(  # noqa: SLF001 — test reaches into the store to seed history cheaply
        "UPDATE jobs SET status='done', finished_at=?, num_findings=?, severity_counts=? WHERE id=?",
        (time.time(), total, json.dumps(counts), job_id),
    )


# --- pure helpers ----------------------------------------------------------------------


def test_sparkline_points_spans_the_canvas() -> None:
    pts = _sparkline_points([1, 5, 3]).split()
    assert len(pts) == 3
    # first x is at the left pad, last x near the right edge
    assert float(pts[0].split(",")[0]) < float(pts[-1].split(",")[0])


def test_build_trends_groups_and_deltas() -> None:
    points = [
        {"target": "http://a.test", "num_findings": 2, "severity_counts": {"high": 2}},
        {"target": "http://a.test", "num_findings": 5, "severity_counts": {"high": 5}},
        {"target": "http://b.test", "num_findings": 1, "severity_counts": {"low": 1}},
    ]
    trends = {t["target"]: t for t in _build_trends(points)}
    assert trends["http://a.test"]["scans"] == 2
    assert trends["http://a.test"]["latest"] == 5 and trends["http://a.test"]["delta"] == 3  # 5 - 2
    assert trends["http://b.test"]["delta"] is None  # single scan → no previous
    # sorted most-findings first
    assert _build_trends(points)[0]["target"] == "http://a.test"


# --- store + API -----------------------------------------------------------------------


def test_trend_points_are_ordered_completed_scans(tmp_path) -> None:
    store = Store(tmp_path / "c.db")
    project_id, _ = store.create_project("acme")
    _complete(store, project_id, "http://a.test", {"high": 1})
    _complete(store, project_id, "http://a.test", {"high": 3})
    points = store.trend_points(project_id)
    assert [p["num_findings"] for p in points] == [1, 3]  # oldest → newest
    assert all(p["target"] == "http://a.test" for p in points)


async def test_api_trends_reports_per_target_series(tmp_path) -> None:
    app = create_app(tmp_path / "c.db", admin_token=ADMIN)
    store = app.state.store  # seed through the app's own store (one connection)
    project_id, key = store.create_project("acme")
    _complete(store, project_id, "http://a.test", {"high": 2})
    _complete(store, project_id, "http://a.test", {"high": 4, "low": 1})
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://cp") as client:
        resp = await client.get("/api/trends", headers={"Authorization": f"Bearer {key}"})
    assert resp.status_code == 200
    trends = resp.json()["trends"]
    assert len(trends) == 1
    row = trends[0]
    assert row["target"] == "http://a.test" and row["scans"] == 2
    assert row["latest"] == 5 and row["delta"] == 3  # 5 findings now vs 2 before
    assert row["severity_counts"]["high"] == 4


async def test_dashboard_renders_trends_panel(tmp_path) -> None:
    app = create_app(tmp_path / "c.db", admin_token=ADMIN)
    store = app.state.store
    project_id, key = store.create_project("acme")
    _complete(store, project_id, "http://a.test", {"high": 2})
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://cp") as client:
        client.cookies.set("dast_key", key)
        html = (await client.get("/ui")).text
    assert "Tendencias por objetivo" in html and "<polyline" in html
