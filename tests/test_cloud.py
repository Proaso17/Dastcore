"""Cloud control-plane API + runner protocol, driven over an in-process transport.

The runner e2e test exercises the whole SaaS loop: enqueue a job on the control
plane, have the runner claim it, scan the local vuln app for real, and push the
findings back — all offline.
"""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport

from dastcore.cloud.app import create_app
from dastcore.cloud.runner import run_once

ADMIN = "admintok"


def make_app(tmp_path):
    return create_app(tmp_path / "cloud.db", admin_token=ADMIN)


@pytest.fixture
def client(tmp_path):
    app = make_app(tmp_path)
    return httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://cp")


async def _new_project(client: httpx.AsyncClient, name: str = "acme") -> str:
    resp = await client.post("/api/projects", json={"name": name}, headers={"Authorization": f"Bearer {ADMIN}"})
    assert resp.status_code == 201
    return resp.json()["api_key"]


async def test_project_creation_requires_admin(client: httpx.AsyncClient) -> None:
    async with client:
        bad = await client.post("/api/projects", json={"name": "x"}, headers={"Authorization": "Bearer wrong"})
        assert bad.status_code == 403
        ok = await client.post("/api/projects", json={"name": "x"}, headers={"Authorization": f"Bearer {ADMIN}"})
        assert ok.status_code == 201
        assert ok.json()["api_key"].startswith("dast_")


async def test_full_job_lifecycle(client: httpx.AsyncClient) -> None:
    async with client:
        key = await _new_project(client)
        h = {"Authorization": f"Bearer {key}"}

        # an invalid project key is rejected
        assert (await client.get("/api/jobs", headers={"Authorization": "Bearer nope"})).status_code == 401

        enq = await client.post("/api/jobs", json={"target": "http://t.test/", "engine": "http"}, headers=h)
        assert enq.status_code == 201
        job_id = enq.json()["id"]

        claim = await client.post("/api/runner/claim", headers=h)
        assert claim.status_code == 200
        assert claim.json()["id"] == job_id
        # nothing left in the queue
        assert (await client.post("/api/runner/claim", headers=h)).status_code == 204

        result = await client.post(
            f"/api/runner/jobs/{job_id}/result", json={"status": "done", "findings": []}, headers=h
        )
        assert result.status_code == 200

        got = await client.get(f"/api/jobs/{job_id}", headers=h)
        assert got.json()["status"] == "done"


async def test_projects_are_isolated(client: httpx.AsyncClient) -> None:
    async with client:
        key_a = await _new_project(client, "a")
        key_b = await _new_project(client, "b")
        job_id = (
            await client.post(
                "/api/jobs", json={"target": "http://t.test/"}, headers={"Authorization": f"Bearer {key_a}"}
            )
        ).json()["id"]

        # project B cannot see A's job, and A's job is not claimable from B
        assert (
            await client.get(f"/api/jobs/{job_id}", headers={"Authorization": f"Bearer {key_b}"})
        ).status_code == 404
        assert (await client.post("/api/runner/claim", headers={"Authorization": f"Bearer {key_b}"})).status_code == 204


async def test_runner_scans_target_and_reports(client: httpx.AsyncClient, vuln_app_url: str) -> None:
    async with client:
        key = await _new_project(client)
        h = {"Authorization": f"Bearer {key}"}
        job_id = (
            await client.post("/api/jobs", json={"target": vuln_app_url, "engine": "http", "rps": 50}, headers=h)
        ).json()["id"]

        # the runner claims the job, scans the vuln app for real, and reports back
        handled = await run_once(client, key)
        assert handled is True

        got = (await client.get(f"/api/jobs/{job_id}", headers=h)).json()
        assert got["status"] == "done"
        assert got["num_findings"] > 0
        rule_ids = {f["rule_id"] for f in got["findings"]}
        assert "sqli-injection" in rule_ids  # planted vuln surfaced through the whole cloud loop


async def test_runner_with_empty_queue_returns_false(client: httpx.AsyncClient) -> None:
    async with client:
        key = await _new_project(client)
        assert await run_once(client, key) is False
