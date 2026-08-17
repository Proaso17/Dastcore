"""Cloud control-plane API + runner protocol + scheduling + UI, over an in-process transport.

The runner e2e test exercises the whole SaaS loop: enqueue a job, register a runner,
have it claim the job, scan the local vuln app for real, and push findings back.
"""

from __future__ import annotations

import time

import httpx
import pytest
from httpx import ASGITransport

from dastcore.cloud.app import create_app
from dastcore.cloud.models import ScheduleCreate
from dastcore.cloud.runner import run_once

ADMIN = "admintok"


@pytest.fixture
def app(tmp_path):
    return create_app(tmp_path / "cloud.db", admin_token=ADMIN)


@pytest.fixture
def client(app):
    return httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://cp")


async def _new_project(client: httpx.AsyncClient, name: str = "acme") -> str:
    resp = await client.post("/api/projects", json={"name": name}, headers={"Authorization": f"Bearer {ADMIN}"})
    assert resp.status_code == 201
    return resp.json()["api_key"]


async def _new_runner(client: httpx.AsyncClient, project_key: str, name: str = "r1") -> str:
    resp = await client.post("/api/runners", json={"name": name}, headers={"Authorization": f"Bearer {project_key}"})
    assert resp.status_code == 201
    return resp.json()["token"]


# --- auth scopes -------------------------------------------------------------------------


async def test_project_creation_requires_admin(client: httpx.AsyncClient) -> None:
    async with client:
        bad = await client.post("/api/projects", json={"name": "x"}, headers={"Authorization": "Bearer wrong"})
        assert bad.status_code == 403
        ok = await client.post("/api/projects", json={"name": "x"}, headers={"Authorization": f"Bearer {ADMIN}"})
        assert ok.status_code == 201
        assert ok.json()["api_key"].startswith("dast_")


async def test_runner_token_cannot_enqueue_and_project_key_cannot_claim(client: httpx.AsyncClient) -> None:
    async with client:
        key = await _new_project(client)
        runner_token = await _new_runner(client, key)

        # runner token has no enqueue rights
        enq = await client.post(
            "/api/jobs", json={"target": "http://t.test/"}, headers={"Authorization": f"Bearer {runner_token}"}
        )
        assert enq.status_code == 401
        # project key can't claim (that needs a runner token)
        claim = await client.post("/api/runner/claim", headers={"Authorization": f"Bearer {key}"})
        assert claim.status_code == 401


# --- job lifecycle -----------------------------------------------------------------------


async def test_full_job_lifecycle(client: httpx.AsyncClient) -> None:
    async with client:
        key = await _new_project(client)
        runner_token = await _new_runner(client, key)
        proj_h = {"Authorization": f"Bearer {key}"}
        run_h = {"Authorization": f"Bearer {runner_token}"}

        job_id = (
            await client.post("/api/jobs", json={"target": "http://t.test/", "engine": "http"}, headers=proj_h)
        ).json()["id"]

        claim = await client.post("/api/runner/claim", headers=run_h)
        assert claim.status_code == 200 and claim.json()["id"] == job_id
        assert (await client.post("/api/runner/claim", headers=run_h)).status_code == 204  # queue empty

        result = await client.post(
            f"/api/runner/jobs/{job_id}/result", json={"status": "done", "findings": []}, headers=run_h
        )
        assert result.status_code == 200

        got = await client.get(f"/api/jobs/{job_id}", headers=proj_h)
        assert got.json()["status"] == "done"

        # heartbeat works and the runner shows up in the project's list
        assert (await client.post("/api/runner/heartbeat", headers=run_h)).json()["status"] == "ok"
        runners = (await client.get("/api/runners", headers=proj_h)).json()["runners"]
        assert runners and runners[0]["last_seen_at"] is not None


async def test_projects_are_isolated(client: httpx.AsyncClient) -> None:
    async with client:
        key_a = await _new_project(client, "a")
        key_b = await _new_project(client, "b")
        runner_b = await _new_runner(client, key_b)
        job_id = (
            await client.post(
                "/api/jobs", json={"target": "http://t.test/"}, headers={"Authorization": f"Bearer {key_a}"}
            )
        ).json()["id"]

        # B can't read A's job, and B's runner can't claim it
        assert (
            await client.get(f"/api/jobs/{job_id}", headers={"Authorization": f"Bearer {key_b}"})
        ).status_code == 404
        assert (
            await client.post("/api/runner/claim", headers={"Authorization": f"Bearer {runner_b}"})
        ).status_code == 204


# --- runner e2e --------------------------------------------------------------------------


async def test_runner_scans_target_and_reports(client: httpx.AsyncClient, mini_target_url: str) -> None:
    async with client:
        key = await _new_project(client)
        runner_token = await _new_runner(client, key)
        proj_h = {"Authorization": f"Bearer {key}"}
        job_id = (
            await client.post(
                "/api/jobs", json={"target": mini_target_url, "engine": "http", "rps": 50}, headers=proj_h
            )
        ).json()["id"]

        assert await run_once(client, runner_token) is True

        got = (await client.get(f"/api/jobs/{job_id}", headers=proj_h)).json()
        assert got["status"] == "done"
        assert got["num_findings"] > 0
        assert "sqli-injection" in {f["rule_id"] for f in got["findings"]}


async def test_runner_runs_embedded_chatbot_scan(client: httpx.AsyncClient, chatbot_app_url: str, monkeypatch) -> None:
    """The whole SaaS loop for an 'ai' job: enqueue a chatbot scan with a second identity,
    a runner claims it, discovers the bot and runs the LLM checks, and reports the findings.

    The static crawler can't reach a JS chat XHR, so we feed the runner the requests the
    headless engine would capture (same shim as the CLI/web discovery tests)."""
    import dastcore.cli as cli
    from dastcore.core.models import HttpRequest

    auth_a = {"Authorization": "Bearer tok-a"}
    candidates = [
        HttpRequest(method="POST", url=f"{chatbot_app_url}/api/chat", headers=auth_a, json_body={"message": "hi"}),
        HttpRequest(method="POST", url=f"{chatbot_app_url}/api/messages", headers=auth_a, json_body={"text": "n"}),
    ]

    class _FakeCrawler:
        def __init__(self, http_client, max_pages=200):
            pass

        async def crawl(self, start_url):
            return candidates

    monkeypatch.setattr(cli, "HttpCrawler", _FakeCrawler)
    async with client:
        key = await _new_project(client)
        runner_token = await _new_runner(client, key)
        proj_h = {"Authorization": f"Bearer {key}"}
        job_id = (
            await client.post(
                "/api/jobs",
                json={
                    "target": chatbot_app_url,
                    "mode": "ai",
                    "rps": 50,
                    "auth_bearer": "tok-a",
                    "victim_bearer": "tok-b",
                    "victim_refs": ["unit 4B"],
                },
                headers=proj_h,
            )
        ).json()["id"]

        assert await run_once(client, runner_token) is True

        got = (await client.get(f"/api/jobs/{job_id}", headers=proj_h)).json()
        assert got["status"] == "done"
        rule_ids = {f["rule_id"] for f in got["findings"]}
        assert "llm-stored-injection" in rule_ids
        assert "llm-cross-tenant-leak" in rule_ids


async def test_runner_with_empty_queue_returns_false(client: httpx.AsyncClient) -> None:
    async with client:
        key = await _new_project(client)
        runner_token = await _new_runner(client, key)
        assert await run_once(client, runner_token) is False


# --- scheduling --------------------------------------------------------------------------


async def test_scheduler_enqueues_due_jobs(app, client: httpx.AsyncClient) -> None:
    store = app.state.store
    scheduler = app.state.scheduler
    async with client:
        key = await _new_project(client)
        project_id = store.project_for_key(key)
        now = time.time()
        store.create_schedule(project_id, ScheduleCreate(target="http://t.test/", interval_minutes=60), now)

        assert await scheduler.tick(now=now) == 0  # first run is one interval away
        assert store.list_jobs(project_id) == []

        assert await scheduler.tick(now=now + 3700) == 1  # due -> a job is enqueued
        jobs = store.list_jobs(project_id)
        assert len(jobs) == 1 and jobs[0].status == "queued"


# --- UI ----------------------------------------------------------------------------------


async def test_control_plane_sets_security_headers(client: httpx.AsyncClient) -> None:
    async with client:
        resp = await client.get("/api/health")
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert "object-src 'none'" in resp.headers["content-security-policy"]
    assert "strict-transport-security" not in resp.headers  # not over plain HTTP


async def test_https_deploy_gets_hsts_and_secure_cookie(client: httpx.AsyncClient) -> None:
    https = {"X-Forwarded-Proto": "https"}  # behind a TLS-terminating proxy
    async with client:
        key = await _new_project(client)
        health = await client.get("/api/health", headers=https)
        assert "max-age" in health.headers.get("strict-transport-security", "")
        login = await client.post("/ui/login", data={"api_key": key}, headers=https, follow_redirects=False)
        assert "secure" in login.headers.get("set-cookie", "").lower()


async def test_ui_login_and_dashboard(client: httpx.AsyncClient) -> None:
    async with client:
        key = await _new_project(client)

        landing = await client.get("/")
        assert "Iniciar sesión" in landing.text and "Entrar con API key" in landing.text

        bad = await client.post("/ui/login", data={"api_key": "nope"})
        assert bad.status_code == 400

        login = await client.post("/ui/login", data={"api_key": key}, follow_redirects=False)
        assert login.status_code == 303  # cookie set by the client for the next request

        dash = await client.get("/ui")
        assert dash.status_code == 200
        assert "Encolar escaneo" in dash.text
        assert "Runners" in dash.text
        assert "Chatbot embebido" in dash.text  # the AI scan mode is offered in the enqueue form


async def test_ui_enqueues_an_ai_chatbot_job(client: httpx.AsyncClient) -> None:
    async with client:
        key = await _new_project(client)
        proj_h = {"Authorization": f"Bearer {key}"}
        await client.post("/ui/login", data={"api_key": key}, follow_redirects=False)

        enq = await client.post(
            "/ui/jobs",
            data={
                "target": "https://app.test",
                "mode": "ai",
                "auth_bearer": "tok-a",
                "victim_bearer": "tok-b",
                "victim_ref": "unit 4B\nbob",
            },
            follow_redirects=False,
        )
        assert enq.status_code == 303

        jobs = (await client.get("/api/jobs", headers=proj_h)).json()["jobs"]
        assert len(jobs) == 1 and jobs[0]["mode"] == "ai"
