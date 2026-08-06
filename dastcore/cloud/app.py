"""Control-plane API.

Two auth scopes, both via ``Authorization: Bearer <token>``:
- the **admin token** (set when the server starts) creates projects;
- a **project API key** scopes everything else — enqueueing jobs, reading results,
  and the runner claim/result protocol.

For the MVP a project's single API key authorizes both the user (enqueue/read) and
its runners (claim/result). A production split would issue separate runner tokens.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse, Response

from dastcore.cloud.models import JobResult, JobSpec, ProjectCreate
from dastcore.cloud.store import JobRow, Store
from dastcore.core.models import Finding


def _bearer(authorization: str) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or malformed Authorization header")
    return authorization[7:].strip()


def _job_summary(job: JobRow) -> dict:
    return {
        "id": job.id,
        "target": job.target,
        "engine": job.engine,
        "profile": job.profile,
        "status": job.status,
        "runner": job.runner,
        "created_at": job.created_at,
        "finished_at": job.finished_at,
        "num_findings": job.num_findings,
        "severity_counts": job.severity_counts,
        "error": job.error,
    }


def create_app(db_path: str | Path = "dastcore-cloud.db", *, admin_token: str) -> FastAPI:
    """Build the control-plane app. ``admin_token`` guards project creation."""
    store = Store(db_path)
    app = FastAPI(title="dastcore control-plane", docs_url=None, redoc_url=None)
    app.state.store = store
    app.state.admin_token = admin_token

    def require_admin(authorization: str) -> None:
        if not secrets.compare_digest(_bearer(authorization), admin_token):
            raise HTTPException(status_code=403, detail="admin token required")

    def require_project(authorization: str) -> str:
        project_id = store.project_for_key(_bearer(authorization))
        if project_id is None:
            raise HTTPException(status_code=401, detail="invalid project API key")
        return project_id

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok"}

    # --- admin ------------------------------------------------------------------------

    @app.post("/api/projects", status_code=201)
    def create_project(body: ProjectCreate, authorization: str = Header(default="")) -> dict:
        require_admin(authorization)
        project_id, api_key = store.create_project(body.name)
        # The API key is shown exactly once here.
        return {"id": project_id, "name": body.name, "api_key": api_key}

    # --- user (project-scoped) --------------------------------------------------------

    @app.post("/api/jobs", status_code=201)
    def enqueue(spec: JobSpec, authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        job_id = store.enqueue_job(project_id, spec)
        return {"id": job_id, "status": "queued"}

    @app.get("/api/jobs")
    def list_jobs(authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        return {"jobs": [_job_summary(job) for job in store.list_jobs(project_id)]}

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str, authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        job = store.get_job(project_id, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        detail = _job_summary(job)
        if job.status == "done":
            detail["findings"] = [f.model_dump(mode="json") for f in store.get_findings(project_id, job_id)]
        return detail

    # --- runner protocol --------------------------------------------------------------

    @app.post("/api/runner/claim")
    def claim(runner: str = "runner", authorization: str = Header(default="")) -> Response:
        project_id = require_project(authorization)
        job = store.claim_job(project_id, runner)
        if job is None:
            return Response(status_code=204)  # nothing queued
        return JSONResponse({"id": job.id, "spec": job.spec().model_dump()})

    @app.post("/api/runner/jobs/{job_id}/result")
    def submit_result(job_id: str, result: JobResult, authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        if store.get_job(project_id, job_id) is None:
            raise HTTPException(status_code=404, detail="job not found")
        if result.status == "error":
            store.fail_job(project_id, job_id, result.error or "runner reported an error")
            return {"status": "error"}
        findings = [Finding.model_validate(item) for item in result.findings]
        if not store.complete_job(project_id, job_id, findings):
            raise HTTPException(status_code=409, detail="job is not in a running state")
        return {"status": "done", "num_findings": len(findings)}

    return app
