"""Control-plane API + a minimal server-rendered UI.

Three auth scopes, all via ``Authorization: Bearer <token>`` on the API:
- the **admin token** (set at startup) creates projects;
- a **project API key** enqueues/reads jobs and manages runners and schedules;
- a **runner token** (minted per runner) can only claim jobs, post results and
  heartbeat — never enqueue or manage the project.

The UI authenticates with the project API key held in an httpOnly cookie.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

from dastcore.cloud.models import JobResult, JobSpec, ProjectCreate, RunnerCreate, ScheduleCreate
from dastcore.cloud.scheduler import Scheduler
from dastcore.cloud.store import JobRow, RunnerRow, ScheduleRow, Store
from dastcore.core.models import Finding

_TEMPLATES_DIR = Path(__file__).parent / "templates"
# Recurring-job interval presets for the UI (minutes).
_INTERVALS = [(60, "cada hora"), (360, "cada 6 h"), (720, "cada 12 h"), (1440, "diario"), (10080, "semanal")]


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


def _runner_summary(runner: RunnerRow) -> dict:
    return {"id": runner.id, "name": runner.name, "created_at": runner.created_at, "last_seen_at": runner.last_seen_at}


def _schedule_summary(sched: ScheduleRow) -> dict:
    return {
        "id": sched.id,
        "target": sched.target,
        "engine": sched.engine,
        "interval_minutes": sched.interval_minutes,
        "enabled": sched.enabled,
        "last_run_at": sched.last_run_at,
        "next_run_at": sched.next_run_at,
    }


def _build_env() -> Environment:
    env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=select_autoescape(["html", "j2"]))
    env.filters["datetime"] = lambda ts: _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "—"
    return env


def create_app(db_path: str | Path = "dastcore-cloud.db", *, admin_token: str) -> FastAPI:
    """Build the control-plane app. ``admin_token`` guards project creation."""
    store = Store(db_path)
    scheduler = Scheduler(store)
    env = _build_env()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        task = asyncio.create_task(scheduler.run_forever())
        try:
            yield
        finally:
            task.cancel()

    app = FastAPI(title="dastcore control-plane", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.store = store
    app.state.scheduler = scheduler
    app.state.admin_token = admin_token

    def render(name: str, **ctx: object) -> HTMLResponse:
        return HTMLResponse(env.get_template(name).render(**ctx))

    # --- auth -------------------------------------------------------------------------

    def require_admin(authorization: str) -> None:
        if not secrets.compare_digest(_bearer(authorization), admin_token):
            raise HTTPException(status_code=403, detail="admin token required")

    def require_project(authorization: str) -> str:
        project_id = store.project_for_key(_bearer(authorization))
        if project_id is None:
            raise HTTPException(status_code=401, detail="invalid project API key")
        return project_id

    def require_runner(authorization: str) -> RunnerRow:
        runner = store.runner_for_token(_bearer(authorization))
        if runner is None:
            raise HTTPException(status_code=401, detail="invalid runner token")
        store.touch_runner(runner.id)
        return runner

    def ui_project(request: Request) -> str | None:
        key = request.cookies.get("dast_key", "")
        return store.project_for_key(key) if key else None

    # --- API: health & admin ----------------------------------------------------------

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/api/projects", status_code=201)
    def create_project(body: ProjectCreate, authorization: str = Header(default="")) -> dict:
        require_admin(authorization)
        project_id, api_key = store.create_project(body.name)
        return {"id": project_id, "name": body.name, "api_key": api_key}

    # --- API: jobs (project-scoped) ---------------------------------------------------

    @app.post("/api/jobs", status_code=201)
    def enqueue(spec: JobSpec, authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        return {"id": store.enqueue_job(project_id, spec), "status": "queued"}

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

    # --- API: runners (project mints tokens; runners use them) ------------------------

    @app.post("/api/runners", status_code=201)
    def create_runner(body: RunnerCreate, authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        runner_id, token = store.create_runner(project_id, body.name)
        return {"id": runner_id, "name": body.name, "token": token}

    @app.get("/api/runners")
    def list_runners(authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        return {"runners": [_runner_summary(r) for r in store.list_runners(project_id)]}

    @app.post("/api/runner/claim")
    def claim(authorization: str = Header(default="")) -> Response:
        runner = require_runner(authorization)
        job = store.claim_job(runner.project_id, runner.name)
        if job is None:
            return Response(status_code=204)
        return JSONResponse({"id": job.id, "spec": job.spec().model_dump()})

    @app.post("/api/runner/jobs/{job_id}/result")
    def submit_result(job_id: str, result: JobResult, authorization: str = Header(default="")) -> dict:
        runner = require_runner(authorization)
        if store.get_job(runner.project_id, job_id) is None:
            raise HTTPException(status_code=404, detail="job not found")
        if result.status == "error":
            store.fail_job(runner.project_id, job_id, result.error or "runner reported an error")
            return {"status": "error"}
        findings = [Finding.model_validate(item) for item in result.findings]
        if not store.complete_job(runner.project_id, job_id, findings):
            raise HTTPException(status_code=409, detail="job is not in a running state")
        return {"status": "done", "num_findings": len(findings)}

    @app.post("/api/runner/heartbeat")
    def heartbeat(authorization: str = Header(default="")) -> dict:
        runner = require_runner(authorization)
        return {"status": "ok", "runner": runner.name}

    # --- API: schedules (project-scoped) ----------------------------------------------

    @app.post("/api/schedules", status_code=201)
    def create_schedule(body: ScheduleCreate, authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        return {"id": store.create_schedule(project_id, body, time.time())}

    @app.get("/api/schedules")
    def list_schedules(authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        return {"schedules": [_schedule_summary(s) for s in store.list_schedules(project_id)]}

    @app.post("/api/schedules/{schedule_id}/toggle")
    def toggle_schedule(schedule_id: str, authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        sched = store.get_schedule(project_id, schedule_id)
        if sched is None:
            raise HTTPException(status_code=404, detail="schedule not found")
        store.set_schedule_enabled(project_id, schedule_id, not sched.enabled)
        return {"id": schedule_id, "enabled": not sched.enabled}

    @app.delete("/api/schedules/{schedule_id}")
    def delete_schedule(schedule_id: str, authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        store.delete_schedule(project_id, schedule_id)
        return {"status": "deleted"}

    # --- UI (project API key in an httpOnly cookie) -----------------------------------

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request) -> Response:
        if ui_project(request) is not None:
            return RedirectResponse("/ui", status_code=303)
        return render("login.html.j2", error="")

    @app.post("/ui/login")
    def ui_login(api_key: str = Form(...)) -> Response:
        if store.project_for_key(api_key.strip()) is None:
            return HTMLResponse(env.get_template("login.html.j2").render(error="API key inválida."), status_code=400)
        resp = RedirectResponse("/ui", status_code=303)
        resp.set_cookie("dast_key", api_key.strip(), httponly=True, samesite="lax")
        return resp

    @app.post("/ui/logout")
    def ui_logout() -> Response:
        resp = RedirectResponse("/", status_code=303)
        resp.delete_cookie("dast_key")
        return resp

    @app.get("/ui", response_class=HTMLResponse)
    def ui_dashboard(request: Request, new_runner_token: str = "") -> Response:
        project_id = ui_project(request)
        if project_id is None:
            return RedirectResponse("/", status_code=303)
        project = store.get_project(project_id)
        return render(
            "dashboard.html.j2",
            project=project,
            jobs=[_job_summary(j) for j in store.list_jobs(project_id)],
            runners=[_runner_summary(r) for r in store.list_runners(project_id)],
            schedules=[_schedule_summary(s) for s in store.list_schedules(project_id)],
            intervals=_INTERVALS,
            new_runner_token=new_runner_token,
        )

    @app.post("/ui/jobs")
    def ui_enqueue(
        request: Request, target: str = Form(...), engine: str = Form("http"), profile: str = Form("")
    ) -> Response:
        project_id = ui_project(request)
        if project_id is None:
            return RedirectResponse("/", status_code=303)
        spec = JobSpec(
            target=target.strip(),
            engine=engine if engine in ("http", "headless", "both") else "http",
            profile=profile if profile in ("quick", "full", "api") else "",
        )
        store.enqueue_job(project_id, spec)
        return RedirectResponse("/ui", status_code=303)

    @app.get("/ui/jobs/{job_id}", response_class=HTMLResponse)
    def ui_job(request: Request, job_id: str) -> Response:
        project_id = ui_project(request)
        if project_id is None:
            return RedirectResponse("/", status_code=303)
        job = store.get_job(project_id, job_id)
        if job is None:
            return HTMLResponse("<h1>404</h1>", status_code=404)
        findings = store.get_findings(project_id, job_id) if job.status == "done" else []
        return render("job.html.j2", job=_job_summary(job), findings=[f.model_dump(mode="json") for f in findings])

    @app.post("/ui/runners")
    def ui_create_runner(request: Request, name: str = Form("runner")) -> Response:
        project_id = ui_project(request)
        if project_id is None:
            return RedirectResponse("/", status_code=303)
        _, token = store.create_runner(project_id, name.strip() or "runner")
        # Show the token once via a query param (localhost UI).
        return RedirectResponse(f"/ui?new_runner_token={token}", status_code=303)

    @app.post("/ui/schedules")
    def ui_create_schedule(
        request: Request,
        target: str = Form(...),
        engine: str = Form("http"),
        profile: str = Form(""),
        interval_minutes: int = Form(1440),
    ) -> Response:
        project_id = ui_project(request)
        if project_id is None:
            return RedirectResponse("/", status_code=303)
        spec = ScheduleCreate(
            target=target.strip(),
            engine=engine if engine in ("http", "headless", "both") else "http",
            profile=profile if profile in ("quick", "full", "api") else "",
            interval_minutes=max(1, interval_minutes),
        )
        store.create_schedule(project_id, spec, time.time())
        return RedirectResponse("/ui", status_code=303)

    @app.post("/ui/schedules/{schedule_id}/toggle")
    def ui_toggle_schedule(request: Request, schedule_id: str) -> Response:
        project_id = ui_project(request)
        if project_id is None:
            return RedirectResponse("/", status_code=303)
        sched = store.get_schedule(project_id, schedule_id)
        if sched is not None:
            store.set_schedule_enabled(project_id, schedule_id, not sched.enabled)
        return RedirectResponse("/ui", status_code=303)

    @app.post("/ui/schedules/{schedule_id}/delete")
    def ui_delete_schedule(request: Request, schedule_id: str) -> Response:
        project_id = ui_project(request)
        if project_id is None:
            return RedirectResponse("/", status_code=303)
        store.delete_schedule(project_id, schedule_id)
        return RedirectResponse("/ui", status_code=303)

    return app
