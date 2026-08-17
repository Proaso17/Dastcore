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

from fastapi import BackgroundTasks, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

from dastcore.cloud.models import (
    JobResult,
    JobSpec,
    NotificationConfig,
    ProjectCreate,
    RunnerCreate,
    ScheduleCreate,
)
from dastcore.cloud.notify import filter_by_severity, send_alert
from dastcore.cloud.scheduler import Scheduler
from dastcore.cloud.store import JobRow, RunnerRow, ScheduleRow, Store
from dastcore.core.models import Finding
from dastcore.httpsec import add_csrf_protection, add_error_pages, add_security_headers, is_https

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
        "mode": job.mode,
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


def _sparkline_points(values: list[int], width: int = 130, height: int = 30, pad: int = 3) -> str:
    """An SVG polyline `points` string plotting ``values`` (findings-per-scan) over time."""
    if not values:
        return ""
    low, high = min(values), max(values)
    span = (high - low) or 1
    step = (width - 2 * pad) / (len(values) - 1) if len(values) > 1 else 0.0
    coords = []
    for i, value in enumerate(values):
        x = pad + i * step
        y = height - pad - (value - low) / span * (height - 2 * pad)
        coords.append(f"{x:.1f},{y:.1f}")
    return " ".join(coords)


def _build_trends(points: list[dict]) -> list[dict]:
    """Group completed scans by target into a trend row: scan count, latest/previous finding
    counts and their delta, the latest severity breakdown, and a sparkline of counts over time."""
    by_target: dict[str, list[dict]] = {}
    for point in points:
        by_target.setdefault(point["target"], []).append(point)
    trends = []
    for target, series in by_target.items():
        counts = [p["num_findings"] for p in series]
        latest, previous = counts[-1], (counts[-2] if len(counts) > 1 else None)
        trends.append(
            {
                "target": target,
                "scans": len(series),
                "latest": latest,
                "previous": previous,
                "delta": (latest - previous) if previous is not None else None,
                "severity_counts": series[-1]["severity_counts"],
                "sparkline": _sparkline_points(counts),
            }
        )
    trends.sort(key=lambda t: (t["latest"], t["scans"]), reverse=True)
    return trends


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
    add_security_headers(app)
    add_csrf_protection(app)
    add_error_pages(app)
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
        # An email/password session cookie takes precedence; the raw-API-key cookie is the fallback
        # (backward compatible with API-key login and the `--project-key` flow).
        session = store.project_for_session(request.cookies.get("dast_session", ""))
        if session is not None:
            return session
        key = request.cookies.get("dast_key", "")
        return store.project_for_key(key) if key else None

    _rate_hits: dict[tuple[str, str], list[float]] = {}

    def _rate_limited(bucket: str, request: Request, *, limit: int, window: float = 600.0) -> bool:
        """Per-IP, per-bucket throttle: open signup can't be spammed and login can't be brute-forced."""
        ip = request.client.host if request.client else "?"
        key = (bucket, ip)
        now = time.time()
        hits = [t for t in _rate_hits.get(key, []) if now - t < window]
        hits.append(now)
        _rate_hits[key] = hits
        return len(hits) > limit

    def _set_session(response: Response, request: Request, project_id: str) -> None:
        token = store.create_session(project_id)
        response.set_cookie("dast_session", token, httponly=True, samesite="strict", secure=is_https(request))

    def _render_dashboard(
        request: Request, project_id: str, *, new_runner_token: str = "", new_api_key: str = ""
    ) -> Response:
        return render(
            "dashboard.html.j2",
            project=store.get_project(project_id),
            jobs=[_job_summary(j) for j in store.list_jobs(project_id)],
            runners=[_runner_summary(r) for r in store.list_runners(project_id)],
            schedules=[_schedule_summary(s) for s in store.list_schedules(project_id)],
            trends=_build_trends(store.trend_points(project_id)),
            intervals=_INTERVALS,
            notification=store.get_notification(project_id),
            new_runner_token=new_runner_token,
            new_api_key=new_api_key,
        )

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

    @app.get("/api/trends")
    def get_trends(authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        trends = _build_trends(store.trend_points(project_id))
        return {
            "trends": [
                {k: t[k] for k in ("target", "scans", "latest", "previous", "delta", "severity_counts")} for t in trends
            ]
        }

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

    async def _maybe_alert(project_id: str, job_id: str) -> None:
        """Fire the project's webhook after a job completes (best-effort).

        ``regression`` fires only when new findings appeared vs the previous scan; ``any`` fires
        on every completed job with a summary of its findings at/above ``min_severity``."""
        notification = store.get_notification(project_id)
        if notification is None or not notification.enabled:
            return
        if notification.notify_on == "any":
            findings = filter_by_severity(store.get_findings(project_id, job_id), notification.min_severity)
            event = "completed"  # a completion heartbeat fires even with nothing above the floor
        else:
            findings = filter_by_severity(store.new_findings_since_last(project_id, job_id), notification.min_severity)
            if not findings:
                return  # no regression → stay quiet
            event = "regression"
        job = store.get_job(project_id, job_id)
        project = store.get_project(project_id)
        if job is None or project is None:
            return
        await send_alert(notification, project_id, project.name, job, findings, event=event)

    @app.post("/api/runner/jobs/{job_id}/result")
    def submit_result(
        job_id: str, result: JobResult, background: BackgroundTasks, authorization: str = Header(default="")
    ) -> dict:
        runner = require_runner(authorization)
        if store.get_job(runner.project_id, job_id) is None:
            raise HTTPException(status_code=404, detail="job not found")
        if result.status == "error":
            store.fail_job(runner.project_id, job_id, result.error or "runner reported an error")
            return {"status": "error"}
        findings = [Finding.model_validate(item) for item in result.findings]
        if not store.complete_job(runner.project_id, job_id, findings):
            raise HTTPException(status_code=409, detail="job is not in a running state")
        # Regression alerting runs after the response so a slow webhook never delays the runner.
        background.add_task(_maybe_alert, runner.project_id, job_id)
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

    # --- API: regression-alert notifications (project-scoped) -------------------------

    @app.put("/api/notifications")
    def set_notification(body: NotificationConfig, authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        store.set_notification(
            project_id, body.webhook_url, body.format, body.notify_on, body.min_severity, body.enabled
        )
        return {"status": "ok"}

    @app.get("/api/notifications")
    def get_notification(authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        notification = store.get_notification(project_id)
        if notification is None:
            return {"notification": None}
        return {
            "notification": {
                "webhook_url": notification.webhook_url,
                "format": notification.format,
                "notify_on": notification.notify_on,
                "min_severity": notification.min_severity,
                "enabled": notification.enabled,
            }
        }

    @app.delete("/api/notifications")
    def delete_notification(authorization: str = Header(default="")) -> dict:
        project_id = require_project(authorization)
        store.delete_notification(project_id)
        return {"status": "deleted"}

    # --- UI (project API key in an httpOnly cookie) -----------------------------------

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request) -> Response:
        if ui_project(request) is not None:
            return RedirectResponse("/ui", status_code=303)
        return render("login.html.j2", error="")

    @app.post("/ui/login")
    def ui_login(request: Request, api_key: str = Form(...)) -> Response:
        if _rate_limited("login", request, limit=10):
            return HTMLResponse(
                env.get_template("login.html.j2").render(error="Demasiados intentos. Espera unos minutos."),
                status_code=429,
            )
        if store.project_for_key(api_key.strip()) is None:
            return HTMLResponse(env.get_template("login.html.j2").render(error="API key inválida."), status_code=400)
        resp = RedirectResponse("/ui", status_code=303)
        # Secure only over HTTPS so the session cookie can't leak over plain HTTP once
        # deployed behind TLS — while still working on localhost HTTP for dev.
        resp.set_cookie("dast_key", api_key.strip(), httponly=True, samesite="strict", secure=is_https(request))
        return resp

    @app.get("/signup", response_class=HTMLResponse)
    def signup_page(request: Request) -> Response:
        if ui_project(request) is not None:
            return RedirectResponse("/ui", status_code=303)
        return render("signup.html.j2", error="")

    @app.post("/signup")
    def signup(
        request: Request,
        email: str = Form(...),
        password: str = Form(...),
        project_name: str = Form(""),
    ) -> Response:
        def fail(message: str, code: int = 400) -> Response:
            return HTMLResponse(env.get_template("signup.html.j2").render(error=message), status_code=code)

        if _rate_limited("signup", request, limit=5):
            return fail("Demasiados intentos. Espera unos minutos e inténtalo de nuevo.", code=429)
        clean = email.strip().lower()
        if "@" not in clean or "." not in clean.split("@")[-1]:
            return fail("Introduce un email válido.")
        if len(password) < 8:
            return fail("La contraseña debe tener al menos 8 caracteres.")
        if store.email_exists(clean):
            return fail("Ese email ya tiene una cuenta. Inicia sesión.")
        _, api_key = store.create_account(clean, password, project_name)
        resp = render("welcome.html.j2", api_key=api_key, email=clean)
        _set_session(resp, request, store.project_for_key(api_key))  # type: ignore[arg-type]
        return resp

    @app.post("/login")
    def account_login(request: Request, email: str = Form(...), password: str = Form(...)) -> Response:
        if _rate_limited("login", request, limit=10):
            return HTMLResponse(
                env.get_template("login.html.j2").render(error="Demasiados intentos. Espera unos minutos."),
                status_code=429,
            )
        project_id = store.account_project(email, password)
        if project_id is None:
            return HTMLResponse(
                env.get_template("login.html.j2").render(error="Email o contraseña incorrectos."), status_code=400
            )
        resp = RedirectResponse("/ui", status_code=303)
        _set_session(resp, request, project_id)
        return resp

    @app.post("/ui/logout")
    def ui_logout(request: Request) -> Response:
        store.delete_session(request.cookies.get("dast_session", ""))
        resp = RedirectResponse("/", status_code=303)
        resp.delete_cookie("dast_session")
        resp.delete_cookie("dast_key")
        return resp

    @app.post("/ui/regenerate-key")
    def ui_regenerate_key(request: Request) -> Response:
        project_id = ui_project(request)
        if project_id is None:
            return RedirectResponse("/", status_code=303)
        api_key = store.regenerate_api_key(project_id)
        return _render_dashboard(request, project_id, new_api_key=api_key)

    @app.get("/ui", response_class=HTMLResponse)
    def ui_dashboard(request: Request, new_runner_token: str = "") -> Response:
        project_id = ui_project(request)
        if project_id is None:
            return RedirectResponse("/", status_code=303)
        return _render_dashboard(request, project_id, new_runner_token=new_runner_token)

    @app.post("/ui/jobs")
    def ui_enqueue(
        request: Request,
        target: str = Form(...),
        mode: str = Form("scan"),
        engine: str = Form("http"),
        profile: str = Form(""),
        auth_bearer: str = Form(""),
        victim_bearer: str = Form(""),
        victim_ref: str = Form(""),
    ) -> Response:
        project_id = ui_project(request)
        if project_id is None:
            return RedirectResponse("/", status_code=303)
        if mode == "ai":
            spec = JobSpec(
                target=target.strip(),
                mode="ai",
                auth_bearer=auth_bearer.strip(),
                victim_bearer=victim_bearer.strip(),
                victim_refs=[r.strip() for r in victim_ref.splitlines() if r.strip()],
            )
        else:
            spec = JobSpec(
                target=target.strip(),
                engine=engine if engine in ("http", "headless", "both") else "http",
                profile=profile if profile in ("quick", "full", "api") else "",
                auth_bearer=auth_bearer.strip(),
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

    @app.post("/ui/notifications")
    def ui_set_notification(
        request: Request,
        webhook_url: str = Form(""),
        format: str = Form("slack"),
        notify_on: str = Form("regression"),
        min_severity: str = Form("high"),
    ) -> Response:
        project_id = ui_project(request)
        if project_id is None:
            return RedirectResponse("/", status_code=303)
        if webhook_url.strip():
            store.set_notification(project_id, webhook_url.strip(), format, notify_on, min_severity, True)
        else:
            store.delete_notification(project_id)  # empty URL clears the alert
        return RedirectResponse("/ui", status_code=303)

    return app
