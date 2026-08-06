"""FastAPI application for the local dashboard.

Server-rendered Jinja2 (autoescaped — captured payloads render inert), a SQLite
`Store` for history, and an in-process `ScanManager` for live runs. Live progress
is polled by a few lines of vanilla JS hitting the ``/panel`` fragment; no external
JS/CSS assets, so the whole UI is self-contained like the rest of dastcore.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

from dastcore.report import render_html, render_json, render_sarif
from dastcore.report.correlation import IssueGroup, correlate
from dastcore.web.jobs import ScanManager, ScanRequest
from dastcore.web.store import ScanRow, Store

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _build_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    env.filters["datetime"] = lambda ts: _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    return env


def create_app(db_path: str | Path = "dastcore.db") -> FastAPI:
    """Build the dashboard app backed by a SQLite store at ``db_path``."""
    store = Store(db_path)
    store.mark_interrupted_running()  # a scan can't survive a restart
    manager = ScanManager(store)
    env = _build_env()

    app = FastAPI(title="dastcore", docs_url=None, redoc_url=None)
    app.state.store = store
    app.state.manager = manager

    def render(name: str, **ctx: object) -> HTMLResponse:
        return HTMLResponse(env.get_template(name).render(**ctx))

    def panel_context(scan: ScanRow) -> tuple[dict[str, object], bool]:
        """Context for the result panel + whether the scan is finished (done polling)."""
        live = manager.live(scan.id)
        running = live is not None and live.status == "running"
        if running:
            assert live is not None
            return (
                {"scan": scan, "running": True, "phase": live.phase, "completed": live.completed, "total": live.total},
                False,
            )
        issues: list[IssueGroup] = correlate(store.get_findings(scan.id)) if scan.status == "done" else []
        ctx: dict[str, object] = {"scan": scan, "running": False, "issues": issues}
        if scan.kind == "retest":
            ctx["retest"] = store.get_retest(scan.id)
        return ctx, True

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> HTMLResponse:
        return render("dashboard.html.j2", scans=store.list_scans())

    @app.post("/scans")
    async def start_scan(
        target: str = Form(...),
        engine: str = Form("http"),
        profile: str = Form(""),
        rps: float = Form(5.0),
        auth_bearer: str = Form(""),
        auth_cookie: str = Form(""),
        authorization: str = Form(""),
    ) -> Response:
        target = target.strip()
        if authorization != "on":
            return HTMLResponse(
                env.get_template("dashboard.html.j2").render(
                    scans=store.list_scans(),
                    target=target,
                    error="Debes confirmar que tienes autorización para escanear el objetivo.",
                ),
                status_code=400,
            )
        if engine not in ("http", "headless", "both"):
            engine = "http"
        try:
            scan_id = manager.start(
                ScanRequest(
                    target=target,
                    engine=engine,
                    profile=profile if profile in ("quick", "full", "api") else "",
                    rps=rps if rps > 0 else 5.0,
                    auth_bearer=auth_bearer.strip(),
                    auth_cookie=auth_cookie.strip(),
                )
            )
        except Exception as exc:  # noqa: BLE001 — bad target/config -> re-render the form with the reason
            return HTMLResponse(
                env.get_template("dashboard.html.j2").render(
                    scans=store.list_scans(), target=target, error=f"No se pudo iniciar: {exc}"
                ),
                status_code=400,
            )
        return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)

    @app.post("/scans/{scan_id}/retest")
    async def start_retest(
        scan_id: str,
        authorization: str = Form(""),
        auth_bearer: str = Form(""),
        auth_cookie: str = Form(""),
        rps: float = Form(5.0),
    ) -> Response:
        scan = store.get_scan(scan_id)
        if scan is None:
            return HTMLResponse("<h1>404</h1><p>Escaneo no encontrado.</p>", status_code=404)
        if authorization != "on":
            return HTMLResponse(
                f"<p>Debes confirmar la autorización para reverificar. "
                f'<a href="/scans/{scan_id}">Volver</a></p>',
                status_code=400,
            )
        new_id = manager.start_retest(
            scan_id, auth_bearer=auth_bearer.strip(), auth_cookie=auth_cookie.strip(), rps=rps
        )
        if new_id is None:
            return HTMLResponse(
                f"<p>Nada que reverificar (sin hallazgos o sin objetivo válido). "
                f'<a href="/scans/{scan_id}">Volver</a></p>',
                status_code=400,
            )
        return RedirectResponse(url=f"/scans/{new_id}", status_code=303)

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    def scan_detail(scan_id: str) -> Response:
        scan = store.get_scan(scan_id)
        if scan is None:
            return HTMLResponse("<h1>404</h1><p>Escaneo no encontrado.</p>", status_code=404)
        ctx, done = panel_context(scan)
        return render("scan_detail.html.j2", done=done, **ctx)

    @app.get("/scans/{scan_id}/panel", response_class=HTMLResponse)
    def scan_panel(scan_id: str) -> Response:
        scan = store.get_scan(scan_id)
        if scan is None:
            return HTMLResponse("Escaneo no encontrado.", status_code=404)
        ctx, done = panel_context(scan)
        html = env.get_template("_panel.html.j2").render(**ctx)
        return HTMLResponse(html, headers={"X-Scan-Done": "1" if done else "0"})

    @app.get("/scans/{scan_id}/report", response_class=HTMLResponse)
    def scan_report(scan_id: str) -> Response:
        scan = store.get_scan(scan_id)
        if scan is None:
            return HTMLResponse("Escaneo no encontrado.", status_code=404)
        html = render_html(store.get_findings(scan_id), target=scan.target, title=f"dastcore — {scan.target}")
        return HTMLResponse(html)

    @app.get("/scans/{scan_id}/findings.json")
    def scan_json(scan_id: str) -> Response:
        raw = store.get_findings_json(scan_id)
        if raw is None:
            return PlainTextResponse("Escaneo no encontrado.", status_code=404)
        return Response(render_json(store.get_findings(scan_id)), media_type="application/json")

    @app.get("/scans/{scan_id}/findings.sarif")
    def scan_sarif(scan_id: str) -> Response:
        scan = store.get_scan(scan_id)
        if scan is None:
            return PlainTextResponse("Escaneo no encontrado.", status_code=404)
        return Response(render_sarif(store.get_findings(scan_id)), media_type="application/json")

    return app
