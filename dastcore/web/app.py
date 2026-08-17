"""FastAPI application for the local dashboard.

Server-rendered Jinja2 (autoescaped — captured payloads render inert), a SQLite
`Store` for history, and an in-process `ScanManager` for live runs. Live progress
is polled by a few lines of vanilla JS hitting the ``/panel`` fragment; no external
JS/CSS assets, so the whole UI is self-contained like the rest of dastcore.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import ValidationError

from dastcore.analysis import correlate_chains
from dastcore.bugbounty import triage_for_bounty
from dastcore.bugbounty.program import Program, ProgramLimits, ProgramScope
from dastcore.bugbounty.report import PLATFORMS, render_bounty_report
from dastcore.core.models import Finding
from dastcore.httpsec import add_csrf_protection, add_error_pages, add_security_headers
from dastcore.obslog import add_request_logging
from dastcore.report import render_html, render_json, render_sarif
from dastcore.report.correlation import correlate
from dastcore.report.remediation import guide_for
from dastcore.severity import severity_rank
from dastcore.suppressions import apply_suppressions
from dastcore.web.diff import diff_findings, location_label
from dastcore.web.jobs import ScanManager, ScanRequest
from dastcore.web.scheduler import Scheduler
from dastcore.web.store import ScanRow, Store, severity_counts

# Recurring-scan interval presets shown in the UI (minutes).
_INTERVALS = [(60, "cada hora"), (360, "cada 6 h"), (720, "cada 12 h"), (1440, "diario"), (10080, "semanal")]

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _classify_scope(text: str) -> tuple[list[str], list[str], list[str]]:
    """Split free-text scope lines into (domains, wildcards, CIDRs) so a novice only types hosts."""
    domains: list[str] = []
    wildcards: list[str] = []
    cidrs: list[str] = []
    for raw in text.splitlines():
        item = raw.strip().lower()
        if not item:
            continue
        if item.startswith("*."):
            wildcards.append(item)
        elif (
            "/" in item
            and item.split("/")[0].replace(".", "").replace(":", "").isalnum()
            and any(c.isdigit() for c in item.split("/")[0])
        ):
            cidrs.append(item)
        else:
            domains.append(item)
    return domains, wildcards, cidrs


def _program_from_form(handle: str, platform: str, in_scope: str, out_of_scope: str, allow_active: bool) -> Program:
    """Build a Program from the friendly dashboard form (seeds derived from the in-scope hosts)."""
    domains, wildcards, cidrs = _classify_scope(in_scope)
    out_lines = [line.strip().lower() for line in out_of_scope.splitlines() if line.strip()]
    seeds = domains + [w[2:] for w in wildcards]  # start recon from the apex of each in-scope host
    return Program(
        handle=handle.strip() or "objetivo",
        platform=platform if platform in ("hackerone", "bugcrowd", "intigriti", "immunefi", "self") else "self",
        scope=ProgramScope(domains=domains, wildcards=wildcards, cidrs=cidrs, out_of_scope=out_lines),
        limits=ProgramLimits(no_automated_scanning=not allow_active),
        seeds=seeds,
    )


def _build_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    env.filters["datetime"] = lambda ts: _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    env.globals["remediation_guide"] = guide_for
    return env


def create_app(db_path: str | Path = "dastcore.db") -> FastAPI:
    """Build the dashboard app backed by a SQLite store at ``db_path``."""
    store = Store(db_path)
    store.mark_interrupted_running()  # a scan can't survive a restart
    manager = ScanManager(store)
    scheduler = Scheduler(store, manager)
    env = _build_env()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        # Under uvicorn this starts the recurring-scan loop; ASGITransport tests skip
        # lifespan and drive scheduler.tick() directly instead.
        task = asyncio.create_task(scheduler.run_forever())
        try:
            yield
        finally:
            task.cancel()

    app = FastAPI(title="dastcore", docs_url=None, redoc_url=None, lifespan=lifespan)
    add_security_headers(app)
    add_csrf_protection(app)
    add_error_pages(app)
    add_request_logging(app)
    app.state.store = store
    app.state.manager = manager
    app.state.scheduler = scheduler

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
        ctx: dict[str, object] = {"scan": scan, "running": False, "issues": [], "accepted": []}
        if scan.status == "done":
            findings = store.get_findings(scan.id)
            if scan.kind == "retest":
                ctx["retest"] = store.get_retest(scan.id)
                ctx["issues"] = correlate(findings)  # still-open set; triage doesn't apply here
            else:
                # Triage: accepted / false-positive findings drop out of the issues table
                # into a separate "aceptados" section (they still live in the stored JSON).
                apply_suppressions(findings, store.build_suppressions())
                ctx["issues"] = correlate([f for f in findings if not f.suppressed])
                ctx["accepted"] = correlate([f for f in findings if f.suppressed])
                ctx["chains"] = correlate_chains(findings)  # exploit paths across the active findings
        return ctx, True

    def _with_triage(scan: ScanRow, suppressions: list) -> ScanRow:
        """Recompute a row's finding counts with current triage applied (display only).

        Fast path: with no suppressions the stored counts already stand, so we skip
        loading findings. Retests and unfinished runs are shown as stored.
        """
        if not suppressions or scan.status != "done" or scan.kind == "retest":
            return scan
        findings = store.get_findings(scan.id)
        apply_suppressions(findings, suppressions)
        active = [f for f in findings if not f.suppressed]
        scan.num_findings = len(active)
        scan.severity_counts = severity_counts(active)
        scan.accepted = len(findings) - len(active)
        return scan

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> HTMLResponse:
        suppressions = store.build_suppressions()
        scans = [_with_triage(s, suppressions) for s in store.list_scans()]
        return render("dashboard.html.j2", scans=scans)

    @app.post("/scans")
    async def start_scan(
        target: str = Form(...),
        mode: str = Form("scan"),
        engine: str = Form("http"),
        profile: str = Form(""),
        rps: float = Form(5.0),
        auth_bearer: str = Form(""),
        auth_cookie: str = Form(""),
        victim_bearer: str = Form(""),
        victim_ref: str = Form(""),
        prove_impact: str = Form(""),
        discover: str = Form(""),
        discover_depth: str = Form("aggressive"),
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
            if mode == "ai":
                # One victim reference per line for the cross-tenant checks.
                refs = [r.strip() for r in victim_ref.splitlines() if r.strip()]
                scan_id = manager.start_ai(
                    ScanRequest(
                        target=target,
                        rps=rps if rps > 0 else 5.0,
                        auth_bearer=auth_bearer.strip(),
                        victim_bearer=victim_bearer.strip(),
                        victim_refs=refs,
                    )
                )
            else:
                scan_id = manager.start(
                    ScanRequest(
                        target=target,
                        engine=engine,
                        profile=profile if profile in ("quick", "full", "api") else "",
                        rps=rps if rps > 0 else 5.0,
                        auth_bearer=auth_bearer.strip(),
                        auth_cookie=auth_cookie.strip(),
                        prove_impact=prove_impact == "on",
                        discover_subdomains=discover == "on",
                        discover_content=discover == "on",
                        discover_depth=(
                            discover_depth if discover_depth in ("light", "balanced", "aggressive") else "aggressive"
                        ),
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
                f'<p>Debes confirmar la autorización para reverificar. <a href="/scans/{scan_id}">Volver</a></p>',
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
        # Other finished plain scans of the same target — candidates to diff against.
        others = [
            s
            for s in store.list_scans()
            if s.id != scan.id and s.kind == "scan" and s.status == "done" and s.target == scan.target
        ]
        return render("scan_detail.html.j2", done=done, others=others, **ctx)

    @app.get("/scans/{scan_id}/panel", response_class=HTMLResponse)
    def scan_panel(scan_id: str) -> Response:
        scan = store.get_scan(scan_id)
        if scan is None:
            return HTMLResponse("Escaneo no encontrado.", status_code=404)
        ctx, done = panel_context(scan)
        html = env.get_template("_panel.html.j2").render(**ctx)
        return HTMLResponse(html, headers={"X-Scan-Done": "1" if done else "0"})

    @app.post("/suppress")
    def suppress(
        rule_id: str = Form(""),
        finding_id: str = Form(""),
        url: str = Form(""),
        reason: str = Form(""),
        expires: str = Form(""),
        scan_id: str = Form(""),
    ) -> Response:
        if not (rule_id.strip() or finding_id.strip() or url.strip()):
            dest = f"/scans/{scan_id}" if scan_id else "/suppressions"
            return RedirectResponse(dest, status_code=303)
        store.add_suppression(
            rule_id=rule_id.strip(),
            finding_id=finding_id.strip(),
            url=url.strip(),
            reason=reason.strip(),
            expires=expires.strip(),
        )
        dest = f"/scans/{scan_id}" if scan_id.strip() else "/suppressions"
        return RedirectResponse(dest, status_code=303)

    @app.post("/suppress/{row_id}/delete")
    def suppress_delete(row_id: int) -> Response:
        store.delete_suppression(row_id)
        return RedirectResponse("/suppressions", status_code=303)

    @app.get("/suppressions", response_class=HTMLResponse)
    def suppressions_page() -> HTMLResponse:
        return render("suppressions.html.j2", suppressions=store.list_suppressions())

    @app.get("/dastcore-ignore")
    def dastcore_ignore() -> Response:
        import yaml

        items = []
        for supp in store.build_suppressions():
            entry: dict[str, object] = {}
            if supp.id:
                entry["id"] = supp.id
            if supp.rule_id:
                entry["rule_id"] = supp.rule_id
            if supp.url:
                entry["url"] = supp.url
            if supp.reason:
                entry["reason"] = supp.reason
            if supp.expires:
                entry["expires"] = supp.expires.isoformat()
            items.append(entry)
        body = yaml.safe_dump({"suppressions": items}, allow_unicode=True, sort_keys=False)
        return Response(
            body,
            media_type="application/yaml",
            headers={"Content-Disposition": 'attachment; filename=".dastcore-ignore"'},
        )

    def active_findings(scan_id: str) -> list[Finding]:
        """A scan's findings with current triage applied, keeping only the active ones."""
        findings = store.get_findings(scan_id)
        apply_suppressions(findings, store.build_suppressions())
        return [f for f in findings if not f.suppressed]

    def _diff_rows(findings: list[Finding]) -> list[dict[str, str]]:
        return [
            {"severity": f.severity, "name": f.name, "location": location_label(f)}
            for f in sorted(findings, key=lambda x: severity_rank(x.severity), reverse=True)
        ]

    @app.get("/diff", response_class=HTMLResponse)
    def diff_page(base: str, head: str) -> Response:
        base_scan, head_scan = store.get_scan(base), store.get_scan(head)
        if base_scan is None or head_scan is None:
            return HTMLResponse("<h1>404</h1><p>Escaneo no encontrado.</p>", status_code=404)
        result = diff_findings(active_findings(base), active_findings(head))
        return render(
            "diff.html.j2",
            base=base_scan,
            head=head_scan,
            counts=result.counts,
            new=_diff_rows(result.new),
            fixed=_diff_rows(result.fixed),
            persistent=_diff_rows(result.persistent),
        )

    @app.get("/schedules", response_class=HTMLResponse)
    def schedules_page(error: str = "") -> HTMLResponse:
        return render("schedules.html.j2", schedules=store.list_schedules(), intervals=_INTERVALS, error=error)

    @app.post("/schedules")
    def add_schedule(
        target: str = Form(...),
        engine: str = Form("http"),
        profile: str = Form(""),
        rps: float = Form(5.0),
        interval_minutes: int = Form(1440),
        auth_bearer: str = Form(""),
        auth_cookie: str = Form(""),
        authorization: str = Form(""),
    ) -> Response:
        target = target.strip()
        if authorization != "on":
            return render(
                "schedules.html.j2",
                schedules=store.list_schedules(),
                intervals=_INTERVALS,
                error="Debes confirmar la autorización: los escaneos programados también son intrusivos.",
            )
        req = ScanRequest(
            target=target,
            engine=engine if engine in ("http", "headless", "both") else "http",
            profile=profile if profile in ("quick", "full", "api") else "",
            rps=rps if rps > 0 else 5.0,
            auth_bearer=auth_bearer.strip(),
            auth_cookie=auth_cookie.strip(),
        )
        try:
            manager.validate(req)
        except ValidationError:
            return render(
                "schedules.html.j2",
                schedules=store.list_schedules(),
                intervals=_INTERVALS,
                error=f"Objetivo inválido: {target!r}",
            )
        store.add_schedule(
            target=req.target,
            engine=req.engine,
            profile=req.profile or None,
            rps=req.rps,
            auth_bearer=req.auth_bearer,
            auth_cookie=req.auth_cookie,
            interval_minutes=max(1, interval_minutes),
            now=time.time(),
        )
        return RedirectResponse("/schedules", status_code=303)

    @app.post("/schedules/{schedule_id}/toggle")
    def toggle_schedule(schedule_id: int) -> Response:
        sched = store.get_schedule(schedule_id)
        if sched is not None:
            store.set_schedule_enabled(schedule_id, not sched.enabled)
        return RedirectResponse("/schedules", status_code=303)

    @app.post("/schedules/{schedule_id}/delete")
    def delete_schedule(schedule_id: int) -> Response:
        store.delete_schedule(schedule_id)
        return RedirectResponse("/schedules", status_code=303)

    @app.post("/schedules/{schedule_id}/run")
    async def run_schedule_now(schedule_id: int) -> Response:
        sched = store.get_schedule(schedule_id)
        if sched is not None:
            manager.start(
                ScanRequest(
                    target=sched.target,
                    engine=sched.engine,
                    profile=sched.profile or "",
                    rps=sched.rps,
                    auth_bearer=sched.auth_bearer or "",
                    auth_cookie=sched.auth_cookie or "",
                )
            )
            store.mark_ran(schedule_id, time.time(), sched.next_run_at)
        return RedirectResponse("/", status_code=303)

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

    @app.get("/scans/{scan_id}/bounty", response_class=HTMLResponse)
    def bounty_report(scan_id: str, finding: str = "", platform: str = "generic") -> Response:
        """A ready-to-paste bug-bounty submission draft for a chosen finding (human-in-the-loop)."""
        scan = store.get_scan(scan_id)
        if scan is None:
            return HTMLResponse("<h1>404</h1><p>Análisis no encontrado.</p>", status_code=404)
        findings = store.get_findings(scan_id)
        apply_suppressions(findings, store.build_suppressions())
        bounties = triage_for_bounty([f for f in findings if not f.suppressed])
        platform = platform if platform in PLATFORMS else "generic"
        selected = next((b for b in bounties if b.finding.id == finding), bounties[0] if bounties else None)
        draft = render_bounty_report(selected, None, platform) if selected is not None else ""
        return render(
            "bounty.html.j2",
            scan=scan, bounties=bounties, selected=selected, draft=draft, platform=platform, platforms=PLATFORMS,
        )

    # --- Bug bounty: programas + caza ---------------------------------------------------------

    @app.get("/programs", response_class=HTMLResponse)
    def programs_page(error: str = "") -> HTMLResponse:
        return render("programs.html.j2", programs=store.list_programs(), error=error)

    @app.post("/programs")
    def create_program(
        handle: str = Form(...),
        platform: str = Form("self"),
        in_scope: str = Form(""),
        out_of_scope: str = Form(""),
        allow_active: str = Form(""),
    ) -> Response:
        program = _program_from_form(handle, platform, in_scope, out_of_scope, allow_active == "on")
        if not program.scope.allow_patterns():
            return render(
                "programs.html.j2",
                programs=store.list_programs(),
                error="Indica al menos un dominio en alcance (uno por línea).",
                handle=handle,
            )
        store.add_program(program)
        return RedirectResponse("/programs", status_code=303)

    @app.post("/programs/{program_id}/delete")
    def delete_program(program_id: str) -> Response:
        store.delete_program(program_id)
        return RedirectResponse("/programs", status_code=303)

    @app.post("/programs/{program_id}/hunt")
    async def start_hunt(program_id: str, authorization: str = Form("")) -> Response:
        row = store.get_program(program_id)
        if row is None:
            return HTMLResponse("<h1>404</h1><p>Objetivo no encontrado.</p>", status_code=404)
        if authorization != "on":
            return render(
                "programs.html.j2",
                programs=store.list_programs(),
                error="Debes confirmar que tienes autorización para analizar este objetivo.",
            )
        scan_id = manager.start_hunt(row.program, "standard", db_path)
        return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)

    return app
