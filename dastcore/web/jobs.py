"""In-process scan job runner for the web dashboard.

Each launched scan runs as an asyncio task on the app's event loop (the engine is
already async and I/O-bound, so no threads/workers are needed for the MVP). Live
progress lives in memory while a scan runs; the final result is persisted to the
`Store`. The actual pipeline is the CLI's ``_run_scan`` reused verbatim, driven by
a progress sink that updates the in-memory job instead of a rich progress bar.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field

from dastcore.cli import (
    SessionLoginError,
    _Budget,
    _build_auth_config,
    _retest_scope_and_target,
    _run_ai_discover_scan,
    _run_retest,
    _run_scan,
)
from dastcore.config import OutputConfig, RateLimitConfig, ScanConfig, ScopeConfig
from dastcore.core.models import Finding
from dastcore.engine.rule_engine import load_rules
from dastcore.retest import classify, open_findings, summarize
from dastcore.web.store import Store


@dataclass
class ScanRequest:
    """A validated request to launch a scan from the dashboard form."""

    target: str
    engine: str = "http"
    profile: str = ""
    max_pages: int = 200
    rps: float = 5.0
    concurrency: int = 5
    auth_bearer: str = ""
    auth_cookie: str = ""  # "name=value"
    prove_impact: bool = False  # enrich confirmed findings with bounded, read-only proof of impact
    # Full-surface discovery: enumerate in-scope subdomains and/or brute-force hidden paths, then scan each.
    discover_subdomains: bool = False
    discover_content: bool = False
    discover_depth: str = "aggressive"
    content_wordlist: str = ""  # optional path to a custom paths list (e.g. SecLists); "" = built-in
    subdomain_wordlist: str = ""  # optional path to a custom subdomains list; "" = built-in
    seed_hosts: list[str] = field(default_factory=list)  # known hosts to always include in discovery
    seed_paths: list[str] = field(default_factory=list)  # known paths to always probe on each host
    mine_params: bool = False  # Arjun-style hidden parameter discovery on the discovered endpoints
    allow_domains: list[str] = field(default_factory=list)
    # Embedded-chatbot ("ai --discover") scans: a second identity for the cross-tenant checks.
    victim_bearer: str = ""
    victim_refs: list[str] = field(default_factory=list)


@dataclass
class LiveJob:
    """The in-memory, live state of a currently running scan."""

    id: str
    target: str
    phase: str = "En cola…"
    completed: int = 0
    total: int | None = None
    status: str = "running"  # running | done | error


# Profiles mirror the CLI's convenience defaults (engine + crawl breadth).
_PROFILE_DEFAULTS = {
    "quick": ("http", 40),
    "full": ("both", 200),
    "api": ("http", 80),
}


class _JobProgress:
    """Progress sink with the same surface the CLI's ``_ProgressAdapter`` exposes.

    ``_run_scan`` only ever calls ``status``/``start_scanning``/``tick`` on its
    progress object, so this drop-in updates the live job for the UI to poll.
    """

    def __init__(self, job: LiveJob) -> None:
        self._job = job

    def status(self, text: str) -> None:
        self._job.phase = text

    def start_scanning(self, total: int) -> None:
        self._job.phase = "Escaneando"
        self._job.total = total
        self._job.completed = 0

    def tick(self) -> None:
        self._job.completed += 1


class ScanManager:
    """Launches and tracks scan jobs; persists results to the `Store`."""

    def __init__(self, store: Store) -> None:
        self._store = store
        self._live: dict[str, LiveJob] = {}
        self._tasks: set[asyncio.Task] = set()

    def _build_config(self, req: ScanRequest) -> tuple[ScanConfig, str, int]:
        engine, max_pages = req.engine, req.max_pages
        if req.profile in _PROFILE_DEFAULTS:
            engine, max_pages = _PROFILE_DEFAULTS[req.profile]
        auth_cookie = [req.auth_cookie] if req.auth_cookie else []
        auth = _build_auth_config(
            auth_cookie=auth_cookie,
            auth_header=[],
            auth_bearer=req.auth_bearer,
            login_url="",
            login_field=[],
            oauth_token_url="",
            oauth_client_id="",
            oauth_client_secret="",
            oauth_scope="",
        )
        config = ScanConfig(
            target=req.target,  # type: ignore[arg-type]
            scope=ScopeConfig(allow_domains=list(req.allow_domains)),
            auth=auth,
            rate_limit=RateLimitConfig(requests_per_second=req.rps, max_concurrency=req.concurrency),
            output=OutputConfig(format="json"),
            i_have_authorization=True,
        )
        return config, engine, max_pages

    def validate(self, req: ScanRequest) -> None:
        """Raise (pydantic ValidationError) if the request can't form a valid scan config."""
        self._build_config(req)

    def start(self, req: ScanRequest) -> str:
        """Validate + persist a new run and launch it in the background. Returns its id."""
        config, engine, max_pages = self._build_config(req)
        scan_id = uuid.uuid4().hex[:12]
        job = LiveJob(id=scan_id, target=str(config.target))
        self._live[scan_id] = job
        self._store.insert_running(scan_id, str(config.target), engine, req.profile or None, time.time())

        not_quick = req.profile != "quick"  # discovery is intrusive; never in the quick profile
        task = asyncio.create_task(
            self._run(
                job, config, engine, max_pages, req.prove_impact,
                discover_subdomains=req.discover_subdomains and not_quick,
                discover_content=req.discover_content and not_quick,
                discover_depth=req.discover_depth,
                content_wordlist=req.content_wordlist,
                subdomain_wordlist=req.subdomain_wordlist,
                seed_hosts=req.seed_hosts,
                seed_paths=req.seed_paths,
                use_historical=req.discover_content and not_quick,  # historical is part of surface discovery
                use_js=req.discover_content and not_quick,  # JS endpoint extraction too
                mine_params=req.mine_params and not_quick,
            )
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return scan_id

    # --- bug-bounty hunt (recon -> scan) -----------------------------------------------

    def start_hunt(self, program, profile: str, db_path) -> str:
        """Launch a full hunt (recon + scan of the in-scope live surface) as a background job."""
        from pathlib import Path

        scan_id = uuid.uuid4().hex[:12]
        target = program.handle or (program.seeds[0] if program.seeds else "hunt")
        job = LiveJob(id=scan_id, target=target, phase="Preparando la caza…")
        self._live[scan_id] = job
        self._store.insert_running(scan_id, target, "hunt", profile or None, time.time(), kind="hunt")
        assets_db = str(Path(db_path).with_name("hunt-assets.db"))
        task = asyncio.create_task(self._run_hunt(job, program, profile, assets_db))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return scan_id

    async def _run_hunt(self, job: LiveJob, program, profile: str, assets_db: str) -> None:
        from dastcore.bugbounty.campaign import run_campaign
        from dastcore.recon import AssetStore, ReconOptions

        started = time.monotonic()
        store = AssetStore(assets_db)
        try:
            result = await run_campaign(
                program,
                authorized=True,  # a saved program is an explicit authorization artifact
                asset_store=store,
                recon_opts=ReconOptions(profile=profile if profile in ("passive", "standard", "deep") else "standard"),
                engine="http",
                on_status=lambda text: setattr(job, "phase", text),
            )
            duration = time.monotonic() - started
            self._store.mark_done(job.id, time.time(), duration, result.findings)
            job.status = "done"
            job.phase = f"Completado · {len(result.assets)} activos, {len(result.findings)} hallazgos"
        except Exception as exc:  # noqa: BLE001 — surface any error to the UI, don't crash the server
            self._fail(job, started, f"{type(exc).__name__}: {exc}")
        finally:
            store.close()

    async def _run(
        self,
        job: LiveJob,
        config: ScanConfig,
        engine: str,
        max_pages: int,
        prove_impact: bool = False,
        *,
        discover_subdomains: bool = False,
        discover_content: bool = False,
        discover_depth: str = "aggressive",
        content_wordlist: str = "",
        subdomain_wordlist: str = "",
        seed_hosts: list[str] | None = None,
        seed_paths: list[str] | None = None,
        use_historical: bool = False,
        use_js: bool = False,
        mine_params: bool = False,
    ) -> None:
        started = time.monotonic()
        try:
            findings = await _run_scan(
                config,
                max_pages,
                engine,
                budget=_Budget(None, None),
                progress=_JobProgress(job),
                prove_impact=prove_impact,
                discover_subdomains=discover_subdomains,
                discover_content=discover_content,
                discover_depth=discover_depth,
                content_wordlist=content_wordlist,
                subdomain_wordlist=subdomain_wordlist,
                seed_hosts=seed_hosts or [],
                seed_paths=seed_paths or [],
                use_historical=use_historical,
                use_js=use_js,
                mine_params=mine_params,
            )
            duration = time.monotonic() - started
            self._store.mark_done(job.id, time.time(), duration, findings)
            job.status = "done"
            job.phase = "Completado"
        except SessionLoginError as exc:
            self._fail(job, started, f"Error de autenticación: {exc}")
        except Exception as exc:  # noqa: BLE001 — surface any engine error to the UI, don't crash the server
            self._fail(job, started, f"{type(exc).__name__}: {exc}")

    # --- embedded chatbot (ai --discover) ----------------------------------------------

    def _ai_config(self, req: ScanRequest) -> ScanConfig:
        return ScanConfig(
            target=req.target,  # type: ignore[arg-type]
            scope=ScopeConfig(allow_domains=list(req.allow_domains)),
            rate_limit=RateLimitConfig(requests_per_second=req.rps if req.rps > 0 else 5.0),
            output=OutputConfig(format="json"),
            i_have_authorization=True,
        )

    def start_ai(self, req: ScanRequest) -> str:
        """Launch an embedded-chatbot scan (discover the bot, then run the LLM checks)."""
        config = self._ai_config(req)
        headers = {"Authorization": f"Bearer {req.auth_bearer}"} if req.auth_bearer else {}
        victim_headers = {"Authorization": f"Bearer {req.victim_bearer}"} if req.victim_bearer else None
        scan_id = uuid.uuid4().hex[:12]
        job = LiveJob(id=scan_id, target=str(config.target), phase="Descubriendo el chatbot…")
        self._live[scan_id] = job
        self._store.insert_running(scan_id, str(config.target), "chatbot", None, time.time(), kind="ai")

        task = asyncio.create_task(
            self._run_ai_job(job, config, headers, victim_headers, list(req.victim_refs), req.max_pages)
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return scan_id

    async def _run_ai_job(
        self,
        job: LiveJob,
        config: ScanConfig,
        headers: dict[str, str],
        victim_headers: dict[str, str] | None,
        victim_refs: list[str],
        max_pages: int,
    ) -> None:
        started = time.monotonic()
        try:
            profile, findings = await _run_ai_discover_scan(
                config, str(config.target), headers, "", max_pages, victim_headers, victim_refs
            )
            self._store.mark_done(job.id, time.time(), time.monotonic() - started, findings)
            job.status = "done"
            job.phase = "Completado" if profile is not None else "Completado — no se detectó ningún chatbot embebido"
        except SessionLoginError as exc:
            self._fail(job, started, f"Error de autenticación: {exc}")
        except Exception as exc:  # noqa: BLE001 — surface any engine error to the UI, don't crash the server
            self._fail(job, started, f"{type(exc).__name__}: {exc}")

    # --- retest ------------------------------------------------------------------------

    def start_retest(
        self, parent_id: str, *, auth_bearer: str = "", auth_cookie: str = "", rps: float = 5.0
    ) -> str | None:
        """Launch a retest of a finished scan's findings. Returns the new run id, or
        None if the parent has no findings / no usable target to re-scan."""
        prior = self._store.get_findings(parent_id)
        if not prior:
            return None
        scope, target = _retest_scope_and_target(prior, [], [])
        if not target:
            return None
        auth = _build_auth_config(
            auth_cookie=[auth_cookie] if auth_cookie else [],
            auth_header=[],
            auth_bearer=auth_bearer,
            login_url="",
            login_field=[],
            oauth_token_url="",
            oauth_client_id="",
            oauth_client_secret="",
            oauth_scope="",
        )
        config = ScanConfig(
            target=target,  # type: ignore[arg-type]
            scope=scope,
            auth=auth,
            rate_limit=RateLimitConfig(requests_per_second=rps if rps > 0 else 5.0),
            output=OutputConfig(format="json"),
            i_have_authorization=True,
        )
        scan_id = uuid.uuid4().hex[:12]
        job = LiveJob(id=scan_id, target=target, phase="Reverificando…")
        self._live[scan_id] = job
        self._store.insert_running(scan_id, target, "retest", None, time.time(), kind="retest", parent_id=parent_id)

        task = asyncio.create_task(self._run_retest_job(job, config, prior))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return scan_id

    async def _run_retest_job(self, job: LiveJob, config: ScanConfig, prior: list[Finding]) -> None:
        started = time.monotonic()
        try:
            new_findings = await _run_retest(config, prior, "off", "", _Budget(None, None))
            active_rule_ids = frozenset(r.id for r in load_rules())
            outcomes = classify(prior, new_findings, oast_attempted=False, active_rule_ids=active_rule_ids)
            still_open = open_findings(outcomes)
            retest = {
                "counts": summarize(outcomes),
                "outcomes": [
                    {
                        "id": o.prior.id,
                        "name": o.prior.name,
                        "severity": o.prior.severity,
                        "location": f"{o.prior.injection_point.location}:{o.prior.injection_point.name}",
                        "status": o.status,
                    }
                    for o in outcomes
                ],
            }
            self._store.mark_retest_done(job.id, time.time(), time.monotonic() - started, still_open, retest)
            job.status = "done"
            job.phase = "Completado"
        except SessionLoginError as exc:
            self._fail(job, started, f"Error de autenticación: {exc}")
        except Exception as exc:  # noqa: BLE001 — surface any engine error to the UI, don't crash the server
            self._fail(job, started, f"{type(exc).__name__}: {exc}")

    def _fail(self, job: LiveJob, started: float, message: str) -> None:
        self._store.mark_error(job.id, time.time(), time.monotonic() - started, message)
        job.status = "error"
        job.phase = message

    def live(self, scan_id: str) -> LiveJob | None:
        return self._live.get(scan_id)
