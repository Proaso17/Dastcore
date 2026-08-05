"""dastcore CLI entrypoint.

Prints the legal banner and enforces the authorization gate on every scan,
then runs the real pipeline: crawl (static HTTP and/or headless browser) ->
rule-based active scan + passive checks + DOM-XSS -> report (JSON / SARIF /
HTML). For CI/CD, `--fail-on` sets a severity threshold that makes the process
exit non-zero when met.
"""
from __future__ import annotations

import asyncio
import json as _json
import logging
import time
from contextlib import AsyncExitStack
from pathlib import Path

import httpx
import typer
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from dastcore import __version__
from dastcore.ai.client import AiChatClient
from dastcore.ai.engine import AiScanner, load_ai_rules
from dastcore.ai.presets import AI_PRESETS, resolve_preset
from dastcore.config import (
    AuthConfig,
    FormLoginConfig,
    Identity,
    OAuth2Config,
    OutputConfig,
    RateLimitConfig,
    ScanConfig,
    ScanFile,
    ScopeConfig,
)
from dastcore.core.http_client import HttpClient
from dastcore.core.models import Finding, HttpRequest
from dastcore.core.session import SessionManager
from dastcore.detectors.active_checks import check_graphql_introspection, probe_sensitive_files
from dastcore.detectors.authz import Identity as AuthzIdentity
from dastcore.detectors.authz import run_authz_checks
from dastcore.discovery.crawler_headless import HeadlessEngine, HeadlessUnavailableError
from dastcore.discovery.crawler_http import HttpCrawler
from dastcore.discovery.graphql import discover_graphql
from dastcore.discovery.openapi import fetch_and_parse_openapi
from dastcore.engine.oast import InteractshClient, LocalOastServer, OastProvider
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner
from dastcore.report import render_html, render_json, render_sarif
from dastcore.severity import meets_threshold

# Distinct from operational-error exit code 1: findings met the --fail-on bar.
EXIT_FINDINGS_OVER_THRESHOLD = 2

_RENDERERS = {"json": render_json, "sarif": render_sarif}

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="dastcore — dynamic application security testing (DAST) scanner.",
)
console = Console()

LEGAL_BANNER = (
    "dastcore es una herramienta de pentesting ACTIVA e INTRUSIVA.\n\n"
    "Solo debe usarse contra sistemas para los que tienes autorización EXPLÍCITA\n"
    "y por escrito para realizar pruebas de seguridad. Escanear sistemas sin\n"
    "autorización puede ser ilegal en tu jurisdicción (p. ej. Computer Fraud and\n"
    "Abuse Act en EE.UU., Ley 30096 en Perú, o equivalentes locales) y puede\n"
    "causar interrupciones de servicio no intencionadas.\n\n"
    "Al continuar, declaras que tienes autorización para escanear el objetivo\n"
    "indicado y que asumes toda la responsabilidad por el uso de esta herramienta."
)

_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

# Scan profiles set convenient defaults; any flag the user passes explicitly still wins.
_PROFILES: dict[str, dict[str, object]] = {
    "quick": {"engine": "http", "max_pages": 40, "oast": "off"},
    "full": {"engine": "both", "max_pages": 200, "oast": "off"},
    "api": {"engine": "http", "max_pages": 80, "oast": "off"},
}


def _load_scan_file(path: str) -> ScanFile:
    import yaml

    raw = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(raw)  # YAML is a superset of JSON, so this handles both
    if not isinstance(data, dict):
        raise ValueError("el archivo de config debe ser un mapeo (objeto) en su raíz")
    return ScanFile.model_validate(data)


def _is_default_source(ctx: typer.Context, name: str) -> bool:
    """Whether a parameter came from its default (not the command line).

    Compared by enum *name* on purpose: typer bundles its own click, so the
    ParameterSource enum it returns is a different object than one imported from
    the top-level `click` package — identity/`==` comparison would silently fail.
    """
    return ctx.get_parameter_source(name).name == "DEFAULT"


def _pick(ctx: typer.Context, name: str, cli_value, file_value):
    """CLI value if the flag was passed explicitly, else the file value, else the CLI default."""
    if _is_default_source(ctx, name) and file_value is not None:
        return file_value
    return cli_value


def _resolve_layered(ctx: typer.Context, name: str, cli_value, file_value, profile_value):
    """Precedence for profile-affected flags: explicit CLI > config file > profile > default."""
    if not _is_default_source(ctx, name):
        return cli_value
    if file_value is not None:
        return file_value
    if profile_value is not None:
        return profile_value
    return cli_value


class _Budget:
    """Global scan limits: total requests and/or wall-clock seconds. None means unbounded."""

    def __init__(self, max_requests: int | None, time_budget_s: float | None) -> None:
        self.max_requests = max_requests
        self.time_budget_s = time_budget_s


class _ProgressAdapter:
    """Drives a rich progress bar during a scan. A None progress makes every call a no-op."""

    def __init__(self, progress: Progress | None) -> None:
        self._progress = progress
        self._task = None

    def status(self, text: str) -> None:
        if self._progress is None:
            return
        if self._task is None:
            self._task = self._progress.add_task(text, total=None)
        else:
            self._progress.update(self._task, description=text)

    def start_scanning(self, total: int) -> None:
        if self._progress is None:
            return
        if self._task is None:
            self._task = self._progress.add_task("Escaneando", total=total)
        else:
            self._progress.update(self._task, description="Escaneando", total=total, completed=0)

    def tick(self) -> None:
        if self._progress is not None and self._task is not None:
            self._progress.advance(self._task)


class _ResumeState:
    """Persists per-request progress so an interrupted scan can pick up where it stopped."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.completed: set[str] = set()
        self.findings: list[Finding] = []

    def load(self) -> None:
        if not self.path.exists():
            return
        data = _json.loads(self.path.read_text(encoding="utf-8"))
        self.completed = set(data.get("completed", []))
        self.findings = [Finding.model_validate(item) for item in data.get("findings", [])]

    def record(self, signature: str, findings: list[Finding]) -> None:
        self.completed.add(signature)
        self.findings.extend(findings)
        self._flush()

    def _flush(self) -> None:
        payload = {
            "completed": sorted(self.completed),
            "findings": [finding.model_dump(mode="json") for finding in self.findings],
        }
        self.path.write_text(_json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _print_banner() -> None:
    console.print(Panel(LEGAL_BANNER, title="[bold red]AVISO LEGAL[/bold red]", border_style="red"))


def _print_summary(findings: list[Finding], duration_s: float) -> None:
    counts = {sev: 0 for sev in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    parts = [
        f"[{_SEVERITY_STYLE[sev]}]{sev}: {counts[sev]}[/{_SEVERITY_STYLE[sev]}]"
        for sev in ("critical", "high", "medium", "low", "info")
        if counts[sev]
    ]
    body = "  ".join(parts) if parts else "[green]sin hallazgos[/green]"
    console.print(
        Panel(
            f"{body}\n\nTotal: [bold]{len(findings)}[/bold]  ·  Duración: [bold]{duration_s:.1f}s[/bold]",
            title="Resumen del escaneo",
            border_style="cyan",
        )
    )


@app.command("version")
def version_cmd() -> None:
    """Print the dastcore version."""
    _print_banner()
    console.print(f"dastcore [bold]{__version__}[/bold]")


def _parse_kv_list(pairs: list[str], flag_name: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise typer.BadParameter(f"{flag_name} espera 'clave=valor', recibido: {pair!r}")
        key, value = pair.split("=", 1)
        parsed[key.strip()] = value
    return parsed


def _build_auth_config(
    *,
    auth_cookie: list[str],
    auth_header: list[str],
    auth_bearer: str,
    login_url: str,
    login_field: list[str],
    oauth_token_url: str,
    oauth_client_id: str,
    oauth_client_secret: str,
    oauth_scope: str,
) -> AuthConfig:
    """Resolve the auth flags into a single AuthConfig. Most 'active' flow wins."""
    if oauth_token_url:
        return AuthConfig(
            type="oauth2",
            oauth2=OAuth2Config(
                token_url=oauth_token_url,
                client_id=oauth_client_id,
                client_secret=oauth_client_secret,
                scope=oauth_scope or None,
            ),
        )
    if login_url:
        return AuthConfig(
            type="form",
            form=FormLoginConfig(login_url=login_url, credentials=_parse_kv_list(login_field, "--login-field")),
        )
    if auth_bearer:
        return AuthConfig(type="bearer", bearer_token=auth_bearer)
    if auth_cookie:
        return AuthConfig(type="cookie", cookies=_parse_kv_list(auth_cookie, "--auth-cookie"))
    if auth_header:
        return AuthConfig(type="header", headers=_parse_kv_list(auth_header, "--auth-header"))
    return AuthConfig(type="none")


def _build_oast_provider(oast_mode: str, oast_server: str) -> OastProvider | None:
    if oast_mode == "local":
        return LocalOastServer()
    if oast_mode == "interactsh":
        return InteractshClient(server=oast_server or "oast.fun")
    return None


async def _open_authenticated_client(
    stack: AsyncExitStack, config: ScanConfig, auth: AuthConfig, budget: "_Budget"
) -> HttpClient:
    session = SessionManager(auth) if auth.type != "none" else None
    client = await stack.enter_async_context(_make_client(config, budget, session))
    if session is not None and session.can_relogin:
        if not await session.ensure_logged_in(client, initial=True):
            raise SessionLoginError(f"El login inicial falló para una identidad ({auth.type}).")
    return client


def _make_client(config: ScanConfig, budget: "_Budget", session: SessionManager | None = None) -> HttpClient:
    return HttpClient(
        config.scope,
        rate_limit=config.rate_limit,
        session=session,
        max_requests=budget.max_requests,
        time_budget_s=budget.time_budget_s,
    )


async def _run_authz(config: ScanConfig, probes: list[HttpRequest], budget: "_Budget") -> list[Finding]:
    """Run BOLA/BFLA/missing-auth checks across the configured identities."""
    async with AsyncExitStack() as stack:
        identities = []
        for identity_cfg in config.identities:
            client = await _open_authenticated_client(stack, config, identity_cfg.auth, budget)
            identities.append(AuthzIdentity(name=identity_cfg.name, role=identity_cfg.role, client=client))
        unauth_client = await stack.enter_async_context(_make_client(config, budget))
        return await run_authz_checks(identities, probes, unauth_client=unauth_client)


async def _run_scan(
    config: ScanConfig,
    max_pages: int,
    engine: str,
    oast_mode: str = "off",
    oast_server: str = "",
    openapi_url: str = "",
    graphql_url: str = "",
    state: "_ResumeState | None" = None,
    budget: "_Budget | None" = None,
    progress: "_ProgressAdapter | None" = None,
) -> list[Finding]:
    rules = load_rules()
    session = SessionManager(config.auth) if config.auth.type != "none" else None
    target = str(config.target)
    budget = budget or _Budget(None, None)
    progress = progress or _ProgressAdapter(None)

    oast = _build_oast_provider(oast_mode, oast_server)
    if oast is not None:
        await oast.start()
    try:
        async with _make_client(config, budget, session) as client:
            if session is not None and session.can_relogin:
                if not await session.ensure_logged_in(client, initial=True):
                    raise SessionLoginError("El login inicial falló: revisa credenciales / URL de login.")

            discovered: dict[str, HttpRequest] = {}
            dom_findings: list[Finding] = []

            if engine in ("http", "both"):
                progress.status("Crawleando (HTTP estático)…")
                for req in await HttpCrawler(client, max_pages=max_pages).crawl(target):
                    discovered.setdefault(req.signature(), req)

            if engine in ("headless", "both"):
                progress.status("Crawleando (headless / SPA)…")
                headless_reqs, dom_findings = await _run_headless(config, client, target, max_pages)
                for req in headless_reqs:
                    discovered.setdefault(req.signature(), req)

            if openapi_url:
                progress.status("Ingiriendo OpenAPI…")
                for req in await fetch_and_parse_openapi(client, openapi_url, target):
                    discovered.setdefault(req.signature(), req)

            extra_findings: list[Finding] = []
            if graphql_url:
                progress.status("Introspeccionando GraphQL…")
                for req in await discover_graphql(client, graphql_url):
                    discovered.setdefault(req.signature(), req)
                extra_findings.extend(await check_graphql_introspection(client, graphql_url))

            progress.status("Probando ficheros sensibles…")
            extra_findings.extend(await probe_sensitive_files(client, target))

            scanner = Scanner(client, rules, oast=oast, concurrency=config.rate_limit.max_concurrency)
            all_requests = list(discovered.values())
            active_passive = await _scan_with_optional_resume(scanner, all_requests, state, progress)
            active_passive.extend(extra_findings)
    finally:
        if oast is not None:
            await oast.stop()

    authz_findings: list[Finding] = []
    if config.identities:
        progress.status("Pruebas de autorización (BOLA/BFLA)…")
        authz_findings = await _run_authz(config, list(discovered.values()), budget)

    return active_passive + dom_findings + authz_findings


async def _scan_with_optional_resume(
    scanner: Scanner,
    requests: list[HttpRequest],
    state: "_ResumeState | None",
    progress: "_ProgressAdapter",
) -> list[Finding]:
    """Concurrent in-band + passive scan, then OOB. With a resume state, skip requests
    already completed in a prior run and persist progress after each one."""
    prior = list(state.findings) if state is not None else []
    to_scan = [req for req in requests if state is None or req.signature() not in state.completed]
    progress.start_scanning(len(to_scan))

    def _on_done(request: HttpRequest, request_findings: list[Finding]) -> None:
        if state is not None:
            state.record(request.signature(), request_findings)
        progress.tick()

    in_band = await scanner.scan_inband(to_scan, on_request_done=_on_done)
    # OOB is idempotent and gated by the provider; run it over the full set every time.
    oob = await scanner.run_oob(requests)
    return prior + in_band + oob


async def _run_headless(
    config: ScanConfig, client: HttpClient, target: str, max_pages: int
) -> tuple[list[HttpRequest], list[Finding]]:
    """Render with a headless browser: crawl JS/XHR + probe DOM-XSS, reusing the auth session."""
    async with HeadlessEngine(
        config.scope,
        cookies=client.cookie_pairs(),
        cookie_url=target,
        extra_headers=client.session_headers(),
        max_pages=max_pages,
    ) as engine:
        discovered = await engine.crawl(target)
        page_urls = [req.url for req in discovered if req.method == "GET"]
        dom_findings = await engine.scan_dom_xss([target, *page_urls])
        return discovered, dom_findings


class SessionLoginError(RuntimeError):
    """Raised when the initial authentication cannot be established."""


def _print_findings_table(findings: list[Finding]) -> None:
    table = Table(title=f"{len(findings)} hallazgo(s)")
    table.add_column("Severidad")
    table.add_column("Nombre")
    table.add_column("Ubicación")
    for finding in findings:
        style = _SEVERITY_STYLE.get(finding.severity, "")
        location = f"{finding.injection_point.location}:{finding.injection_point.name} @ {finding.request.url}"
        table.add_row(f"[{style}]{finding.severity}[/{style}]", finding.name, location)
    console.print(table)


@app.command("scan")
def scan(
    ctx: typer.Context,
    target: str = typer.Argument(None, help="URL objetivo del escaneo. Opcional si --config lo define."),
    config_file: str = typer.Option(
        "", "--config", help="Archivo YAML/JSON con la configuración del escaneo (los flags explícitos ganan)."
    ),
    i_have_authorization: bool = typer.Option(
        False,
        "--i-have-authorization",
        help="Confirma explícitamente que tienes autorización para escanear el objetivo.",
    ),
    profile: str = typer.Option(
        "", "--profile", help="Perfil de escaneo: quick | full | api. Los flags explícitos siempre ganan."
    ),
    resume_file: str = typer.Option(
        "", "--resume", help="Archivo de estado para reanudar un escaneo interrumpido (crea/actualiza el archivo)."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Log de cada petición HTTP (nivel DEBUG)."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Silencia la salida decorativa; solo emite el reporte."),
    allow_domain: list[str] = typer.Option(
        [],
        "--allow-domain",
        help="Dominio(s) adicionales dentro de scope (repetible). Por defecto solo el host del target.",
    ),
    deny_domain: list[str] = typer.Option(
        [],
        "--deny-domain",
        help="Dominio(s) explícitamente fuera de scope (repetible). Deny siempre gana sobre allow.",
    ),
    engine: str = typer.Option(
        "http",
        "--engine",
        help="Motor de descubrimiento: http (estático) | headless (Playwright/SPA) | both.",
    ),
    oast_mode: str = typer.Option(
        "off",
        "--oast",
        help="OAST para vulnerabilidades ciegas: off | local (colaborador self-hosted) | interactsh.",
    ),
    oast_server: str = typer.Option(
        "oast.fun", "--oast-server", help="Servidor Interactsh a usar cuando --oast interactsh."
    ),
    openapi_url: str = typer.Option("", "--openapi", help="URL de un documento OpenAPI/Swagger a ingerir."),
    graphql_url: str = typer.Option("", "--graphql", help="URL de un endpoint GraphQL a introspeccionar."),
    roles_file: str = typer.Option(
        "", "--roles-file", help="Ruta a un JSON con identidades (name/role/auth) para pruebas de autorización."
    ),
    max_pages: int = typer.Option(200, "--max-pages", help="Máximo de páginas a recorrer en el crawl."),
    requests_per_second: float = typer.Option(5.0, "--rps", help="Límite de requests por segundo."),
    concurrency: int = typer.Option(5, "--concurrency", help="Peticiones en paralelo durante el escaneo activo."),
    max_requests: int = typer.Option(
        0, "--max-requests", help="Presupuesto total de peticiones (0 = sin límite). Detiene el escaneo al alcanzarlo."
    ),
    time_budget: float = typer.Option(
        0.0, "--time-budget", help="Presupuesto de tiempo en segundos (0 = sin límite)."
    ),
    output_format: str = typer.Option(
        "json", "--format", "-f", help="Formato del reporte: json | sarif | html."
    ),
    output_path: str = typer.Option(
        "", "--output", "-o", help="Ruta de archivo para el reporte (por defecto, stdout)."
    ),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Umbral de severidad que hace fallar el proceso (exit 2) para CI/CD: "
        "info | low | medium | high | critical | none.",
    ),
    auth_cookie: list[str] = typer.Option([], "--auth-cookie", help="Cookie estática 'nombre=valor' (repetible)."),
    auth_header: list[str] = typer.Option([], "--auth-header", help="Cabecera estática 'Nombre=valor' (repetible)."),
    auth_bearer: str = typer.Option("", "--auth-bearer", help="Token Bearer estático (cabecera Authorization)."),
    login_url: str = typer.Option("", "--login-url", help="Form-login: URL a la que POSTear credenciales."),
    login_field: list[str] = typer.Option(
        [], "--login-field", help="Form-login: campo de credenciales 'clave=valor' (repetible)."
    ),
    oauth_token_url: str = typer.Option("", "--oauth-token-url", help="OAuth2: URL del token endpoint."),
    oauth_client_id: str = typer.Option("", "--oauth-client-id", help="OAuth2: client_id."),
    oauth_client_secret: str = typer.Option("", "--oauth-client-secret", help="OAuth2: client_secret."),
    oauth_scope: str = typer.Option("", "--oauth-scope", help="OAuth2: scope opcional."),
) -> None:
    """Run a scan against TARGET (gated behind explicit authorization)."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    def info(*args: object, **kwargs: object) -> None:
        if not quiet:
            console.print(*args, **kwargs)

    if not quiet:
        _print_banner()

    if not i_have_authorization:
        console.print(
            "\n[bold red]ABORTADO[/bold red]: se requiere el flag "
            "[bold]--i-have-authorization[/bold] para iniciar un escaneo."
        )
        raise typer.Exit(code=1)

    # Load the optional config file; explicit CLI flags override its values.
    scan_file = ScanFile()
    if config_file:
        try:
            scan_file = _load_scan_file(config_file)
        except (OSError, ValueError, ValidationError) as exc:
            console.print(f"[bold red]--config inválido:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc

    profile = _pick(ctx, "profile", profile, scan_file.profile).lower()
    if profile and profile not in _PROFILES:
        console.print(f"[bold red]--profile inválido:[/bold red] {profile!r} (usa {' | '.join(_PROFILES)}).")
        raise typer.Exit(code=1)
    preset = _PROFILES.get(profile, {})

    target = target or scan_file.target  # explicit CLI argument wins; else the file's target
    engine = _resolve_layered(ctx, "engine", engine, scan_file.engine, preset.get("engine")).lower()
    max_pages = _resolve_layered(ctx, "max_pages", max_pages, scan_file.max_pages, preset.get("max_pages"))
    oast_mode = _resolve_layered(ctx, "oast_mode", oast_mode, scan_file.oast, preset.get("oast")).lower()
    oast_server = _pick(ctx, "oast_server", oast_server, scan_file.oast_server)
    requests_per_second = _pick(ctx, "requests_per_second", requests_per_second, scan_file.rps)
    concurrency = _pick(ctx, "concurrency", concurrency, scan_file.concurrency)
    max_requests = _pick(ctx, "max_requests", max_requests, scan_file.max_requests)
    time_budget = _pick(ctx, "time_budget", time_budget, scan_file.time_budget)
    openapi_url = _pick(ctx, "openapi_url", openapi_url, scan_file.openapi)
    graphql_url = _pick(ctx, "graphql_url", graphql_url, scan_file.graphql)
    output_format = _pick(ctx, "output_format", output_format, scan_file.format).lower()
    output_path = _pick(ctx, "output_path", output_path, scan_file.output)
    fail_on = _pick(ctx, "fail_on", fail_on, scan_file.fail_on).lower()
    if _is_default_source(ctx, "allow_domain") and scan_file.allow_domains is not None:
        allow_domain = scan_file.allow_domains
    if _is_default_source(ctx, "deny_domain") and scan_file.deny_domains is not None:
        deny_domain = scan_file.deny_domains

    if not target:
        console.print("[bold red]Falta el target:[/bold red] pásalo como argumento o en --config.")
        raise typer.Exit(code=1)

    if engine not in ("http", "headless", "both"):
        console.print(f"[bold red]--engine inválido:[/bold red] {engine!r} (usa http | headless | both).")
        raise typer.Exit(code=1)

    if oast_mode not in ("off", "local", "interactsh"):
        console.print(f"[bold red]--oast inválido:[/bold red] {oast_mode!r} (usa off | local | interactsh).")
        raise typer.Exit(code=1)

    if output_format not in ("json", "sarif", "html"):
        console.print(f"[bold red]Formato inválido:[/bold red] {output_format!r} (usa json | sarif | html).")
        raise typer.Exit(code=1)

    valid_fail_on = ("info", "low", "medium", "high", "critical", "none")
    if fail_on not in valid_fail_on:
        console.print(f"[bold red]--fail-on inválido:[/bold red] {fail_on!r} (usa {' | '.join(valid_fail_on)}).")
        raise typer.Exit(code=1)

    identities: list[Identity] = []
    if roles_file:
        try:
            raw_identities = _json.loads(Path(roles_file).read_text(encoding="utf-8"))
            identities = [Identity.model_validate(item) for item in raw_identities]
        except (OSError, ValueError, ValidationError) as exc:
            console.print(f"[bold red]--roles-file inválido:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc
    elif scan_file.identities is not None:
        identities = scan_file.identities

    try:
        auth = _build_auth_config(
            auth_cookie=auth_cookie,
            auth_header=auth_header,
            auth_bearer=auth_bearer,
            login_url=login_url,
            login_field=login_field,
            oauth_token_url=oauth_token_url,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
            oauth_scope=oauth_scope,
        )
        if auth.type == "none" and scan_file.auth is not None:
            auth = scan_file.auth
        config = ScanConfig(
            target=target,  # type: ignore[arg-type]
            scope=ScopeConfig(allow_domains=list(allow_domain), deny_domains=list(deny_domain)),
            auth=auth,
            identities=identities,
            rate_limit=RateLimitConfig(requests_per_second=requests_per_second, max_concurrency=concurrency),
            output=OutputConfig(format=output_format, path=output_path or None),
            i_have_authorization=i_have_authorization,
        )
    except ValidationError as exc:
        console.print(f"[bold red]Configuración inválida:[/bold red]\n{exc}")
        raise typer.Exit(code=1) from exc

    budget = _Budget(max_requests or None, time_budget or None)

    state: _ResumeState | None = None
    if resume_file:
        state = _ResumeState(resume_file)
        state.load()

    info(f"\n[green]Autorización confirmada.[/green] Target: [bold]{config.target}[/bold]")
    info(f"Scope permitido: {config.scope.allow_domains}")
    if config.scope.deny_domains:
        info(f"Scope denegado: {config.scope.deny_domains}")
    if config.auth.type != "none":
        info(f"Autenticación: [bold]{config.auth.type}[/bold]")
    if profile:
        info(f"Perfil: [bold]{profile}[/bold]")
    info(f"Motor de descubrimiento: [bold]{engine}[/bold]  ·  Concurrencia: [bold]{concurrency}[/bold]")
    if oast_mode != "off":
        info(f"OAST: [bold]{oast_mode}[/bold]")
    if budget.max_requests or budget.time_budget_s:
        req_limit = budget.max_requests if budget.max_requests else "sin limite"
        time_limit = f"{budget.time_budget_s}s" if budget.time_budget_s else "sin limite"
        info(f"Presupuesto: [bold]{req_limit}[/bold] req, [bold]{time_limit}[/bold]")
    if config.identities:
        info(f"Identidades (authz): [bold]{', '.join(i.name for i in config.identities)}[/bold]")
    if state is not None and state.completed:
        info(f"Reanudando: [bold]{len(state.completed)}[/bold] requests ya completados")

    info()
    started_at = time.monotonic()
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
        disable=quiet or not console.is_terminal,
    )
    try:
        with progress:
            findings = asyncio.run(
                _run_scan(
                    config, max_pages, engine, oast_mode, oast_server, openapi_url, graphql_url,
                    state, budget, _ProgressAdapter(progress),
                )
            )
    except SessionLoginError as exc:
        console.print(f"\n[bold red]Error de autenticación:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    except HeadlessUnavailableError as exc:
        console.print(f"\n[bold red]Motor headless no disponible:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    except httpx.HTTPError as exc:
        console.print(f"\n[bold red]Error de red al escanear el objetivo:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    duration_s = time.monotonic() - started_at

    if output_format == "html":
        report = render_html(findings, target=str(config.target))
    else:
        report = _RENDERERS[output_format](findings)

    if not quiet:
        console.print()
        _print_findings_table(findings)
        _print_summary(findings, duration_s)

    if config.output.path:
        Path(config.output.path).write_text(report, encoding="utf-8")
        info(f"\n[green]Reporte {output_format.upper()} escrito en {config.output.path}[/green]")
    elif output_format == "html" and not quiet:
        console.print(
            "\n[yellow]El reporte HTML es extenso; usa[/yellow] [bold]-o reporte.html[/bold] "
            "[yellow]para guardarlo en un archivo.[/yellow]"
        )
        print(report)
    else:
        # In quiet mode, emit only the raw report to stdout (clean for piping).
        if not quiet:
            console.print(f"\n[bold]{output_format.upper()}:[/bold]")
        print(report)

    if fail_on != "none":
        blocking = [f for f in findings if meets_threshold(f.severity, fail_on)]  # type: ignore[arg-type]
        if blocking:
            console.print(
                f"\n[bold red]{len(blocking)} hallazgo(s) con severidad >= {fail_on}.[/bold red] "
                f"Saliendo con código {EXIT_FINDINGS_OVER_THRESHOLD} (--fail-on)."
            )
            raise typer.Exit(code=EXIT_FINDINGS_OVER_THRESHOLD)


def _emit_report_and_gate(
    findings: list[Finding],
    *,
    output_format: str,
    output_path: str,
    fail_on: str,
    quiet: bool,
    target: str,
    duration_s: float,
) -> None:
    """Shared reporting/exit-gate used by `scan` and `ai`."""
    if output_format == "html":
        report = render_html(findings, target=target)
    else:
        report = _RENDERERS[output_format](findings)

    if not quiet:
        console.print()
        _print_findings_table(findings)
        _print_summary(findings, duration_s)

    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")
        if not quiet:
            console.print(f"\n[green]Reporte {output_format.upper()} escrito en {output_path}[/green]")
    else:
        if not quiet and output_format != "html":
            console.print(f"\n[bold]{output_format.upper()}:[/bold]")
        print(report)

    if fail_on != "none":
        blocking = [f for f in findings if meets_threshold(f.severity, fail_on)]  # type: ignore[arg-type]
        if blocking:
            console.print(
                f"\n[bold red]{len(blocking)} hallazgo(s) con severidad >= {fail_on}.[/bold red] "
                f"Saliendo con código {EXIT_FINDINGS_OVER_THRESHOLD} (--fail-on)."
            )
            raise typer.Exit(code=EXIT_FINDINGS_OVER_THRESHOLD)


async def _run_ai_scan(
    config: ScanConfig,
    target: str,
    prompt_field: str,
    template: str,
    response_path: str,
    headers: dict[str, str],
) -> list[Finding]:
    async with HttpClient(config.scope, rate_limit=config.rate_limit) as client:
        chat = AiChatClient(
            client,
            target,
            prompt_field=prompt_field,
            template=template or None,
            response_path=response_path or None,
            headers=headers or None,
        )
        return await AiScanner(chat, load_ai_rules()).scan()


@app.command("ai")
def ai(
    target: str = typer.Argument(..., help="URL del endpoint de chat/completion del LLM."),
    i_have_authorization: bool = typer.Option(
        False, "--i-have-authorization", help="Confirma que tienes autorización para probar el objetivo."
    ),
    preset: str = typer.Option(
        "", "--ai-preset", help=f"Preset de proveedor: {' | '.join(AI_PRESETS)}. Configura template/response/headers."
    ),
    model: str = typer.Option("", "--ai-model", help="Modelo a usar con el preset (p.ej. gpt-4o-mini, llama3)."),
    api_key: str = typer.Option("", "--ai-key", help="API key del proveedor (se coloca en la cabecera del preset)."),
    prompt_field: str = typer.Option(
        "message", "--ai-prompt-field", help="Campo JSON del prompt (si no usas preset ni --ai-template)."
    ),
    template: str = typer.Option(
        "", "--ai-template", help='Plantilla JSON del body con {{prompt}} o {{messages}} (anula el preset).'
    ),
    response_path: str = typer.Option(
        "", "--ai-response-path", help="Dot-path al texto de respuesta (anula el preset; auto si se omite)."
    ),
    auth_bearer: str = typer.Option("", "--auth-bearer", help="Token Bearer / API key (cabecera Authorization)."),
    auth_header: list[str] = typer.Option([], "--auth-header", help="Cabecera estática 'Nombre=valor' (repetible)."),
    requests_per_second: float = typer.Option(5.0, "--rps", help="Límite de requests por segundo."),
    output_format: str = typer.Option("json", "--format", "-f", help="Formato del reporte: json | sarif | html."),
    output_path: str = typer.Option("", "--output", "-o", help="Ruta de archivo para el reporte."),
    fail_on: str = typer.Option("high", "--fail-on", help="Umbral que hace fallar el proceso (exit 2): ... | none."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Silencia la salida decorativa; solo emite el reporte."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Log de cada petición HTTP (DEBUG)."),
) -> None:
    """Probar un chatbot / LLM (OWASP LLM Top 10): prompt injection (directa/indirecta),
    jailbreak, crescendo multi-turno, fuga de system prompt, secretos/PII, excessive
    agency, output inseguro y denial of wallet. Usa --ai-preset para OpenAI/Anthropic/Ollama/…"""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not quiet:
        _print_banner()

    if not i_have_authorization:
        console.print("\n[bold red]ABORTADO[/bold red]: se requiere [bold]--i-have-authorization[/bold].")
        raise typer.Exit(code=1)

    output_format = output_format.lower()
    if output_format not in ("json", "sarif", "html"):
        console.print(f"[bold red]Formato inválido:[/bold red] {output_format!r} (usa json | sarif | html).")
        raise typer.Exit(code=1)
    fail_on = fail_on.lower()
    if fail_on not in ("info", "low", "medium", "high", "critical", "none"):
        console.print(f"[bold red]--fail-on inválido:[/bold red] {fail_on!r}.")
        raise typer.Exit(code=1)

    headers: dict[str, str] = {}
    if preset:
        preset = preset.lower()
        if preset not in AI_PRESETS:
            console.print(f"[bold red]--ai-preset inválido:[/bold red] {preset!r} (usa {' | '.join(AI_PRESETS)}).")
            raise typer.Exit(code=1)
        preset_template, preset_response, preset_headers = resolve_preset(preset, model=model, api_key=api_key)
        template = template or preset_template
        response_path = response_path or preset_response
        headers.update(preset_headers)
    if auth_bearer:
        headers["Authorization"] = f"Bearer {auth_bearer}"
    try:
        headers.update(_parse_kv_list(auth_header, "--auth-header"))
        config = ScanConfig(
            target=target,  # type: ignore[arg-type]
            rate_limit=RateLimitConfig(requests_per_second=requests_per_second),
            output=OutputConfig(format=output_format, path=output_path or None),
            i_have_authorization=i_have_authorization,
        )
    except (ValidationError, typer.BadParameter) as exc:
        console.print(f"[bold red]Configuración inválida:[/bold red]\n{exc}")
        raise typer.Exit(code=1) from exc

    if not quiet:
        console.print(f"\n[green]Autorización confirmada.[/green] Endpoint IA: [bold]{config.target}[/bold]")
        if preset:
            console.print(f"Preset: [bold]{preset}[/bold]" + (f" · modelo [bold]{model}[/bold]" if model else ""))
        console.print("Ejecutando ataques LLM (OWASP LLM Top 10)…\n")

    started_at = time.monotonic()
    try:
        findings = asyncio.run(_run_ai_scan(config, str(config.target), prompt_field, template, response_path, headers))
    except httpx.HTTPError as exc:
        console.print(f"\n[bold red]Error de red al contactar el endpoint IA:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    _emit_report_and_gate(
        findings,
        output_format=output_format,
        output_path=output_path,
        fail_on=fail_on,
        quiet=quiet,
        target=str(config.target),
        duration_s=time.monotonic() - started_at,
    )


if __name__ == "__main__":
    app()
