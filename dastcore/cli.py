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
import re
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

import httpx
import typer
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text

from dastcore import __version__
from dastcore.ai.agency import ActionAgencyScanner, ReadBack
from dastcore.ai.client import AiChatClient
from dastcore.ai.cross_tenant import CrossTenantScanner, TenantProbe
from dastcore.ai.discovery import ChatEndpointProfile, probe_chat_endpoints
from dastcore.ai.engine import AiScanner, load_ai_rules
from dastcore.ai.payload_gen import AiPayloadGenerator, build_payload_generator
from dastcore.ai.presets import AI_PRESETS, resolve_preset
from dastcore.ai.stored_injection import StoredInjectionScanner, WriteEndpoint, infer_write_endpoints
from dastcore.analysis import prove_findings_impact
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
from dastcore.core.http_client import BudgetExceededError, HttpClient
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.core.session import SessionManager, auth_endpoint_urls
from dastcore.detectors.access_bypass import run_access_bypass_checks
from dastcore.detectors.active_checks import (
    check_dangerous_methods,
    check_graphql_introspection,
    check_trace_method,
    probe_sensitive_files,
)
from dastcore.detectors.authz import Identity as AuthzIdentity
from dastcore.detectors.authz import run_authz_checks
from dastcore.detectors.cache_deception import run_cache_deception_checks
from dastcore.detectors.cache_poison import run_cache_poisoning_checks
from dastcore.detectors.code_injection import run_code_injection_checks
from dastcore.detectors.csrf import run_csrf_checks
from dastcore.detectors.deserialization_active import run_deserialization_checks
from dastcore.detectors.file_upload import run_file_upload_checks
from dastcore.detectors.fingerprint import fingerprint_and_waf
from dastcore.detectors.graphql import run_graphql_checks
from dastcore.detectors.graphql_authz import run_graphql_authz_checks, run_graphql_field_authz_checks
from dastcore.detectors.graphql_injection import check_graphql_arg_injection
from dastcore.detectors.js_secrets import run_js_secret_scan
from dastcore.detectors.jwt import (
    check_jwt_algorithm_confusion,
    check_jwt_jwk_injection,
    check_jwt_key_url_ssrf,
    check_jwt_kid_injection,
    check_jwt_none_acceptance,
    check_jwt_signature_not_verified,
    check_jwt_weak_secret,
    check_jwt_x5c_injection,
    looks_like_jwt,
)
from dastcore.detectors.mass_assignment import run_mass_assignment_checks
from dastcore.detectors.nosqli import run_nosql_checks
from dastcore.detectors.oauth import run_oauth_checks
from dastcore.detectors.proto_pollution import run_proto_pollution_checks
from dastcore.detectors.redos import run_redos_checks
from dastcore.detectors.request_smuggling import run_smuggling_checks
from dastcore.detectors.reset_poison import run_reset_poisoning_checks
from dastcore.detectors.response_splitting import run_response_splitting_checks
from dastcore.detectors.session_fixation import check_session_fixation
from dastcore.detectors.shellshock import check_shellshock
from dastcore.detectors.spa import run_spa_check
from dastcore.detectors.ssi import run_ssi_checks
from dastcore.detectors.ssrf_metadata import run_cloud_ssrf_checks
from dastcore.detectors.ssti_error import run_ssti_error_checks
from dastcore.detectors.takeover import run_subdomain_takeover_check
from dastcore.detectors.user_enum import run_user_enumeration_checks
from dastcore.detectors.weak_credentials import run_weak_credentials_check
from dastcore.detectors.xml_expansion import run_xml_expansion_checks
from dastcore.discovery.activate import activate_endpoints
from dastcore.discovery.api_probe import probe_api_schemas
from dastcore.discovery.asn import asn_intel_findings, gather_asn_intel
from dastcore.discovery.content import (
    ContentDiscoverer,
    content_extensions,
    content_recursion_depth,
    load_content_wordlist,
)
from dastcore.discovery.crawler_headless import HeadlessEngine, HeadlessUnavailableError
from dastcore.discovery.crawler_http import HttpCrawler
from dastcore.discovery.dns_records import RecordSet, gather_dns_records, ptr_sweep
from dastcore.discovery.favicon import probe_favicon
from dastcore.discovery.graphql import discover_graphql
from dastcore.discovery.historical import gather_historical_urls, prioritise, url_to_request
from dastcore.discovery.js_endpoints import JsEndpointDiscoverer
from dastcore.discovery.openapi import fetch_and_parse_openapi
from dastcore.discovery.osint import bucket_findings, check_buckets, github_code_search, github_findings
from dastcore.discovery.params import load_param_wordlist, mine_hidden_params
from dastcore.discovery.ports import discover_http_ports
from dastcore.discovery.recon_paths import ReconPathDiscoverer
from dastcore.discovery.subdomains import (
    SubdomainDiscoverer,
    load_subdomain_wordlist,
    subdomain_recursion_depth,
)
from dastcore.discovery.supabase import (
    SupabaseDiscoverer,
    SupabaseProfile,
    graphql_url_for,
    is_supabase_project,
    probe_cross_user_bola,
    probe_supabase_aux,
    probe_write_rls,
)
from dastcore.discovery.tech_paths import discover_tech_paths
from dastcore.discovery.tls_info import run_tls_checks
from dastcore.discovery.vhosts import VhostDiscoverer, vhost_findings
from dastcore.engine.oast import InteractshClient, LocalOastServer, OastProvider
from dastcore.engine.race import run_race_checks
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner
from dastcore.report import render_defectdojo, render_html, render_json, render_sarif
from dastcore.report.correlation import correlate, cross_correlate, deduplicate
from dastcore.report.incremental import FindingSink
from dastcore.report.markdown import render_markdown_diff
from dastcore.retest import (
    RetestOutcome,
    base_requests_for,
    classify,
    load_prior_findings,
    open_findings,
    summarize,
)
from dastcore.severity import meets_threshold
from dastcore.suppressions import Suppression, apply_suppressions, resolve_suppressions
from dastcore.triage import triage_findings
from dastcore.triage.digest import TriageDigest, build_digest
from dastcore.web.diff import diff_findings

# Distinct from operational-error exit code 1: findings met the --fail-on bar.
EXIT_FINDINGS_OVER_THRESHOLD = 2

_RENDERERS = {"json": render_json, "sarif": render_sarif, "defectdojo": render_defectdojo}

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="dastcore — dynamic application security testing (DAST) scanner.",
)
console = Console()

auth_app = typer.Typer(
    no_args_is_help=True, help="Grabar y reproducir macros de login de navegador (auth compleja / JS)."
)
app.add_typer(auth_app, name="auth")

baseline_app = typer.Typer(
    no_args_is_help=True, help="Gestiona la línea base de hallazgos para el diff de CI (dastcore diff)."
)
app.add_typer(baseline_app, name="baseline")

_DEFAULT_BASELINE = ".dastcore/baseline.json"

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

_CONFIDENCE_STYLE = {"high": "bold green", "medium": "yellow", "low": "dim"}

# Scan profiles set convenient defaults; any flag the user passes explicitly still wins.
_PROFILES: dict[str, dict[str, object]] = {
    "quick": {"engine": "http", "max_pages": 40, "oast": "off"},
    "full": {"engine": "both", "max_pages": 200, "oast": "off"},
    "api": {"engine": "http", "max_pages": 80, "oast": "off"},
}


_ENV_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand_env_refs(value: object) -> object:
    """Replace ``${VAR}`` / ``${VAR:-default}`` references in string leaves with the environment's
    value, so secrets (passwords, API keys) live in env vars instead of a committed config file.

    Expansion is done on the parsed structure (not the raw YAML text), so a secret's contents can
    never alter the document's shape. An unset variable with no default is a clear error rather than
    a silent empty string, so a typo can't quietly turn into an anonymous scan."""
    import os

    if isinstance(value, str):

        def _sub(match: re.Match[str]) -> str:
            name, default = match.group(1), match.group(2)
            if name in os.environ:
                return os.environ[name]
            if default is not None:
                return default
            raise ValueError(
                f"la variable de entorno '{name}' que usa el config no está definida "
                f"(o dale un valor por defecto con ${{{name}:-valor}})"
            )

        return _ENV_REF_RE.sub(_sub, value)
    if isinstance(value, dict):
        return {key: _expand_env_refs(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand_env_refs(item) for item in value]
    return value


def _load_scan_file(path: str) -> ScanFile:
    import yaml

    raw = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(raw)  # YAML is a superset of JSON, so this handles both
    if not isinstance(data, dict):
        raise ValueError("el archivo de config debe ser un mapeo (objeto) en su raíz")
    data = _expand_env_refs(data)  # ${VAR} / ${VAR:-default} → env, so passwords stay out of the file
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


_scan_log = logging.getLogger("dastcore.scan")


class _ProgressAdapter:
    """Drives a rich progress bar during a scan. A None progress makes every call a no-op.

    Every status line is also emitted to the ``dastcore.scan`` logger, so a scan run in the background
    or in CI (no interactive terminal for the rich bar) still shows its phase-by-phase progress once
    logging is configured — which the ``scan`` command does automatically when stdout isn't a TTY.
    """

    def __init__(self, progress: Progress | None) -> None:
        self._progress = progress
        self._task = None

    def status(self, text: str) -> None:
        _scan_log.info(text)
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
    counts = dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
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


_CAPABILITY_LABEL = {
    "full": ("green", "cubierto"),
    "partial": ("yellow", "parcial"),
    "none": ("dim", "no aplica (black-box)"),
}


def _print_owasp_coverage(findings: list[Finding]) -> None:
    """Show the OWASP Top 10 (2021) rollup: what was tested across the surface and what turned up."""
    from dastcore.owasp import summarize

    table = Table(title="Cobertura OWASP Top 10 (2021)", title_style="bold", show_lines=False)
    table.add_column("Categoría")
    table.add_column("Análisis", justify="center")
    table.add_column("Hallazgos", justify="right")
    table.add_column("Peor severidad")
    for row in summarize(findings):
        style, label = _CAPABILITY_LABEL.get(str(row["capability"]), ("white", str(row["capability"])))
        count = int(row["count"])  # type: ignore[call-overload]
        sev = row["worst_severity"]
        sev_cell = f"[{_SEVERITY_STYLE.get(str(sev), 'white')}]{sev}[/]" if sev else "[dim]—[/dim]"
        count_cell = f"[bold]{count}[/bold]" if count else "[dim]0[/dim]"
        table.add_row(f"{row['code']} · {row['name']}", f"[{style}]{label}[/{style}]", count_cell, sev_cell)
    console.print(table)


def _load_suppressions_or_exit(explicit_path: str) -> list[Suppression]:
    """Resolve triage suppressions, turning any error into a clean CLI abort."""
    try:
        return resolve_suppressions(explicit_path)
    except (OSError, ValueError, ValidationError) as exc:
        console.print(f"[bold red]--suppress inválido:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc


def _print_suppressed_note(suppressed: list[Finding]) -> None:
    console.print(
        f"\n[dim]{len(suppressed)} hallazgo(s) suprimido(s) por triaje (.dastcore-ignore): "
        "excluidos del gate --fail-on; siguen en JSON/SARIF marcados como aceptados.[/dim]"
    )


@app.command("version")
def version_cmd() -> None:
    """Print the dastcore version."""
    _print_banner()
    console.print(f"dastcore [bold]{__version__}[/bold]")


async def _run_demo_scan(base_url: str) -> list[Finding]:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    findings: list[Finding] = []
    async with HttpClient(scope) as client:
        discovered = await HttpCrawler(client).crawl(base_url)
        findings.extend(await Scanner(client, load_rules(), concurrency=5).scan(discovered))
        findings.extend(await probe_sensitive_files(client, base_url))
        chat = AiChatClient(client, f"{base_url}/ai/chat")
        findings.extend(await AiScanner(chat, load_ai_rules()).scan())
    return deduplicate(findings)


@app.command("demo")
def demo(
    output_path: str = typer.Option("", "--output", "-o", help="Guarda un reporte HTML del demo."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Solo el resumen."),
) -> None:
    """Lanza un objetivo vulnerable incluido y lo escanea (web + IA) para probar dastcore al instante."""
    from dastcore.demo.app import start_demo_target

    if not quiet:
        console.print(
            Panel(
                "Escaneando un objetivo vulnerable [bold]incluido en dastcore[/bold] (localhost).\n"
                "Sirve para ver resultados al instante, sin tener un objetivo propio.",
                title="dastcore demo",
                border_style="cyan",
            )
        )
    server, base_url = start_demo_target()
    started_at = time.monotonic()
    try:
        console.print(f"\n[yellow]Objetivo demo en[/yellow] [bold]{base_url}[/bold] · escaneando (web + IA)…\n")
        findings = asyncio.run(_run_demo_scan(base_url))
    finally:
        server.shutdown()

    _print_findings_table(findings)
    _print_summary(findings, time.monotonic() - started_at)
    if output_path:
        Path(output_path).write_text(
            render_html(findings, target=base_url, title="dastcore demo report"), encoding="utf-8"
        )
        console.print(f"\n[green]Reporte HTML escrito en {output_path}[/green]")
    console.print(
        "\n[dim]Prueba contra tu objetivo:[/dim] dastcore scan <URL> --i-have-authorization  ·  "
        "dastcore ai <URL-chat> --i-have-authorization"
    )


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
    login_macro: str = "",
    macro_var: list[str] | None = None,
    login_header: list[str] | None = None,
    login_token_field: str = "",
    login_token_header: str = "Authorization",
) -> AuthConfig:
    """Resolve the auth flags into a single AuthConfig. Most 'active' flow wins."""
    if login_macro:
        return AuthConfig(
            type="macro",
            macro_path=login_macro,
            macro_runtime=_parse_kv_list(macro_var or [], "--auth-macro-var"),
        )
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
            form=FormLoginConfig(
                login_url=login_url,
                credentials=_parse_kv_list(login_field, "--login-field"),
                login_headers=_parse_kv_list(login_header or [], "--login-header"),
                token_json_field=login_token_field or None,
                token_header=login_token_header or "Authorization",
            ),
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
    stack: AsyncExitStack, config: ScanConfig, auth: AuthConfig, budget: _Budget
) -> HttpClient:
    session = SessionManager(auth) if auth.type != "none" else None
    client = await stack.enter_async_context(_make_client(config, budget, session))
    if session is not None and session.can_relogin:
        if not await session.ensure_logged_in(client, initial=True):
            raise SessionLoginError(f"El login inicial falló para una identidad ({auth.type}).")
    return client


def _make_client(
    config: ScanConfig,
    budget: _Budget,
    session: SessionManager | None = None,
    user_agent: str = "",
    proxy: str = "",
    attribution: dict[str, str] | None = None,
) -> HttpClient:
    rl = config.rate_limit
    governor = None
    if rl.per_host_rps or rl.per_endpoint_daily_cap or rl.jitter_ms:
        from dastcore.core.rate_governor import RateGovernor

        governor = RateGovernor(
            per_host_rps=rl.per_host_rps,
            per_endpoint_daily_cap=rl.per_endpoint_daily_cap,
            jitter_ms=rl.jitter_ms,
            daily_cap_db=rl.daily_cap_db or None,
        )
    return HttpClient(
        config.scope,
        rate_limit=config.rate_limit,
        timeout=config.rate_limit.timeout,
        max_retries=config.rate_limit.max_retries,
        session=session,
        max_requests=budget.max_requests,
        time_budget_s=budget.time_budget_s,
        # Let the session (re)authenticate against its IdP endpoints even if off the attack scope.
        auth_urls=auth_endpoint_urls(config.auth),
        user_agent=user_agent or None,
        proxy=proxy or None,  # route every request via the proxy/VPN so traffic exits a trusted IP
        attribution=attribution or None,  # e.g. X-Bug-Bounty: identify our traffic as programs require
        governor=governor,  # per-host / per-endpoint-daily RoE governance (None = off)
    )


async def _run_authz(
    config: ScanConfig, probes: list[HttpRequest], budget: _Budget, graphql_url: str = ""
) -> list[Finding]:
    """Run BOLA/BFLA/missing-auth checks across the configured identities (REST + GraphQL)."""
    async with AsyncExitStack() as stack:
        identities = []
        failed_logins: list[str] = []
        for identity_cfg in config.identities:
            # Verify each identity authenticates. A silent login failure would make the anon-vs-authed
            # comparison meaningless (both sessions equal), so we record it and keep the ones that worked
            # rather than aborting all of authz.
            try:
                client = await _open_authenticated_client(stack, config, identity_cfg.auth, budget)
            except Exception as exc:  # noqa: BLE001 — one bad identity must not sink the others
                _scan_log.warning("Identidad '%s' no autenticó: %s: %s", identity_cfg.name, type(exc).__name__, exc)
                failed_logins.append(identity_cfg.name)
                continue
            identities.append(AuthzIdentity(name=identity_cfg.name, role=identity_cfg.role, client=client))
        unauth_client = await stack.enter_async_context(_make_client(config, budget))
        findings = await run_authz_checks(identities, probes, unauth_client=unauth_client)
        if graphql_url:
            findings.extend(await run_graphql_authz_checks(identities, graphql_url, unauth_client=unauth_client))
            findings.extend(await run_graphql_field_authz_checks(identities, graphql_url, unauth_client=unauth_client))
        if failed_logins:
            findings.append(_login_failed_finding(str(config.target), failed_logins))
        return findings


async def _run_supabase_write_test(
    config: ScanConfig, rest_base: str, tables: set[str], budget: _Budget
) -> list[Finding]:
    """Opt-in write-side RLS test: for each configured identity (or the main session), probe whether it
    can INSERT into each discovered table. Safe (see probe_write_rls) but mutating in the worst case, so
    it only runs when explicitly enabled."""
    vulns: list[Finding] = []
    identities_probed = 0
    tables_tested = 0
    async with AsyncExitStack() as stack:
        identity_cfgs = config.identities or [Identity(name=config.auth.type or "sesión", auth=config.auth)]
        for identity_cfg in identity_cfgs:
            try:
                client = await _open_authenticated_client(stack, config, identity_cfg.auth, budget)
            except Exception as exc:  # noqa: BLE001 — a bad identity is reported by authz; just skip it here
                _scan_log.warning("write-rls: identidad '%s' no autenticó: %s", identity_cfg.name, exc)
                continue
            f, tested = await probe_write_rls(client, rest_base, tables, identity=identity_cfg.name)
            vulns.extend(f)
            tables_tested = max(tables_tested, tested)
            identities_probed += 1
    result: list[Finding] = list(vulns)
    if identities_probed:  # emit coverage even with 0 vulns, so the report documents what was tested
        result.append(_supabase_write_coverage_finding(rest_base, tables_tested, identities_probed, len(vulns)))
    return result


_USER_AUTH_TYPES = ("form", "oauth2", "oauth2_pkce", "bearer")  # a distinct logged-in user (not the anon key)


async def _run_supabase_bola(config: ScanConfig, rest_base: str, tables: set[str], budget: _Budget) -> list[Finding]:
    """Cross-user BOLA on Supabase tables: for every ordered pair of authenticated identities, test if
    one can read the other's own rows by id. Read-only, so it runs automatically once ≥2 real user
    identities are configured."""
    import itertools

    users = [idc for idc in config.identities if idc.auth.type in _USER_AUTH_TYPES]
    if len(users) < 2:
        return []
    vulns: list[Finding] = []
    pairs = 0
    comparable_total = 0
    async with AsyncExitStack() as stack:
        clients: dict[str, HttpClient] = {}
        for idc in users:
            try:
                clients[idc.name] = await _open_authenticated_client(stack, config, idc.auth, budget)
            except Exception as exc:  # noqa: BLE001 — a bad identity is already reported by authz; skip here
                _scan_log.warning("bola: identidad '%s' no autenticó: %s", idc.name, exc)
        names = [idc.name for idc in users if idc.name in clients]
        for name_a, name_b in itertools.permutations(names, 2):
            f, comparable = await probe_cross_user_bola(
                clients[name_a], clients[name_b], rest_base, tables, name_a=name_a, name_b=name_b
            )
            vulns.extend(f)
            comparable_total += comparable
            pairs += 1
    result: list[Finding] = list(vulns)
    if pairs:  # BOLA actually ran (≥2 users authenticated) → document coverage, incl. "nothing to compare"
        result.append(_supabase_bola_coverage_finding(rest_base, comparable_total, pairs, len(vulns)))
    return result


async def _prove_impact_isolated(client: HttpClient, findings: list[Finding]) -> list[Finding]:
    """Adapt prove_findings_impact (mutates findings in place) to the isolated ``phase`` runner."""
    await prove_findings_impact(client, findings)
    return []


def _coverage_finding(target: str, failed: list[str]) -> Finding:
    """An info advisory that some checks were skipped, so the report reflects partial coverage."""
    names = ", ".join(sorted(set(failed)))
    request = HttpRequest(method="GET", url=target)
    return Finding(
        id="scan-partial-coverage",
        rule_id="scan-coverage",
        name=f"Cobertura parcial: {len(set(failed))} comprobación(es) se omitieron por un error",
        severity="info",
        cwe="CWE-200",
        owasp="WSTG-INFO-01",
        injection_point=InjectionPoint(location="header", name="-", base_value="", request_template=request),
        evidence=[Evidence(type="response_match", data=f"omitidas: {names}"[:300], confidence="high")],
        request=request,
        response=HttpResponse(status_code=0, url=target),
        remediation=(
            "Algunas comprobaciones se saltaron por un error interno o del objetivo, así que este escaneo "
            "es de cobertura parcial. Revisa los registros (nivel WARNING) para ver cuál falló y por qué."
        ),
    )


def _login_failed_finding(target: str, names: list[str]) -> Finding:
    """An advisory that one or more configured identities failed to authenticate — so any anon-vs-authed
    / BOLA comparison over them is unreliable and must not be read as 'no authorization flaw'."""
    who = ", ".join(names)
    request = HttpRequest(method="GET", url=target)
    detail = (
        f"Identidad(es) que no autenticaron: {who}. La comparación de autorización (anon-vs-authed / BOLA) "
        "sobre ellas NO es fiable: revisa credenciales, login_url y cabeceras (p. ej. apikey de Supabase)."
    )
    return Finding(
        id="authz-identity-login-failed",
        rule_id="authz-login",
        name=f"Identidad(es) sin autenticar: {who} — la comprobación de autorización puede no ser válida",
        severity="info",
        cwe="CWE-287",
        owasp="WSTG-ATHN-01",
        injection_point=InjectionPoint(location="header", name="-", base_value="", request_template=request),
        evidence=[Evidence(type="status", data=detail[:300], confidence="high")],
        request=request,
        response=HttpResponse(status_code=0, url=target, text=detail),
        remediation=(
            "Corrige el login de esas identidades y vuelve a escanear. Para Supabase: login_url a "
            "/auth/v1/token?grant_type=password, credenciales email/password correctas, y el header "
            "apikey (anon) tanto en el login como en cada petición."
        ),
    )


def _supabase_coverage_finding(target: str, prof: SupabaseProfile) -> Finding:
    """An info advisory recording the autonomous Supabase enumeration, so the report itself says how
    many tables were found and tested (anon-vs-authed) — instead of that only living in the console."""
    n = len(prof.tables)
    request = HttpRequest(method="GET", url=target)
    sources: list[str] = [
        f"GraphQL introspection: {len(prof.graphql_tables)}" if prof.introspection_enabled
        else "GraphQL introspection: deshabilitada/vacía"
    ]
    if prof.frontend_tables:
        sources.append(f"frontend: {len(prof.frontend_tables)}")
    if prof.oracle_blind:
        sources.append("oráculo PostgREST ciego → solo fuentes exactas")
    sample = ", ".join(sorted(prof.tables)[:20])
    detail = f"{n} tabla(s) confirmadas y probadas anon-vs-authed. Fuentes → {'; '.join(sources)}."
    if sample:
        detail += f" Tablas: {sample}{' …' if n > 20 else ''}"
    name = (
        f"Supabase: {n} tabla(s) descubiertas y probadas (anon vs authed)"
        if n
        else "Supabase: no se descubrió ninguna tabla accesible con la apikey anon"
    )
    remediation = (
        "Este aviso documenta la cobertura del perfilado de Supabase (introspección GraphQL + "
        "enumeración PostgREST). Si el número de tablas es 0, revisa que la introspección de "
        "pg_graphql esté deshabilitada y que ninguna tabla sea legible con la clave anon; si hay "
        "tablas, cada una se comparó anónimo-vs-autenticado para detectar RLS/BOLA (mira los "
        "hallazgos de autorización, si los hay)."
    )
    return Finding(
        id="supabase-coverage",
        rule_id="supabase-profile",
        name=name,
        severity="info",
        cwe="CWE-200",
        owasp="WSTG-INFO-01",
        injection_point=InjectionPoint(location="header", name="-", base_value="", request_template=request),
        evidence=[Evidence(type="response_match", data=detail[:300], confidence="high")],
        request=request,
        response=HttpResponse(status_code=0, url=target, text=detail),
        remediation=remediation,
    )


def _supabase_service_role_finding(target: str, keys: set[str]) -> Finding:
    """CRITICAL: a service_role key was found in the front-end bundle. That key bypasses RLS entirely,
    so anyone reading the JavaScript gains full read/write to the whole database."""
    request = HttpRequest(method="GET", url=target)
    detail = (
        f"Se encontró {len(keys)} clave(s) `service_role` de Supabase en el bundle del frontend "
        f"({', '.join(sorted(keys))}). Esa clave IGNORA el RLS: cualquiera que lea el JavaScript tiene "
        "lectura/escritura TOTAL de la base de datos."
    )
    return Finding(
        id="supabase-service-role-exposed",
        rule_id="supabase-service-role",
        name="CRÍTICO: clave service_role de Supabase expuesta en el frontend (bypass total de RLS)",
        severity="critical",
        cwe="CWE-798",
        owasp="API2:2023",
        injection_point=InjectionPoint(location="header", name="apikey", base_value="", request_template=request),
        evidence=[Evidence(type="status", data=detail[:300], confidence="high")],
        request=request,
        response=HttpResponse(status_code=0, url=target, text=detail),
        remediation=(
            "Quita la clave service_role del frontend de inmediato y ROTA la clave en Supabase "
            "(Settings → API). El frontend solo debe usar la clave anon (o publishable). Nunca embebas "
            "service_role en código que llega al navegador."
        ),
    )


def _supabase_functions_finding(target: str, rpcs: set[str], edge: set[str]) -> Finding:
    """Info surface: the RPC / Edge Functions the front-end invokes — listed for manual review, not
    invoked (calling an unknown function could have side effects)."""
    request = HttpRequest(method="GET", url=target)
    parts = []
    if rpcs:
        parts.append(f"RPC ({len(rpcs)}): {', '.join(sorted(rpcs)[:20])}")
    if edge:
        parts.append(f"Edge Functions ({len(edge)}): {', '.join(sorted(edge)[:20])}")
    detail = "Funciones que el frontend invoca (revisar manualmente authz/SECURITY DEFINER). " + " · ".join(parts)
    return Finding(
        id="supabase-functions",
        rule_id="supabase-functions",
        name=f"Supabase: {len(rpcs)} RPC + {len(edge)} Edge Function(s) descubiertas (revisar)",
        severity="info",
        cwe="CWE-200",
        owasp="WSTG-INFO-01",
        injection_point=InjectionPoint(location="path", name="-", base_value="", request_template=request),
        evidence=[Evidence(type="status", data=detail[:300], confidence="high")],
        request=request,
        response=HttpResponse(status_code=0, url=target, text=detail),
        remediation=(
            "Revisa cada función: las RPC SECURITY DEFINER y las Edge Functions deben validar la "
            "autorización del llamante; no confíes en que solo el frontend las invoque."
        ),
    )


def _supabase_write_coverage_finding(target: str, n_tested: int, n_identities: int, n_writable: int) -> Finding:
    """Info advisory documenting the write-side RLS test, so the report itemizes what was tried."""
    request = HttpRequest(method="POST", url=target)
    verdict = "sin tablas escribibles" if n_writable == 0 else f"{n_writable} tabla(s) escribible(s)"
    detail = (
        f"RLS de escritura: INSERT probado de forma concluyente en {n_tested} tabla(s) por "
        f"{n_identities} identidad(es); {verdict}."
    )
    return Finding(
        id="supabase-write-coverage",
        rule_id="supabase-write-profile",
        name=f"Cobertura de escritura Supabase: {n_tested} tabla(s) probadas, {n_writable} escribible(s)",
        severity="info",
        cwe="CWE-200",
        owasp="WSTG-INFO-01",
        injection_point=InjectionPoint(location="body", name="-", base_value="", request_template=request),
        evidence=[Evidence(type="status", data=detail[:300], confidence="high")],
        request=request,
        response=HttpResponse(status_code=0, url=target, text=detail),
        remediation="Documenta la cobertura del test de escritura. 0 escribibles = ninguna identidad pudo INSERT.",
    )


def _supabase_bola_coverage_finding(target: str, n_comparable: int, n_pairs: int, n_leaks: int) -> Finding:
    """Info advisory documenting the cross-user BOLA test — crucially, whether it had anything to compare."""
    request = HttpRequest(method="GET", url=target)
    if n_comparable == 0:
        detail = (
            f"BOLA user-vs-user: entre {n_pairs} par(es) de usuarios no se hallaron filas privadas de uno que "
            "el otro no viera, así que no hubo nada que comparar — el 'sin fuga' NO es concluyente aquí."
        )
        name = "Cobertura BOLA Supabase: 0 comparaciones posibles (no concluyente)"
    else:
        verdict = "sin fugas" if n_leaks == 0 else f"{n_leaks} fuga(s)"
        detail = (
            f"BOLA user-vs-user: {n_comparable} tabla(s) con filas propias de otro usuario comprobadas entre "
            f"{n_pairs} par(es) de usuarios; {verdict}."
        )
        name = f"Cobertura BOLA Supabase: {n_comparable} comparación(es), {n_leaks} fuga(s)"
    return Finding(
        id="supabase-bola-coverage",
        rule_id="supabase-bola-profile",
        name=name,
        severity="info",
        cwe="CWE-200",
        owasp="WSTG-INFO-01",
        injection_point=InjectionPoint(location="query", name="id", base_value="", request_template=request),
        evidence=[Evidence(type="differential", data=detail[:300], confidence="high")],
        request=request,
        response=HttpResponse(status_code=0, url=target, text=detail),
        remediation=(
            "Documenta la cobertura del BOLA. Si 0 comparaciones, crea datos en ambas cuentas de prueba "
            "para que haya filas privadas que comparar y el resultado sea concluyente."
        ),
    )


def _waf_blocking_finding(target: str, ratio: float, blocked: int, total: int) -> Finding:
    """An advisory (not a vuln) that the target's WAF blocked most requests, so results are unreliable."""
    request = HttpRequest(method="GET", url=target)
    detail = (
        f"{blocked}/{total} respuestas ({ratio * 100:.0f}%) fueron bloqueos del WAF/CDN (403/429/503). "
        "El escaneo automático no está viendo la aplicación real, así que sus hallazgos NO son fiables."
    )
    return Finding(
        id="waf-blocking-scan",
        rule_id="waf-blocking",
        name="El WAF/CDN está bloqueando el escaneo (resultados no fiables)",
        severity="info",
        cwe="CWE-200",
        owasp="WSTG-INFO-01",
        injection_point=InjectionPoint(location="header", name="-", base_value="", request_template=request),
        evidence=[Evidence(type="response_match", data=detail, confidence="high")],
        request=request,
        response=HttpResponse(status_code=0, url=target, text=detail),
        remediation=(
            "El WAF (p. ej. Cloudflare) rechaza las peticiones automáticas. Para escanear la app real: usa "
            "--engine both (headless sigiloso), y sobre todo pasa la cookie de tu navegador que superó el "
            "challenge con --auth-cookie \"cf_clearance=...\" + --user-agent \"<tu UA exacto>\", lanzándolo "
            "desde tu misma IP. Si no, prueba con una sesión autenticada real o testing manual."
        ),
    )


def _looks_like_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def _resolve_ip(host: str) -> str:
    """Resolve ``host`` to a single IP (for a vhost host-override). Empty string if it doesn't resolve."""
    import socket

    if not host:
        return ""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return ""
    return str(infos[0][4][0]) if infos else ""


# Second-level public suffixes where the registrable domain is the last THREE labels.
_TWO_LEVEL_TLDS = frozenset(
    {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
     "com.br", "com.mx", "co.in", "com.tr", "com.sg", "com.hk", "co.za", "com.ar"}
)


def _base_domain(host: str) -> str:
    """Best-effort registrable domain, so we enumerate siblings (api., admin.) not sub-sub-domains.

    A heuristic (no public-suffix list dependency); the scope gate is the real safety net, so an
    over-broad guess only produces candidates that are then filtered by scope anyway.
    """
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _TWO_LEVEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


async def _discover_scan_roots(
    client: HttpClient,
    target: str,
    depth: str,
    progress: _ProgressAdapter,
    wordlist_path: str = "",
    seeds: Sequence[str] = (),
    recursion: int = -1,
    auto: bool = True,
    permute: bool = False,
) -> list[str]:
    """Expand a target URL into itself + every live, in-scope host we can find.

    ``auto`` runs the automatic sweep (wordlist + passive + recursion); ``seeds`` are known hosts always
    probed and scanned (and recursed into). ``permute`` mutates the found subdomains and probes those
    too. With ``auto=False`` only the seeds are probed (no sweep)."""
    from urllib.parse import urlsplit

    from dastcore.discovery.permutations import load_permutation_words

    host = urlsplit(target).hostname or ""
    roots = [target]
    base = "" if (not host or _looks_like_ip(host)) else _base_domain(host)
    if not base and not seeds:
        return roots  # a bare IP with no seeds has nothing to expand
    progress.status("Descubriendo subdominios…" if auto else "Sondeando hosts semilla…")
    words = load_subdomain_wordlist(depth, wordlist_path or None) if auto else []
    depth_recursion = subdomain_recursion_depth(depth) if recursion < 0 else recursion
    found = await SubdomainDiscoverer(
        client,
        wordlist=words,
        seeds=list(seeds),
        recursion_depth=depth_recursion,
        use_passive=auto,
        use_external=auto,
        use_permutations=permute and auto,
        permutation_words=load_permutation_words() if (permute and auto) else [],
    ).discover(base)
    seen = {host}
    for discovered_host in found:
        if discovered_host.host not in seen:
            seen.add(discovered_host.host)
            roots.append(discovered_host.url)
    progress.status(f"Superficie a escanear: {len(roots)} host(s).")
    return roots


# Per-isolated-check wall-clock cap (seconds). A check that hangs on a stuck socket/DNS to an
# unroutable host never attempts a new request, so the request-level budget can't catch it; this
# bounds every phase() so one hung check can't freeze the whole scan. The core active scan is exempt.
_PHASE_TIMEOUT_S: float = 180.0


async def _run_scan(
    config: ScanConfig,
    max_pages: int,
    engine: str,
    oast_mode: str = "off",
    oast_server: str = "",
    openapi_url: str = "",
    graphql_url: str = "",
    state: _ResumeState | None = None,
    budget: _Budget | None = None,
    progress: _ProgressAdapter | None = None,
    stored_scan: bool = False,
    waf_evasion: bool = False,
    test_race: bool = False,
    test_csrf: bool = False,
    test_proto_pollution: bool = False,
    test_cache_poisoning: bool = False,
    test_weak_creds: bool = False,
    test_upload: bool = False,
    test_dos: bool = False,
    test_smuggling: bool = False,
    prove_impact: bool = False,
    discover_subdomains: bool = False,
    discover_content: bool = False,
    discover_ports: bool = False,
    discover_vhosts: bool = False,
    osint: bool = False,
    screenshots: bool = False,
    screenshots_dir: str = "",
    user_agent: str = "",
    proxy: str = "",
    bug_bounty: bool = False,
    attribution: dict[str, str] | None = None,
    discover_depth: str = "aggressive",
    content_wordlist: str = "",
    subdomain_wordlist: str = "",
    seed_hosts: Sequence[str] = (),
    seed_paths: Sequence[str] = (),
    subdomain_recursion: int = -1,
    use_permutations: bool = False,
    use_historical: bool = False,
    use_js: bool = False,
    mine_params: bool = False,
    findings_log: str = "",
    surface: dict[str, Any] | None = None,
    ai_payloads: AiPayloadGenerator | None = None,
    on_finding: Callable[[Finding], None] | None = None,
    interactive: bool = False,
    supabase_frontend: str = "",
    supabase_tables: Sequence[str] = (),
    supabase_write_test: bool = False,
) -> list[Finding]:
    rules = load_rules()
    session = SessionManager(config.auth) if config.auth.type != "none" else None
    target = str(config.target)
    budget = budget or _Budget(None, None)
    progress = progress or _ProgressAdapter(None)

    # Bug-bounty mode also enforces compliance with strict program rules ("no brute force / no DoS / no
    # shells / no data exfiltration"): hard-disable the checks that would break them, even if a profile or
    # flag turned them on. Findings-filtering happens later; this gates the *tests we run*.
    if bug_bounty and (test_weak_creds or test_dos or test_upload or prove_impact):
        _scan_log.info(
            "Modo bug bounty: desactivo checks peligrosos (weak-creds/brute-force, DoS, upload, "
            "prove-impact) para cumplir las reglas del programa."
        )
        test_weak_creds = test_dos = test_upload = prove_impact = False

    # Defined up front so a budget/time cap (BudgetExceededError) can stop the scan mid-flight and still
    # report everything gathered so far, instead of crashing with no report.
    discovered: dict[str, HttpRequest] = {}
    dom_findings: list[Finding] = []
    extra_findings: list[Finding] = []
    active_passive: list[Finding] = []
    dns_records: dict[str, RecordSet] = {}  # host -> DNS records; feeds the takeover check its CNAMEs
    budget_hit = False
    sink = FindingSink(findings_log).open() if findings_log else None  # persist findings as they're found
    failed_phases: list[str] = []

    async def phase(name: str, coro: Awaitable[list[Any]], *, timeout: float | None = _PHASE_TIMEOUT_S) -> list[Any]:
        """Run one check in isolation: a bug, an odd response, OR a hang in it must never abort/freeze
        the whole scan.

        A budget cap still stops the scan (it's the intended soft stop, handled upstream). Any other
        error is logged, recorded, and skipped so every other check still runs. A per-phase wall-clock
        ``timeout`` (default 180s) cancels a check that hangs — a stuck socket/DNS to an unroutable host
        (e.g. cloud-metadata SSRF, takeover DNS) never attempts a new request, so the request-level
        budget can't catch it and the scan would otherwise freeze forever. Any findings a check returns
        are streamed to the sink immediately, so a hard interruption loses nothing."""
        try:
            result = await (asyncio.wait_for(coro, timeout) if timeout is not None else coro)
        except BudgetExceededError:
            raise
        except Exception as exc:  # noqa: BLE001 — isolate: log it loudly, skip this one, keep going
            is_timeout = isinstance(exc, (asyncio.TimeoutError, TimeoutError))
            _scan_log.warning(
                "Comprobación '%s' omitida por %s: %s: %s",
                name,
                "timeout (posible cuelgue)" if is_timeout else "un error",
                type(exc).__name__,
                exc,
                exc_info=not is_timeout,
            )
            failed_phases.append(name)
            return []
        if isinstance(result, list) and result and isinstance(result[0], Finding):
            if sink is not None:
                sink.write(result)  # persist findings the moment the check produces them
            if on_finding is not None:
                for finding in result:  # surface each finding live (e.g. the web panel's feed)
                    on_finding(finding)
        return result

    oast = _build_oast_provider(oast_mode, oast_server)
    if oast is not None:
        await oast.start()
    try:
        async with _make_client(
            config, budget, session, user_agent=user_agent, proxy=proxy, attribution=attribution
        ) as client:
            if session is not None and session.can_relogin:
                if not await session.ensure_logged_in(client, initial=True):
                    raise SessionLoginError("El login inicial falló: revisa credenciales / URL de login.")

            # Full-surface scanning: expand the single target into every in-scope host we can find,
            # then crawl + brute-force paths on each. Both stages are opt-in and scope-enforced.
            scan_roots = [target]
            seed_host_pool = list(seed_hosts)
            historical_requests: list[HttpRequest] = []
            if use_historical:
                from urllib.parse import urlsplit

                thost = urlsplit(target).hostname or ""
                if thost and not _looks_like_ip(thost):
                    progress.status("Minando URLs históricas (Wayback · Common Crawl · urlscan · OTX)…")
                    hist_hosts: set[str] = set()
                    reqs: list[HttpRequest] = []
                    for hist_url in await gather_historical_urls(_base_domain(thost)):  # passive: hits the archive
                        req = url_to_request(hist_url)
                        if req is None or not client.is_in_scope(req.url):  # scope-gate before anything is scanned
                            continue
                        found_host = urlsplit(req.url).hostname
                        if found_host:
                            hist_hosts.add(found_host)
                        reqs.append(req)
                    historical_requests = prioritise(reqs, limit=3000)  # parametrised URLs first, then capped
                    seed_host_pool.extend(hist_hosts)
                    progress.status(f"Histórico: {len(historical_requests)} endpoint(s) en scope, {len(hist_hosts)} host(s).")
                    if surface is not None:
                        surface["historical"] = {"endpoints": len(historical_requests), "hosts": sorted(hist_hosts)}

            if discover_subdomains or seed_host_pool:
                scan_roots = await _discover_scan_roots(
                    client, target, discover_depth, progress, subdomain_wordlist,
                    seeds=seed_host_pool, recursion=subdomain_recursion, auto=discover_subdomains,
                    permute=use_permutations,
                )
            for historical_req in historical_requests:  # historical endpoints (with their params) get scanned
                discovered.setdefault(historical_req.signature(), historical_req)

            if discover_subdomains or discover_content or discover_ports:
                from urllib.parse import urlsplit as _urlsplit

                # Port discovery: connect-scan each root host and add the extra HTTP services (8080,
                # 8443, 9200…) as scan roots. Scope-gated (host:port must be in scope) and best-effort.
                if discover_ports:
                    progress.status("Escaneando puertos (servicios HTTP no estándar)…")
                    port_hosts = sorted(
                        {h for r in list(scan_roots) if (h := (_urlsplit(r).hostname or ""))}
                    )
                    for phost in port_hosts:
                        try:
                            for port_root in await discover_http_ports(client, phost):
                                if port_root not in scan_roots:
                                    scan_roots.append(port_root)
                        except Exception:  # noqa: BLE001 — port discovery is best-effort, never fatal
                            _scan_log.warning("Escaneo de puertos omitido para %s", phost, exc_info=True)

            if discover_subdomains or discover_content:
                # DNS enrichment: reverse-resolve any in-scope CIDR ranges into real hosts (added as
                # scan roots), then resolve each host's records. The CNAMEs feed the takeover check;
                # MX/TXT/NS enrich the surface report. All fail-open and scope-gated.
                from urllib.parse import urlsplit as _urlsplit

                cidrs = [p for p in config.scope.allow_domains if "/" in p]
                if cidrs:
                    progress.status("Barrido inverso (PTR) de rangos en scope…")
                    try:
                        for ptr_host in sorted(await ptr_sweep(cidrs, client.is_asset_in_scope)):
                            root = f"https://{ptr_host}"
                            if root not in scan_roots:
                                scan_roots.append(root)
                    except Exception:  # noqa: BLE001 — PTR enrichment is best-effort, never fatal
                        _scan_log.warning("Barrido PTR omitido por un error", exc_info=True)

                root_hosts = sorted(
                    {
                        h
                        for r in scan_roots
                        if (h := (_urlsplit(r).hostname or "")) and not _looks_like_ip(h)
                    }
                )
                if root_hosts:
                    progress.status("Resolviendo registros DNS (CNAME · MX · TXT · NS)…")
                    try:
                        dns_records = await gather_dns_records(root_hosts)
                    except Exception:  # noqa: BLE001 — DNS enrichment is best-effort, never fatal
                        _scan_log.warning("Enriquecimiento DNS omitido por un error", exc_info=True)
                    if surface is not None and dns_records:
                        surface["dns"] = {
                            host: {"cname": rs.cname, "mx": rs.mx, "ns": rs.ns, "txt": rs.txt}
                            for host, rs in dns_records.items()
                            if rs.cname or rs.mx or rs.ns or rs.txt
                        }

                    # ASN footprint: from the resolved IPs, learn the org's autonomous system and its
                    # announced prefixes (RIPEstat, passive). Purely informational — never scanned here.
                    seed_ips = sorted({ip for rs in dns_records.values() for ip in rs.a})
                    if seed_ips:
                        progress.status("Consultando ASN y prefijos del objetivo (RIPEstat)…")
                        try:
                            intel = await gather_asn_intel(seed_ips)
                            extra_findings.extend(asn_intel_findings(intel, target))
                            if surface is not None and intel.asns:
                                surface["asn"] = {
                                    "asns": intel.asns, "holders": intel.holders, "prefixes": intel.prefixes
                                }
                        except Exception:  # noqa: BLE001 — ASN lookup is best-effort, never fatal
                            _scan_log.warning("Consulta ASN omitida por un error", exc_info=True)

                # Favicon fingerprint per root — identifies/correlates the stack behind each host.
                favicons: dict[str, dict[str, object]] = {}
                for root in scan_roots:
                    info = await probe_favicon(client, root)
                    if info is not None:
                        favicons[root] = {"hash": info.hash, "product": info.product}
                if surface is not None and favicons:
                    surface["favicon"] = favicons

            if discover_vhosts:
                # Host-header fuzzing per root: find virtual hosts not published in DNS. Every request
                # goes to the in-scope URL and every candidate Host is scope-gated. Each vhost found is
                # then added as a full scan root: a host override points its requests at the serving IP
                # (Host/SNI keep the vhost name), so the crawler + every detector scan it like any host.
                from urllib.parse import urlsplit as _urlsplit_vhost

                progress.status("Fuzzing de virtual hosts (cabecera Host)…")
                vhost_words = load_subdomain_wordlist(discover_depth, subdomain_wordlist or None)
                base = _base_domain(_urlsplit_vhost(target).hostname or "")
                vhost_candidates = [f"{word}.{base}" for word in vhost_words] if base else []
                if vhost_candidates:
                    seen_vhosts = set()
                    for root in list(scan_roots):
                        root_parts = _urlsplit_vhost(root)
                        root_host = root_parts.hostname or ""
                        try:
                            found_vhosts = await VhostDiscoverer(client, candidates=vhost_candidates).discover(root)
                        except Exception:  # noqa: BLE001 — vhost fuzzing is best-effort, never fatal
                            _scan_log.warning("Fuzzing de vhosts omitido para %s", root, exc_info=True)
                            continue
                        fresh = [v for v in found_vhosts if v.host not in seen_vhosts]
                        if not fresh:
                            continue
                        # The IP serving this root also serves its vhosts — resolve it once and route
                        # the vhost roots there so they are actually reachable (they aren't in DNS).
                        serving_ip = root_host if _looks_like_ip(root_host) else await _resolve_ip(root_host)
                        for vhost in fresh:
                            seen_vhosts.add(vhost.host)
                            if serving_ip:
                                client.add_host_override(vhost.host, serving_ip)
                                vhost_root = f"{root_parts.scheme}://{vhost.host}/"
                                if vhost_root not in scan_roots:
                                    scan_roots.append(vhost_root)
                        extra_findings.extend(vhost_findings(root, fresh))
                    if surface is not None and seen_vhosts:
                        surface["vhosts"] = sorted(seen_vhosts)

            if osint:
                # Organisational OSINT (passive): public-code references + world-listable cloud buckets,
                # derived only from the scope's own domain labels. Reports findings; never scans them.
                progress.status("OSINT organizacional (código público · buckets cloud)…")
                osint_domains = sorted(
                    {
                        _base_domain(p) for p in config.scope.allow_domains if "/" not in p and "." in p
                    }
                )
                labels = sorted({d.split(".", 1)[0] for d in osint_domains if d})
                try:
                    for osint_domain in osint_domains:
                        extra_findings.extend(
                            github_findings(osint_domain, await github_code_search(osint_domain))
                        )
                    if labels:
                        extra_findings.extend(bucket_findings(await check_buckets(labels)))
                except Exception:  # noqa: BLE001 — OSINT is best-effort, never fatal
                    _scan_log.warning("OSINT omitido por un error", exc_info=True)

            if surface is not None:
                surface["roots"] = list(scan_roots)
                surface.setdefault("content", {})

            if screenshots:
                # Visual triage: one headless screenshot per host. Best-effort — a missing browser just
                # skips it, never breaks the scan.
                progress.status("Capturando screenshots (headless) de cada host…")
                try:
                    shots = await _capture_screenshots(
                        config, client, scan_roots, screenshots_dir or "dastcore-screenshots"
                    )
                    if surface is not None and shots:
                        surface["screenshots"] = shots
                    _scan_log.info("Screenshots capturadas: %d", len(shots))
                except HeadlessUnavailableError:
                    progress.status("Screenshots omitidas: Playwright/Chromium no disponible.")
                except Exception:  # noqa: BLE001 — screenshots are best-effort, never fatal
                    _scan_log.warning("Captura de screenshots omitida por un error", exc_info=True)

            if engine in ("http", "both"):
                for root in scan_roots:
                    progress.status(f"Crawleando (HTTP estático) {root}…")
                    try:
                        for req in await HttpCrawler(client, max_pages=max_pages).crawl(root):
                            discovered.setdefault(req.signature(), req)
                    except httpx.HTTPError:
                        progress.status(f"{root} no accesible (error de red), lo salto…")

            if engine in ("headless", "both"):
                for root in scan_roots:
                    progress.status(f"Crawleando (headless / SPA) {root}…")
                    try:
                        headless_reqs, root_dom = await _run_headless(
                            config, client, root, max_pages, user_agent, proxy, interactive=interactive
                        )
                    except httpx.HTTPError:
                        continue  # a flaky host must not abort the whole multi-host scan
                    dom_findings.extend(root_dom)
                    if sink is not None:
                        sink.write(root_dom)
                    for req in headless_reqs:
                        discovered.setdefault(req.signature(), req)

            if discover_content or seed_paths:
                # Manual seed paths are always tried (first, so they lead the sweep); the auto wordlist
                # + extensions + recursion only run when content discovery is enabled.
                seed_words = [p.strip().lstrip("/") for p in seed_paths if p.strip()]
                base_words = load_content_wordlist(discover_depth, content_wordlist or None) if discover_content else []
                content_words = list(dict.fromkeys(seed_words + base_words))
                extensions = content_extensions(discover_depth) if discover_content else []
                recursion = content_recursion_depth(discover_depth) if discover_content else 1
                from urllib.parse import urljoin as _urljoin_dir
                from urllib.parse import urlsplit as _urlsplit_dir

                probed_dirs: set[str] = set()  # directories already swept for sensitive files (deduped)
                dir_probe_budget = 200  # cap so a huge dirbust doesn't multiply into an unbounded sweep
                for root in scan_roots:
                    progress.status(f"Descubriendo directorios y rutas (dirbusting) en {root}…")
                    endpoints = await ContentDiscoverer(
                        client, wordlist=content_words, extensions=extensions, recursion_depth=recursion
                    ).discover(root)
                    if surface is not None:
                        surface["content"][root] = [e.url for e in endpoints]
                    for endpoint in endpoints:
                        # A shallow crawl of each hidden page extracts its own links/forms/params, so the
                        # detectors actually get something to test — not just a bare URL.
                        for req in await HttpCrawler(client, max_pages=8, use_robots=False).crawl(endpoint.url):
                            discovered.setdefault(req.signature(), req)

                    # Per-directory leak sweep: probe each discovered directory for its OWN sensitive
                    # files (/admin/.env, /backup/config.php.bak, /api/.git/config…), not just the site
                    # root. Complements the injection scan (which already covers every route's params).
                    for endpoint in endpoints:
                        if len(probed_dirs) >= dir_probe_budget:
                            break
                        directory = _urljoin_dir(endpoint.url, ".")  # the endpoint's containing directory
                        if _urlsplit_dir(directory).path in ("", "/") or directory in probed_dirs:
                            continue  # the origin root is already swept per-root; skip dupes
                        probed_dirs.add(directory)
                        extra_findings.extend(
                            await phase("dir-sensitive-files", probe_sensitive_files(client, directory, under_directory=True))
                        )

            # robots.txt / sitemap.xml: mine the paths the site advertises (admin panels, exports,
            # staging routes) — high-signal endpoints a blind crawler never reaches. Cheap + always on.
            for root in scan_roots:
                for req in await phase("recon-paths", ReconPathDiscoverer(client).discover(root)):
                    discovered.setdefault(req.signature(), req)

            if use_js:
                # Modern SPAs hide their API in JS bundles — extract those endpoints and scan them too.
                # harvest_maps also pulls each bundle's .map sourcemap to mine the original source.
                for root in scan_roots:
                    progress.status(f"Extrayendo endpoints de JavaScript en {root}…")
                    for req in await JsEndpointDiscoverer(client, harvest_maps=True).discover(root):
                        discovered.setdefault(req.signature(), req)

            if discover_content:
                # Tech-aware probing: fingerprint each host's stack and probe the paths that stack exposes
                # (WordPress /wp-json, Spring /actuator, Laravel /.env…) — far higher signal than a generic
                # wordlist. Calibrated per host, scope-gated.
                for root in scan_roots:
                    progress.status(f"Rutas según la tecnología detectada en {root}…")
                    for req in await phase("tech-paths", discover_tech_paths(client, root)):
                        discovered.setdefault(req.signature(), req)

            if discover_content or discover_subdomains:
                # The API is the real surface: auto-find OpenAPI/GraphQL schemas and ingest every endpoint.
                progress.status("Detectando esquemas de API (OpenAPI/GraphQL)…")
                try:
                    found_openapi, found_graphql = await probe_api_schemas(client, scan_roots)
                except httpx.HTTPError:
                    found_openapi, found_graphql = [], []
                for schema_url in found_openapi:
                    for req in await phase("openapi-ingest", fetch_and_parse_openapi(client, schema_url, target)):
                        discovered.setdefault(req.signature(), req)
                for gql_url in found_graphql:
                    for req in await phase("graphql-ingest", discover_graphql(client, gql_url)):
                        discovered.setdefault(req.signature(), req)
                    extra_findings.extend(await phase("graphql-introspection", check_graphql_introspection(client, gql_url)))
                    extra_findings.extend(await phase("graphql-checks", run_graphql_checks(client, gql_url)))
                    extra_findings.extend(await phase("graphql-arg-injection", check_graphql_arg_injection(client, gql_url)))
                if surface is not None and (found_openapi or found_graphql):
                    surface["api"] = {"openapi": found_openapi, "graphql": found_graphql}

            if openapi_url:
                progress.status("Ingiriendo OpenAPI…")
                for req in await phase("openapi-ingest", fetch_and_parse_openapi(client, openapi_url, target)):
                    discovered.setdefault(req.signature(), req)

            if supabase_frontend or supabase_tables or is_supabase_project(target):
                # A Supabase project's OpenAPI schema is service_role-only, so the table list can't be
                # read from the API. Enumerate it autonomously — pg_graphql introspection + a PostgREST
                # existence oracle — plus any front-end mining / explicit list, then probe each table so
                # the authz detector can test RLS anon-vs-authed. Auto-runs on any *.supabase.co target.
                progress.status("Perfilando Supabase (GraphQL introspection + enum PostgREST)…")
                supa = SupabaseDiscoverer(client)
                # profile() returns a SupabaseProfile (not a Finding list), so it isn't wrapped in phase();
                # isolate its errors here so a profiling hiccup never aborts the whole scan.
                try:
                    supa_prof = await supa.profile(
                        target,
                        frontend_url=supabase_frontend,
                        graphql_url=graphql_url_for(target),
                        extra_tables=tuple(supabase_tables),
                    )
                except BudgetExceededError:
                    raise
                except Exception as exc:  # noqa: BLE001 — isolate: a profiling error must not abort the scan
                    _scan_log.warning(
                        "Perfilado Supabase omitido por un error: %s: %s", type(exc).__name__, exc, exc_info=True
                    )
                    supa_prof = SupabaseProfile()
                added = 0
                for req in supa_prof.probes:
                    if client.is_in_scope(req.url):
                        discovered.setdefault(req.signature(), req)
                        added += 1
                extra_findings.append(_supabase_coverage_finding(target, supa_prof))  # self-documenting report
                if supa_prof.service_role_exposed:  # a leaked service_role key = full RLS bypass (critical)
                    extra_findings.append(_supabase_service_role_finding(target, supa_prof.service_role_exposed))
                # GET-only surface probes (Storage buckets, Auth signup config) — safe, auto-run.
                extra_findings.extend(await phase("supabase-aux", probe_supabase_aux(client, target)))
                if supa_prof.rpcs or supa_prof.edge_functions:  # surface the functions for manual review
                    extra_findings.append(
                        _supabase_functions_finding(target, supa_prof.rpcs, supa_prof.edge_functions)
                    )
                progress.status(f"Supabase: {added} tabla(s) confirmadas para probar RLS/authz")
                if supabase_write_test and supa_prof.tables:
                    # Opt-in: also test write-side RLS (safe INSERT probe). Off by default because it can
                    # mutate; here the operator asked for it explicitly.
                    progress.status("Probando RLS de escritura (INSERT seguro, opt-in)…")
                    extra_findings.extend(
                        await phase(
                            "supabase-write-rls",
                            _run_supabase_write_test(config, target, supa_prof.tables, budget),
                        )
                    )
                if supa_prof.tables and sum(1 for i in config.identities if i.auth.type in _USER_AUTH_TYPES) >= 2:
                    # Cross-user BOLA (read-only): auto-runs once two real user identities exist.
                    progress.status("Probando BOLA user-vs-user (acceso cruzado por id)…")
                    extra_findings.extend(
                        await phase("supabase-bola", _run_supabase_bola(config, target, supa_prof.tables, budget))
                    )

            if graphql_url:
                progress.status("Introspeccionando GraphQL…")
                for req in await phase("graphql-ingest", discover_graphql(client, graphql_url)):
                    discovered.setdefault(req.signature(), req)
                extra_findings.extend(await phase("graphql-introspection", check_graphql_introspection(client, graphql_url)))
                extra_findings.extend(await phase("graphql-checks", run_graphql_checks(client, graphql_url)))
                extra_findings.extend(await phase("graphql-arg-injection", check_graphql_arg_injection(client, graphql_url)))

            progress.status("Probando ficheros sensibles…")
            for root in scan_roots:
                extra_findings.extend(await phase("sensitive-files", probe_sensitive_files(client, root)))

            progress.status("Fingerprint de tecnología + WAF…")
            for root in scan_roots:
                extra_findings.extend(await phase("fingerprint-waf", fingerprint_and_waf(client, root)))
                extra_findings.extend(await phase("trace-method", check_trace_method(client, root)))
                extra_findings.extend(await phase("dangerous-methods", check_dangerous_methods(client, root)))
                extra_findings.extend(await phase("spa-awareness", run_spa_check(client, root, engine)))
                extra_findings.extend(await phase("tls-info", run_tls_checks(root)))
            if config.auth.type == "bearer" and config.auth.bearer_token and looks_like_jwt(config.auth.bearer_token):
                jwt = config.auth.bearer_token
                extra_findings.extend(await phase("jwt-none", check_jwt_none_acceptance(client, target, jwt)))
                extra_findings.extend(await phase("jwt-weak-secret", check_jwt_weak_secret(client, target, jwt)))
                extra_findings.extend(await phase("jwt-no-verify", check_jwt_signature_not_verified(client, target, jwt)))
                extra_findings.extend(await phase("jwt-kid", check_jwt_kid_injection(client, target, jwt)))
                extra_findings.extend(await phase("jwt-jwk", check_jwt_jwk_injection(client, target, jwt)))
                extra_findings.extend(await phase("jwt-x5c", check_jwt_x5c_injection(client, target, jwt)))
                extra_findings.extend(await phase("jwt-alg-confusion", check_jwt_algorithm_confusion(client, target, jwt)))
                extra_findings.extend(await phase("jwt-key-ssrf", check_jwt_key_url_ssrf(client, target, jwt, oast)))

            scanner = Scanner(
                client,
                rules,
                oast=oast,
                concurrency=config.rate_limit.max_concurrency,
                stored_scan=stored_scan,
                waf_evasion=waf_evasion,
                ai_payloads=ai_payloads,
            )
            if mine_params:
                # Find undocumented query params on the discovered endpoints — each is a new injection point.
                progress.status("Descubriendo parámetros ocultos (estilo Arjun)…")
                seeds_for_mining = [HttpRequest(method="GET", url=r) for r in scan_roots] + list(discovered.values())
                for enriched in await mine_hidden_params(client, seeds_for_mining, load_param_wordlist(discover_depth)):
                    discovered.setdefault(enriched.signature(), enriched)

            if discovered:
                # A SPA's real surface is its JSON API: endpoints discovered (JS/historical/dirbust) as
                # bare GETs that 404/405. Probe each for the verb + body it actually takes so the scanner
                # injects into its JSON fields — otherwise the whole API goes untested. Part of the
                # normal active scan (which every profile runs), so it applies on every scan.
                progress.status("Activando endpoints de API (método + cuerpo JSON)…")
                activated = await phase("activate-endpoints", activate_endpoints(client, list(discovered.values())))
                if activated:
                    _scan_log.info("Endpoints de API activados para inyección: %d", len(activated))
                for req in activated:
                    discovered.setdefault(req.signature(), req)

            all_requests = list(discovered.values())
            extra_findings.extend(await phase("shellshock", check_shellshock(client, all_requests)))
            extra_findings.extend(await phase("nosql", run_nosql_checks(client, all_requests)))
            extra_findings.extend(await phase("mass-assignment", run_mass_assignment_checks(client, all_requests)))
            extra_findings.extend(await phase("js-secrets", run_js_secret_scan(client, all_requests)))
            extra_findings.extend(
                await phase(
                    "subdomain-takeover",
                    run_subdomain_takeover_check(client, target, all_requests, dns_records=dns_records),
                )
            )
            extra_findings.extend(await phase("deserialization", run_deserialization_checks(client, all_requests, oast)))
            extra_findings.extend(await phase("oauth", run_oauth_checks(client, all_requests)))
            extra_findings.extend(await phase("access-bypass", run_access_bypass_checks(client, all_requests)))
            extra_findings.extend(await phase("user-enumeration", run_user_enumeration_checks(client, all_requests)))
            extra_findings.extend(await phase("reset-poisoning", run_reset_poisoning_checks(client, all_requests)))
            extra_findings.extend(await phase("ssrf-cloud-metadata", run_cloud_ssrf_checks(client, all_requests)))
            if config.auth.type != "none":
                # Web cache deception needs an authenticated session + an anonymous client to prove a
                # cached authenticated page is served cross-user.
                async with _make_client(config, budget) as anon_client:
                    extra_findings.extend(await phase(
                        "web-cache-deception", run_cache_deception_checks(client, anon_client, all_requests)))
            extra_findings.extend(await phase("response-splitting", run_response_splitting_checks(client, all_requests)))
            extra_findings.extend(await phase("ssi", run_ssi_checks(client, all_requests)))
            extra_findings.extend(await phase("ssti-error", run_ssti_error_checks(client, all_requests)))
            extra_findings.extend(await phase("code-injection", run_code_injection_checks(client, all_requests)))
            if config.auth.type == "form" and config.auth.form is not None:
                # Fresh visitor (empty jar): capture the pre-auth session, then confirm it isn't rotated.
                async with _make_client(config, budget) as fresh_client:
                    extra_findings.extend(await phase("session-fixation", check_session_fixation(fresh_client, config.auth.form)))
            if test_weak_creds and config.auth.form is not None:
                progress.status("Probando credenciales por defecto…")
                async with _make_client(config, budget) as fresh_client:
                    extra_findings.extend(await phase("weak-credentials", run_weak_credentials_check(fresh_client, config.auth.form)))
            if test_race:
                progress.status("Probando race conditions (single-packet)…")
                extra_findings.extend(await phase("race", run_race_checks(client, all_requests)))
            if test_csrf:
                progress.status("Probando CSRF (enforcement de token)…")
                extra_findings.extend(await phase("csrf", run_csrf_checks(client, all_requests)))
            if test_proto_pollution:
                progress.status("Probando prototype pollution (json spaces)…")
                extra_findings.extend(await phase("proto-pollution", run_proto_pollution_checks(client, all_requests)))
            if test_cache_poisoning:
                progress.status("Probando web cache poisoning…")
                extra_findings.extend(await phase("cache-poisoning", run_cache_poisoning_checks(client, all_requests)))
            if test_upload:
                progress.status("Probando subida de ficheros…")
                extra_findings.extend(await phase("file-upload", run_file_upload_checks(client, all_requests)))
            if test_dos:
                progress.status("Probando XML entity expansion…")
                extra_findings.extend(await phase("xml-expansion", run_xml_expansion_checks(client, all_requests)))
                progress.status("Probando ReDoS (backtracking catastrófico)…")
                extra_findings.extend(await phase("redos", run_redos_checks(client, all_requests)))
            if test_smuggling:
                progress.status("Probando HTTP request smuggling (CL.TE)…")
                extra_findings.extend(await phase("smuggling", run_smuggling_checks(client, all_requests)))
            active_passive = await phase(
                # The core injection scan is exempt from the per-phase timeout: it is already bounded by
                # per-request timeouts + the overall budget (checked between requests), and a large legit
                # scan can outlast any fixed per-phase cap.
                "active-scan",
                _scan_with_optional_resume(scanner, all_requests, state, progress, sink=sink),
                timeout=None,
            )

            # WAF-block advisory: if the target's WAF/CDN rejected most requests, the scan didn't see the
            # real app — say so loudly instead of letting the empty/partial result look like "all clear".
            waf_ratio = client.waf_block_ratio()
            if waf_ratio >= 0.5 and client.response_count >= 10:
                progress.status(
                    f"⚠ El WAF bloqueó el {waf_ratio * 100:.0f}% de las peticiones — resultados no fiables."
                )
                extra_findings.append(
                    _waf_blocking_finding(target, waf_ratio, client.blocked_count, client.response_count)
                )

            if prove_impact:
                progress.status("Probando impacto de los hallazgos confirmados…")
                await phase("prove-impact", _prove_impact_isolated(client, active_passive + extra_findings))
    except BudgetExceededError:
        # A --max-requests / --time-budget cap is a soft stop: keep what we found, don't crash.
        budget_hit = True
        progress.status("Presupuesto agotado (tiempo/peticiones): reportando lo encontrado hasta ahora…")
    except (httpx.HTTPError, OSError):
        # A network blip mid-scan must not discard everything already gathered. But if NOTHING was
        # collected, the target was unreachable from the start — re-raise so the CLI says so clearly.
        if not discovered and not extra_findings and not active_passive:
            raise
        budget_hit = True
        progress.status("Error de red durante el escaneo: reportando lo encontrado hasta ahora…")
    finally:
        if oast is not None:
            await oast.stop()
        if sink is not None:
            sink.close()

    authz_findings: list[Finding] = []
    if config.identities and not budget_hit:  # authz opens fresh clients; skip once the budget is spent
        progress.status("Pruebas de autorización (BOLA/BFLA)…")
        try:
            authz_findings = await _run_authz(config, list(discovered.values()), budget, graphql_url=graphql_url)
        except BudgetExceededError:
            budget_hit = True
        except Exception as exc:  # noqa: BLE001 — authz failing must not sink a completed scan
            _scan_log.warning("Fase 'authz' omitida por un error: %s: %s", type(exc).__name__, exc, exc_info=True)
            failed_phases.append("authz")

    if failed_phases:  # tell the report the coverage was partial (and which checks were skipped)
        extra_findings.append(_coverage_finding(target, failed_phases))

    # Cross-technique correlation over the complete set (in-band + probes + DOM + authz).
    final_findings = cross_correlate(active_passive + extra_findings + dom_findings + authz_findings)

    # Bug-bounty mode: suppress the hardening/disclosure/no-impact findings that programs (HackerOne
    # Core et al.) close as N/A, so the report and gate count only the potentially-reportable ones.
    if bug_bounty:
        from dastcore.bugbounty.eligibility import mark_ineligible

        n = mark_ineligible(final_findings)
        if n:
            _scan_log.info("Modo bug bounty: %d hallazgo(s) marcados como inelegibles (hardening/sin impacto).", n)

    # Unified, ranked attack-surface model: fold every host + discovered endpoint + finding into one
    # prioritised view (highest attack-surface interest first) for the surface report/dashboard.
    if surface is not None and (scan_roots or discovered):
        from urllib.parse import urlsplit as _urlsplit_surface

        from dastcore.discovery.surface import build_scored_surface

        favicon_tech: dict[str, list[str]] = {}
        for root, info in (surface.get("favicon") or {}).items():
            product = info.get("product") if isinstance(info, dict) else None
            if product:
                favicon_tech.setdefault(_urlsplit_surface(root).netloc.lower(), []).append(str(product))
        scored = build_scored_surface(
            scan_roots, list(discovered.values()), final_findings, host_tech=favicon_tech
        )
        surface["scored"] = scored.to_dict()

    return final_findings


async def _run_retest(
    config: ScanConfig,
    prior_findings: list[Finding],
    oast_mode: str,
    oast_server: str,
    budget: _Budget,
) -> list[Finding]:
    """Re-issue only the prior findings' requests and re-run the same rules over them.

    Returns every finding this fresh scan produced; the caller lines them up against
    the prior set by id to decide what's still open vs fixed.
    """
    rules = load_rules()
    base_requests = base_requests_for(prior_findings)
    oast = _build_oast_provider(oast_mode, oast_server)
    if oast is not None:
        await oast.start()
    try:
        async with AsyncExitStack() as stack:
            client = await _open_authenticated_client(stack, config, config.auth, budget)
            scanner = Scanner(client, rules, oast=oast, concurrency=config.rate_limit.max_concurrency)
            return await scanner.scan(base_requests)
    finally:
        if oast is not None:
            await oast.stop()


async def _scan_with_optional_resume(
    scanner: Scanner,
    requests: list[HttpRequest],
    state: _ResumeState | None,
    progress: _ProgressAdapter,
    sink: FindingSink | None = None,
) -> list[Finding]:
    """Concurrent in-band + passive scan, then OOB. With a resume state, skip requests
    already completed in a prior run and persist progress after each one. Each request's findings
    are streamed to ``sink`` (if given) so a hard interruption during this long phase loses nothing."""
    prior = list(state.findings) if state is not None else []
    to_scan = [req for req in requests if state is None or req.signature() not in state.completed]
    progress.start_scanning(len(to_scan))

    def _on_done(request: HttpRequest, request_findings: list[Finding]) -> None:
        if state is not None:
            state.record(request.signature(), request_findings)
        if sink is not None:
            sink.write(request_findings)
        progress.tick()

    in_band = await scanner.scan_inband(to_scan, on_request_done=_on_done)
    # OOB and stored are idempotent and self-gated; run them over the full set every time.
    oob = await scanner.run_oob(requests)
    stored = await scanner.run_stored(requests)
    if sink is not None:
        sink.write(oob + stored)
    return prior + in_band + oob + stored


async def _supabase_local_storage(auth: AuthConfig) -> dict[str, str]:
    """If ``auth`` is a Supabase form-login, log in and return the localStorage entry a Supabase SPA reads
    (``sb-<ref>-auth-token`` = the session JSON), so the headless browser renders *logged in* and the
    crawl reaches the authenticated views. Best-effort: any problem returns {} (falls back to token auth)."""
    form = auth.form
    if auth.type != "form" or form is None:
        return {}
    match = re.search(r"https?://([a-z0-9-]+)\.supabase\.co/auth/v1/token", form.login_url, re.IGNORECASE)
    if not match:
        return {}
    ref = match.group(1)
    headers = {"Content-Type": "application/json", **(form.login_headers or {})}
    apikey = headers.get("apikey")
    if apikey and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {apikey}"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(form.login_url, json=dict(form.credentials), headers=headers)
        if resp.status_code >= 400:
            return {}
        session = resp.json()
    except (httpx.HTTPError, ValueError):
        return {}
    if not isinstance(session, dict) or "access_token" not in session:
        return {}
    return {f"sb-{ref}-auth-token": _json.dumps(session)}


async def _run_headless(
    config: ScanConfig, client: HttpClient, target: str, max_pages: int, user_agent: str = "", proxy: str = "",
    interactive: bool = False,
) -> tuple[list[HttpRequest], list[Finding]]:
    """Render with a headless browser: crawl JS/XHR + probe DOM-XSS, reusing the auth session.

    Stealth is on by default (the engine presents itself as a normal browser), so headless crawling
    gets past bot-detection/WAFs like Cloudflare. ``user_agent`` overrides the UA to match a real
    browser exactly — pair it with that browser's ``cf_clearance`` cookie to scan through the challenge.
    """
    async with HeadlessEngine(
        config.scope,
        cookies=client.cookie_pairs(),
        cookie_url=target,
        extra_headers=client.session_headers(),
        max_pages=max_pages,
        user_agent=user_agent or None,
        proxy=proxy or None,
        interactive=interactive,
        # Seed a Supabase SPA's session into localStorage so the browser renders logged in (reaches the
        # authenticated views/XHR that a token-in-header alone can't unlock in a client-rendered app).
        local_storage=await _supabase_local_storage(config.auth),
    ) as engine:
        discovered = await engine.crawl(target)
        page_urls = [req.url for req in discovered if req.method == "GET"]
        dom_findings = await engine.scan_dom_xss([target, *page_urls])
        # CSTI (AngularJS/Vue) rides the same headless render over reflected query params.
        dom_findings += await engine.scan_csti(discovered)
        return discovered, dom_findings


def _screenshot_filename(root: str) -> str:
    """A filesystem-safe PNG name for a root URL (its netloc, sanitised)."""
    from urllib.parse import urlsplit

    netloc = urlsplit(root).netloc or root
    safe = "".join(c if c.isalnum() or c in ".-" else "_" for c in netloc)
    return f"{safe or 'root'}.png"


async def _capture_screenshots(
    config: ScanConfig, client: HttpClient, roots: list[str], out_dir: str
) -> dict[str, str]:
    """Screenshot each root with one shared headless browser. Returns {root: file}. Fail-open."""
    shots: dict[str, str] = {}
    async with HeadlessEngine(
        config.scope,
        cookies=client.cookie_pairs(),
        extra_headers=client.session_headers(),
    ) as engine:  # raises HeadlessUnavailableError before the dir is created if the browser is missing
        directory = Path(out_dir)
        directory.mkdir(parents=True, exist_ok=True)
        for root in roots:
            path = directory / _screenshot_filename(root)
            if await engine.screenshot(root, str(path)):
                shots[root] = str(path)
    return shots


class SessionLoginError(RuntimeError):
    """Raised when the initial authentication cannot be established."""


def _print_findings_table(findings: list[Finding]) -> None:
    """Correlated overview: one row per issue (rule) with its instance count."""
    issues = correlate(findings)
    table = Table(title=f"{len(findings)} hallazgo(s) · {len(issues)} issue(s)")
    table.add_column("Severidad")
    table.add_column("CVSS", justify="right")
    table.add_column("Confianza")
    table.add_column("Issue")
    table.add_column("Instancias", justify="right")
    table.add_column("Ubicaciones")
    for issue in issues:
        style = _SEVERITY_STYLE.get(issue.severity, "")
        conf_style = _CONFIDENCE_STYLE.get(issue.confidence, "")
        locations = ", ".join(issue.locations[:3]) + (" …" if len(issue.locations) > 3 else "")
        table.add_row(
            f"[{style}]{issue.severity}[/{style}]",
            f"{issue.cvss_score:.1f}",
            f"[{conf_style}]{issue.confidence}[/{conf_style}]",
            issue.name,
            str(issue.count),
            locations,
        )
    console.print(table)


def _print_triage_digest(digest: TriageDigest, *, top: int = 0) -> None:
    """Copilot summary: clusters (class+injection point rolled up across hosts), ranked, with a
    separate 'review / possible FP' bucket — so you see what to handle first."""
    order = ("critical", "high", "medium", "low", "info")
    sev_line = " · ".join(f"{s}: {digest.severity_counts[s]}" for s in order if digest.severity_counts.get(s))
    console.print(
        f"\n[bold]Copilot de triaje[/bold] — {digest.total_findings} hallazgo(s) · "
        f"{len(digest.clusters)} cluster(s) · {digest.distinct_hosts} host(s)"
        + (f"\n[dim]{sev_line}[/dim]" if sev_line else "")
    )

    def _table(title: str, clusters: list) -> None:
        table = Table(title=title)
        for col, kw in (("Prio", {}), ("Severidad", {}), ("Issue", {}), ("Hosts", {"justify": "right"}),
                        ("Inst.", {"justify": "right"}), ("Exploit", {"justify": "right"}), ("Ejemplo", {})):
            table.add_column(col, **kw)
        for c in clusters:
            style = _SEVERITY_STYLE.get(c.severity, "")
            hostlbl = str(c.host_count)
            if c.hosts:
                hostlbl += " · " + ", ".join(c.hosts[:2]) + ("…" if c.host_count > 2 else "")
            table.add_row(c.band, f"[{style}]{c.severity}[/{style}]", c.name, hostlbl,
                          str(c.count), f"{c.exploitability:.1f}", c.example)
        console.print(table)

    prio = digest.priority[:top] if top > 0 else digest.priority
    if prio:
        _table(f"Prioritarios ({len(digest.priority)})", prio)
    else:
        console.print("[dim]Sin clusters prioritarios por encima de la barra de confianza.[/dim]")
    if digest.review:
        _table(f"Revisar — posible falso positivo ({len(digest.review)})", digest.review)


_RETEST_STATUS_STYLE = {"open": "bold red", "unverified": "yellow", "fixed": "green"}
_RETEST_STATUS_LABEL = {"open": "ABIERTO", "unverified": "SIN VERIFICAR", "fixed": "CORREGIDO"}
_RETEST_STATUS_ORDER = {"open": 0, "unverified": 1, "fixed": 2}


def _retest_scope_and_target(
    prior_findings: list[Finding], allow_domain: list[str], deny_domain: list[str]
) -> tuple[ScopeConfig, str]:
    """Derive scope + a representative target from the prior findings' request URLs.

    The allowlist defaults to every host seen in the prior findings (so the retest can
    only reach the endpoints it's re-verifying); an explicit --allow-domain overrides it.
    """
    from urllib.parse import urlsplit

    hosts: list[str] = []
    target = ""
    for finding in prior_findings:
        parts = urlsplit(finding.request.url)
        if not target and parts.scheme and parts.netloc:
            target = f"{parts.scheme}://{parts.netloc}"
        if parts.hostname and parts.hostname not in hosts:
            hosts.append(parts.hostname)
    scope = ScopeConfig(allow_domains=list(allow_domain) or hosts, deny_domains=list(deny_domain))
    return scope, target


def _print_retest_table(outcomes: list[RetestOutcome]) -> None:
    """One row per prior finding, ordered open → unverified → fixed."""
    table = Table(title=f"Retest · {len(outcomes)} hallazgo(s) previo(s)")
    table.add_column("Estado")
    table.add_column("Severidad")
    table.add_column("Issue")
    table.add_column("Ubicación")
    ordered = sorted(outcomes, key=lambda o: (_RETEST_STATUS_ORDER[o.status], o.prior.name))
    for outcome in ordered:
        prior = outcome.prior
        style = _RETEST_STATUS_STYLE[outcome.status]
        sev_style = _SEVERITY_STYLE.get(prior.severity, "")
        table.add_row(
            f"[{style}]{_RETEST_STATUS_LABEL[outcome.status]}[/{style}]",
            f"[{sev_style}]{prior.severity}[/{sev_style}]",
            prior.name,
            f"{prior.injection_point.location}:{prior.injection_point.name}",
        )
    console.print(table)


def _print_retest_summary(counts: dict[str, int], duration_s: float) -> None:
    body = (
        f"[bold red]abiertos: {counts['open']}[/bold red]  ·  "
        f"[green]corregidos: {counts['fixed']}[/green]  ·  "
        f"[yellow]sin verificar: {counts['unverified']}[/yellow]"
    )
    console.print(
        Panel(
            f"{body}\n\nDuración: [bold]{duration_s:.1f}s[/bold]",
            title="Resumen del retest",
            border_style="cyan",
        )
    )


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
    supabase_frontend: str = typer.Option(
        "",
        "--supabase-frontend",
        help="URL del frontend de una app Supabase: mina sus tablas (.from()/rest/v1) para probar RLS/authz.",
    ),
    supabase_write_test: bool = typer.Option(
        False,
        "--supabase-write-test",
        help="Además del RLS de lectura, prueba el de ESCRITURA (INSERT seguro por tabla; puede mutar — opt-in).",
    ),
    stored: bool = typer.Option(
        False,
        "--stored",
        help="Detección de XSS almacenado/segundo orden: inyecta canarios y re-crawlea (más lento).",
    ),
    waf_evasion: bool = typer.Option(
        False,
        "--waf-evasion",
        help="Si el WAF bloquea un payload, reintenta con encoders/tampers para confirmar la vuln enmascarada "
        "(intrusivo; no se activa en el perfil quick).",
    ),
    test_race: bool = typer.Option(
        False,
        "--test-race",
        help="Prueba race conditions en endpoints de escritura con una ráfaga concurrente (intrusivo; "
        "no se activa en el perfil quick).",
    ),
    test_csrf: bool = typer.Option(
        False,
        "--test-csrf",
        help="Comprueba si un token anti-CSRF se valida de verdad reenviando la acción sin el token "
        "(intrusivo: reejecuta escrituras; no se activa en el perfil quick).",
    ),
    test_proto_pollution: bool = typer.Option(
        False,
        "--test-proto-pollution",
        help="Prueba prototype pollution server-side (Node) inyectando __proto__ y observando el cambio de "
        "formato JSON (intrusivo: contamina y restaura el prototipo global; no se activa en el perfil quick).",
    ),
    test_cache_poisoning: bool = typer.Option(
        False,
        "--test-cache-poisoning",
        help="Prueba web cache poisoning: envenena una URL única (cache-buster) con una cabecera no clavada y "
        "confirma con una petición limpia servida desde la caché (intrusivo: escribe una entrada de caché; "
        "no se activa en el perfil quick).",
    ),
    prove_impact: bool = typer.Option(
        False,
        "--prove-impact",
        help="Sobre cada hallazgo ya confirmado, intenta una extracción de solo lectura y acotada que demuestre "
        "el impacto real (SQLi → versión de la BD leída in-band). Solo enriquece hallazgos confirmados, nunca crea "
        "nuevos (opt-in explícito: envía payloads de extracción de solo lectura, acotados a 24 peticiones/hallazgo).",
    ),
    test_weak_creds: bool = typer.Option(
        False,
        "--test-weak-creds",
        help="Prueba credenciales por defecto/débiles contra el login (requiere --login-url). Solo reporta si un par "
        "por defecto autentica de verdad (establece sesión / redirige, a diferencia de un intento inválido). "
        "Intrusivo: envía intentos de login que pueden contar para el bloqueo de cuenta; no se activa en el perfil quick.",
    ),
    test_dos: bool = typer.Option(
        False,
        "--test-dos",
        help="Pruebas de denegación de servicio por diferencial temporal: XML entity expansion (billion laughs) y "
        "ReDoS (backtracking catastrófico de regex, confirmado por escalado super-lineal + control de igual longitud "
        "+ reproducibilidad). Intrusivo: degrada el objetivo a propósito; no se activa en el perfil quick.",
    ),
    test_smuggling: bool = typer.Option(
        False,
        "--test-smuggling",
        help="Prueba HTTP request smuggling (desincronización CL.TE) por diferencial temporal sobre sockets crudos: "
        "un chunked incompleto cuelga solo NUESTRA conexión mientras baseline y control responden rápido; "
        "reproducible. Delicado/intrusivo; no se activa en el perfil quick.",
    ),
    test_upload: bool = typer.Option(
        False,
        "--test-upload",
        help="Prueba subida de ficheros peligrosos en endpoints de upload: sube un fichero benigno pero ejecutable/"
        "servible, lo recupera y confirma el impacto (RCE si el .php se ejecuta; XSS almacenado si el .html/.svg se "
        "sirve). Intrusivo: escribe ficheros en el servidor; no se activa en el perfil quick.",
    ),
    discover: bool = typer.Option(
        False,
        "--discover",
        help="Descubrimiento de superficie completa: enumera subdominios en scope (crt.sh + fuerza bruta DNS) Y rutas "
        "ocultas por host (dirbusting estilo ffuf, con calibración anti-soft-404 para cero falsos positivos), y luego "
        "escanea cada host y ruta descubiertos. Solo toca hosts dentro del scope autorizado. Intrusivo; no en 'quick'.",
    ),
    discover_subdomains: bool = typer.Option(
        False, "--discover-subdomains", help="Solo enumeración de subdominios (subconjunto de --discover)."
    ),
    discover_content: bool = typer.Option(
        False, "--discover-content", help="Solo descubrimiento de rutas / dirbusting (subconjunto de --discover)."
    ),
    discover_ports: bool = typer.Option(
        False,
        "--discover-ports",
        help="Escaneo de puertos (connect-scan nativo, sin privilegios) de cada host descubierto: los servicios "
        "HTTP en puertos no estándar (8080, 8443, 9200…) se añaden como raíces de escaneo. Intrusivo; no en 'quick'.",
    ),
    discover_vhosts: bool = typer.Option(
        False,
        "--discover-vhosts",
        help="Fuzzing de virtual hosts (cabecera Host) sobre cada raíz: encuentra sitios servidos por Host que no "
        "están publicados en DNS (staging/internos). Solo prueba nombres dentro del scope. Se reportan como info.",
    ),
    osint: bool = typer.Option(
        False,
        "--osint",
        help="OSINT organizacional (pasivo): referencias al dominio en código público (GitHub, requiere GITHUB_TOKEN) "
        "y buckets S3/GCS/Azure públicos derivados de los dominios en scope. No escanea; reporta hallazgos.",
    ),
    screenshots: bool = typer.Option(
        False,
        "--screenshots",
        help="Captura una screenshot (headless) de cada host descubierto para triaje visual. Requiere Playwright; "
        "se guardan en --screenshots-dir (por defecto 'dastcore-screenshots/').",
    ),
    screenshots_dir: str = typer.Option(
        "", "--screenshots-dir", help="Directorio donde guardar las screenshots (por defecto 'dastcore-screenshots')."
    ),
    discover_depth: str = typer.Option(
        "aggressive", "--discover-depth", help="Profundidad del descubrimiento: light | balanced | aggressive."
    ),
    content_wordlist: str = typer.Option(
        "", "--content-wordlist", help="Diccionario propio de rutas/directorios (p. ej. de SecLists) en vez del integrado."
    ),
    subdomain_wordlist: str = typer.Option(
        "", "--subdomain-wordlist", help="Diccionario propio de subdominios (p. ej. de SecLists) en vez del integrado."
    ),
    seed_host: list[str] = typer.Option(
        [], "--seed-host", help="Host/subdominio ya conocido a incluir siempre en el escaneo (repetible)."
    ),
    seed_path: list[str] = typer.Option(
        [], "--seed-path", help="Ruta ya conocida a probar siempre en cada host (repetible)."
    ),
    seeds_file: str = typer.Option(
        "", "--seeds-file", help="Fichero con seeds (una por línea): host si contiene un punto, si no ruta."
    ),
    subdomain_recursion: int = typer.Option(
        -1, "--subdomain-recursion", help="Niveles de recursión de subdominios (-1 = según profundidad)."
    ),
    historical: bool = typer.Option(
        True,
        "--historical/--no-historical",
        help="Con el descubrimiento activo, mina URLs históricas (Wayback) — pasivo, sus parámetros son "
        "puntos de inyección. --no-historical para desactivarlo.",
    ),
    js: bool = typer.Option(
        True,
        "--js/--no-js",
        help="Con el descubrimiento activo, extrae endpoints de los bundles JavaScript (SPAs modernas: "
        "Next.js, React…). --no-js para desactivarlo.",
    ),
    interactive: bool = typer.Option(
        False,
        "--interactive",
        help="Crawl interactivo de SPA (headless): hace clic en controles SEGUROS (tabs/nav/ver…) para "
        "disparar y capturar las llamadas API que un React/Vue solo hace al interactuar. Nunca toca "
        "acciones destructivas (delete/logout/pagar/enviar). Descubre mucha más superficie en SPAs.",
    ),
    mine_params: bool = typer.Option(
        False,
        "--mine-params",
        help="Descubre parámetros ocultos (estilo Arjun) en los endpoints descubiertos: cada uno es un nuevo "
        "punto de inyección. Intrusivo (varias peticiones por endpoint); no se activa en el perfil 'quick'.",
    ),
    permute: bool = typer.Option(
        True,
        "--permute/--no-permute",
        help="Con el descubrimiento de subdominios, genera permutaciones de los hallados (api → api-dev, "
        "api2, staging-api…) y las prueba. --no-permute para desactivarlo.",
    ),
    roles_file: str = typer.Option(
        "", "--roles-file", help="Ruta a un JSON con identidades (name/role/auth) para pruebas de autorización."
    ),
    max_pages: int = typer.Option(200, "--max-pages", help="Máximo de páginas a recorrer en el crawl."),
    requests_per_second: float = typer.Option(5.0, "--rps", help="Límite de requests por segundo."),
    concurrency: int = typer.Option(5, "--concurrency", help="Peticiones en paralelo durante el escaneo activo."),
    timeout: float = typer.Option(
        10.0, "--timeout", help="Timeout por petición en segundos. Bájalo (p. ej. 4) para objetivos lentos."
    ),
    max_retries: int = typer.Option(
        2, "--max-retries", help="Reintentos de transporte por petición. Bájalo (p. ej. 0) en objetivos lentos."
    ),
    user_agent: str = typer.Option(
        "", "--user-agent", help="User-Agent para el motor headless (por defecto uno realista). Pon el de tu "
        "navegador real para emparejarlo con su cookie cf_clearance y atravesar WAFs/challenges tipo Cloudflare."
    ),
    proxy: str = typer.Option(
        "", "--proxy", help="Enruta TODO el escaneo (HTTP + headless) por un proxy/VPN, p. ej. "
        "http://127.0.0.1:8080 o socks5://user:pass@host:1080. Úsalo para salir por tu IP de confianza y "
        "esquivar bloqueos de reputación de IP del WAF (túnel a tu casa, VPN, o proxy residencial)."
    ),
    bug_bounty: bool = typer.Option(
        False, "--bug-bounty", help="Modo bug bounty: marca como inelegibles los hallazgos de hardening/"
        "disclosure/sin-impacto que los programas (HackerOne Core…) cierran como N/A, para que el reporte "
        "destaque solo lo potencialmente reportable. No los borra: quedan como suprimidos, revisables."
    ),
    attrib_header: list[str] = typer.Option(
        [], "--attrib-header", help="Cabecera de atribución 'Nombre=valor' enviada en TODO el tráfico "
        "al objetivo (repetible), p. ej. 'X-Bug-Bounty=HackerOne-tu_handle'. Muchos programas la exigen "
        "para identificar tus peticiones."
    ),
    max_requests: int = typer.Option(
        0, "--max-requests", help="Presupuesto total de peticiones (0 = sin límite). Detiene el escaneo al alcanzarlo."
    ),
    time_budget: float = typer.Option(0.0, "--time-budget", help="Presupuesto de tiempo en segundos (0 = sin límite)."),
    output_format: str = typer.Option(
        "json", "--format", "-f", help="Formato del reporte: json | sarif | html | defectdojo | pdf."
    ),
    output_path: str = typer.Option(
        "", "--output", "-o", help="Ruta de archivo para el reporte (por defecto, stdout; pdf requiere --output)."
    ),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Umbral de severidad que hace fallar el proceso (exit 2) para CI/CD: "
        "info | low | medium | high | critical | none.",
    ),
    notify_webhook: str = typer.Option(
        "", "--notify-webhook",
        help="Vigilancia continua: envía a este webhook los hallazgos NUEVOS respecto a --baseline (Slack/Discord/genérico).",
    ),
    notify_format: str = typer.Option(
        "slack", "--notify-format", help="Formato del webhook: slack | discord | generic."
    ),
    notify_min_severity: str = typer.Option(
        "medium", "--notify-min-severity", help="Umbral mínimo para alertar por el webhook."
    ),
    baseline: str = typer.Option(
        "", "--baseline",
        help="JSON de hallazgos previos (salida de un scan anterior -f json): calcula los NUEVOS (alertas / delta gating).",
    ),
    gate_on_new: bool = typer.Option(
        False, "--gate-on-new",
        help="Delta gating (CI): --fail-on cuenta SOLO los hallazgos nuevos vs --baseline, no todo el backlog.",
    ),
    suppress: str = typer.Option(
        "",
        "--suppress",
        help="Archivo de triaje (falsos positivos / riesgos aceptados). "
        "Si se omite, se auto-detecta .dastcore-ignore en el directorio actual.",
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
    login_header: list[str] = typer.Option(
        [], "--login-header",
        help="Form-login: cabecera extra en el login 'Nombre=valor' (p. ej. la 'apikey' de Supabase; repetible).",
    ),
    login_token_field: str = typer.Option(
        "", "--login-token-field",
        help="Form-login: campo JSON de la respuesta de login del que sacar el token (p. ej. 'access_token').",
    ),
    login_token_header: str = typer.Option(
        "Authorization", "--login-token-header", help="Form-login: cabecera donde poner el token extraído."
    ),
    auth_macro: str = typer.Option(
        "", "--auth-macro", help="Login por macro de navegador: fichero .json grabado con 'dastcore auth record'."
    ),
    auth_macro_var: list[str] = typer.Option(
        [], "--auth-macro-var", help="Valor runtime para un placeholder {{name}} de la macro: 'name=valor' (repetible)."
    ),
    ai_triage: bool = typer.Option(
        False,
        "--ai-triage",
        help="Capa IA opcional: clasifica, agrupa por causa raíz y redacta remediación a partir de los hallazgos "
        "YA confirmados por el oráculo (nunca confirma ni crea hallazgos). Usa ANTHROPIC_API_KEY.",
    ),
    ai_triage_key: str = typer.Option(
        "", "--ai-triage-key", help="API key de Anthropic para --ai-triage (si se omite, usa ANTHROPIC_API_KEY)."
    ),
    ai_payloads: bool = typer.Option(
        False,
        "--ai-payloads",
        help="Capa IA opcional: cuando la entrada se refleja pero los payloads declarados no disparan, la IA "
        "propone payloads según el contexto y el ORÁCULO los confirma (la IA nunca confirma). Usa "
        "ANTHROPIC_API_KEY; intrusivo, no se activa en el perfil quick.",
    ),
    ai_payloads_key: str = typer.Option(
        "", "--ai-payloads-key", help="API key de Anthropic para --ai-payloads (si se omite, usa ANTHROPIC_API_KEY)."
    ),
    audience: str = typer.Option(
        "developer",
        "--audience",
        help="Audiencia del reporte HTML: developer (detalle técnico completo) | executive (resumen + "
        "cumplimiento, sin payloads request/response ni curl).",
    ),
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
    supabase_frontend = _pick(ctx, "supabase_frontend", supabase_frontend, scan_file.supabase_frontend)
    supabase_tables = scan_file.supabase_tables or []  # config-file only: an explicit table list to probe
    supabase_write_test = _pick(ctx, "supabase_write_test", supabase_write_test, scan_file.supabase_write_test)
    output_format = _pick(ctx, "output_format", output_format, scan_file.format).lower()
    output_path = _pick(ctx, "output_path", output_path, scan_file.output)
    fail_on = _pick(ctx, "fail_on", fail_on, scan_file.fail_on).lower()
    proxy = _pick(ctx, "proxy", proxy, scan_file.proxy)
    user_agent = _pick(ctx, "user_agent", user_agent, scan_file.user_agent)
    if _is_default_source(ctx, "bug_bounty") and scan_file.bug_bounty is not None:
        bug_bounty = scan_file.bug_bounty
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

    if output_format not in ("json", "sarif", "html", "defectdojo", "pdf"):
        console.print(
            f"[bold red]Formato inválido:[/bold red] {output_format!r} (usa json | sarif | html | defectdojo | pdf)."
        )
        raise typer.Exit(code=1)
    if output_format == "pdf" and not output_path:
        console.print("[bold red]--format pdf requiere --output[/bold red] (un PDF binario no va a stdout).")
        raise typer.Exit(code=1)

    valid_fail_on = ("info", "low", "medium", "high", "critical", "none")
    if fail_on not in valid_fail_on:
        console.print(f"[bold red]--fail-on inválido:[/bold red] {fail_on!r} (usa {' | '.join(valid_fail_on)}).")
        raise typer.Exit(code=1)

    audience = audience.lower()
    if audience not in ("developer", "executive"):
        console.print(f"[bold red]--audience inválido:[/bold red] {audience!r} (usa developer | executive).")
        raise typer.Exit(code=1)

    suppressions = _load_suppressions_or_exit(suppress)

    payload_generator: AiPayloadGenerator | None = None
    if ai_payloads and profile != "quick":
        payload_generator = build_payload_generator(ai_payloads_key or None)
        if payload_generator is None and not quiet:
            console.print(
                "[dim]--ai-payloads: sin ANTHROPIC_API_KEY; se ignora (la IA no está en la ruta crítica).[/dim]"
            )

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
            login_macro=auth_macro,
            macro_var=auth_macro_var,
            login_header=login_header,
            login_token_field=login_token_field,
            login_token_header=login_token_header,
        )
        if auth.type == "none" and scan_file.auth is not None:
            auth = scan_file.auth
        config = ScanConfig(
            target=target,  # type: ignore[arg-type]
            scope=ScopeConfig(allow_domains=list(allow_domain), deny_domains=list(deny_domain)),
            auth=auth,
            identities=identities,
            rate_limit=RateLimitConfig(
                requests_per_second=requests_per_second,
                max_concurrency=concurrency,
                timeout=timeout,
                max_retries=max_retries,
            ),
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

    if not console.is_terminal:
        # Background / piped run: the rich bar is disabled, so surface phase progress via the logger.
        from dastcore.obslog import configure_logging

        configure_logging()

    # Incremental persistence (survives a hard interruption) + a surface map, alongside the main report.
    surface: dict[str, Any] = {}
    findings_log = ""
    surface_path = ""
    if output_path:
        _stem = str(Path(output_path).with_suffix(""))
        findings_log = f"{_stem}.partial.jsonl"
        surface_path = f"{_stem}.surface.json"

    # Manual seeds (flags + file): a token with a dot is a known host, otherwise a known path. They're
    # merged into discovery so the automatic sweep always includes what you already know.
    seed_hosts, seed_paths = list(seed_host), list(seed_path)
    if seeds_file:
        for raw in Path(seeds_file).read_text(encoding="utf-8", errors="ignore").splitlines():
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            (seed_hosts if "." in entry.split("/")[0] and "/" not in entry else seed_paths).append(entry)
    if seed_hosts or seed_paths:
        info(f"Seeds manuales: [bold]{len(seed_hosts)}[/bold] host(s), [bold]{len(seed_paths)}[/bold] ruta(s)")

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
                    config,
                    max_pages,
                    engine,
                    oast_mode,
                    oast_server,
                    openapi_url,
                    graphql_url,
                    state,
                    budget,
                    _ProgressAdapter(progress),
                    stored_scan=stored,
                    waf_evasion=waf_evasion and profile != "quick",
                    test_race=test_race and profile != "quick",
                    test_csrf=test_csrf and profile != "quick",
                    test_proto_pollution=test_proto_pollution and profile != "quick",
                    test_cache_poisoning=test_cache_poisoning and profile != "quick",
                    test_weak_creds=test_weak_creds and profile != "quick",
                    test_upload=test_upload and profile != "quick",
                    test_dos=test_dos and profile != "quick",
                    test_smuggling=test_smuggling and profile != "quick",
                    prove_impact=prove_impact,  # opt-in explícito: enriquece confirmados, no depende del perfil
                    discover_subdomains=(discover or discover_subdomains) and profile != "quick",
                    discover_content=(discover or discover_content) and profile != "quick",
                    discover_ports=discover_ports and profile != "quick",
                    discover_vhosts=discover_vhosts and profile != "quick",
                    osint=osint and profile != "quick",
                    screenshots=screenshots and profile != "quick",
                    screenshots_dir=screenshots_dir,
                    user_agent=user_agent,
                    proxy=proxy,
                    bug_bounty=bug_bounty,
                    attribution=_parse_kv_list(attrib_header, "--attrib-header") if attrib_header else None,
                    discover_depth=discover_depth,
                    content_wordlist=content_wordlist,
                    subdomain_wordlist=subdomain_wordlist,
                    seed_hosts=seed_hosts,
                    seed_paths=seed_paths,
                    subdomain_recursion=subdomain_recursion,
                    use_permutations=(discover or discover_subdomains) and profile != "quick" and permute,
                    use_historical=(discover or discover_content or discover_subdomains)
                    and profile != "quick"
                    and historical,
                    use_js=(discover or discover_content or discover_subdomains) and profile != "quick" and js,
                    mine_params=mine_params and profile != "quick",
                    findings_log=findings_log,
                    surface=surface,
                    ai_payloads=payload_generator,
                    interactive=interactive,
                    supabase_frontend=supabase_frontend,
                    supabase_tables=supabase_tables,
                    supabase_write_test=supabase_write_test,
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

    _emit_surface(surface, surface_path, quiet=quiet)
    gate_findings = _delta_gate_findings(findings, baseline, gate_on_new)
    _emit_report_and_gate(
        findings,
        output_format=output_format,
        output_path=config.output.path or "",
        fail_on=fail_on,
        quiet=quiet,
        target=str(config.target),
        duration_s=time.monotonic() - started_at,
        suppressions=suppressions,
        ai_triage=ai_triage,
        ai_triage_key=ai_triage_key or None,
        audience=audience,
        gate_findings=gate_findings,
    )
    if notify_webhook:
        _notify_delta_cli(
            notify_webhook, notify_format, notify_min_severity, baseline, findings, str(config.target)
        )


def _emit_surface(surface: dict[str, Any], path: str, *, quiet: bool) -> None:
    """Write the discovered attack surface (hosts + hidden paths) to a file and print a short summary.

    This is the map the JSON findings alone can't show: every live host scanned and every hidden path
    found, even the ones with no vulnerability — so you can see exactly what dastcore covered."""
    from urllib.parse import urlsplit

    roots = surface.get("roots") or []
    content = surface.get("content") or {}
    if not roots and not content:
        return  # discovery wasn't enabled for this scan
    if path:
        Path(path).write_text(_json.dumps(surface, indent=2, ensure_ascii=False), encoding="utf-8")
    if quiet:
        return
    total_paths = sum(len(paths) for paths in content.values())
    console.print(
        f"\n[bold]Superficie descubierta[/bold]  ·  {len(roots)} host(s), {total_paths} ruta(s) oculta(s)"
    )
    for root in roots:
        paths = content.get(root, [])
        console.print(f"  [cyan]{urlsplit(root).netloc or root}[/cyan]  ({len(paths)} ruta(s) oculta(s))")
        for url in paths[:12]:
            console.print(f"     {urlsplit(url).path or url}")
        if len(paths) > 12:
            console.print(f"     … y {len(paths) - 12} más")

    # Prioritised view: hosts ranked by attack-surface interest, so the eye goes to what matters first.
    scored = (surface.get("scored") or {}).get("hosts") or []
    ranked = [h for h in scored if h.get("score", 0) > 0][:8]
    if ranked:
        console.print("\n[bold]Prioridad de superficie[/bold] (mayor interés de ataque primero)")
        for host in ranked:
            reasons = "; ".join(host.get("reasons", [])) or "—"
            console.print(f"  [yellow]{host['score']:>4.0f}[/yellow]  [cyan]{host['host']}[/cyan]  · {reasons}")

    if path:
        console.print(f"[dim]Mapa completo: {path}[/dim]")


def _print_ai_triage(findings: list[Finding], *, api_key: str | None) -> None:
    """Run the optional AI triage layer over confirmed findings and print its editorial output.

    Everything shown here is AI-authored and clearly labelled as such: the AI classifies,
    groups by root cause, and drafts remediation from evidence an oracle already confirmed —
    it never confirms, creates, or elevates a finding. Degrades to a dim note if unavailable.
    """
    result = triage_findings(findings, api_key=api_key)
    if not result.generated:
        console.print(f"\n[dim]IA triage: {result.error or 'sin hallazgos que triar'}.[/dim]")
        return

    body = Text(result.executive_summary)
    console.print()
    console.print(Panel(body, title=f"[bold]Resumen ejecutivo (IA · {result.model})[/bold]", border_style="cyan"))

    if result.root_cause_groups:
        table = Table(title="Causas raíz (IA)", show_lines=True)
        table.add_column("Grupo", style="bold")
        table.add_column("Causa raíz")
        table.add_column("Hallazgos", justify="right")
        table.add_column("Remediación")
        for group in result.root_cause_groups:
            table.add_row(group.title, group.root_cause, str(len(group.finding_ids)), group.remediation)
        console.print(table)

    if result.business_severity:
        table = Table(title="Severidad de negocio (IA · orientativa, no sustituye a la técnica)")
        table.add_column("Hallazgo")
        table.add_column("Negocio", justify="center")
        table.add_column("Justificación")
        for item in result.business_severity:
            table.add_row(item.finding_id, item.level.upper(), item.rationale)
        console.print(table)
    console.print(
        "[dim]La IA solo clasifica y redacta a partir de evidencia ya confirmada por el oráculo; "
        "no confirma ni crea hallazgos.[/dim]"
    )


def _load_baseline_findings(path: str) -> list[Finding]:
    """Load a prior scan's findings JSON (dastcore `-f json`) as a baseline. Empty on any problem
    (so a missing/broken baseline degrades to 'everything is new')."""
    if not path:
        return []
    try:
        return [Finding.model_validate(x) for x in _json.loads(Path(path).read_text(encoding="utf-8"))]
    except (OSError, ValueError) as exc:
        console.print(f"[yellow]No pude leer --baseline ({exc}); trato todos los hallazgos como nuevos.[/yellow]")
        return []


def _delta_gate_findings(findings: list[Finding], baseline_path: str, gate_on_new: bool) -> list[Finding] | None:
    """Delta gating: with --gate-on-new, return only the findings NEW vs the baseline (so --fail-on
    gates on the delta a PR introduces, not the whole backlog). None = gate on everything (default)."""
    if not gate_on_new:
        return None
    from dastcore.web.diff import diff_findings

    new = diff_findings(_load_baseline_findings(baseline_path), findings).new
    console.print(
        f"[cyan]Delta gating:[/cyan] {len(new)} hallazgo(s) nuevo(s) vs baseline (de {len(findings)}); "
        "el gate --fail-on solo cuenta esos."
    )
    return new


def _notify_delta_cli(
    webhook: str, fmt: str, min_severity: str, baseline_path: str,
    findings: list[Finding], target: str,
) -> None:
    """Continuous-monitoring alert for the CLI (cron-friendly): POST the findings that are NEW versus
    ``--baseline`` (a prior scan's JSON) to a Slack/Discord/generic webhook. Best-effort."""
    from dastcore.notify import filter_by_severity, send_alert
    from dastcore.web.diff import diff_findings

    fmt = fmt if fmt in ("slack", "discord", "generic") else "slack"
    min_severity = min_severity if min_severity in ("critical", "high", "medium", "low", "info") else "medium"
    new = diff_findings(_load_baseline_findings(baseline_path), findings).new
    alertable = filter_by_severity(new, min_severity)
    if not alertable:
        console.print("[dim]Sin hallazgos nuevos por encima del umbral; no se envía alerta.[/dim]")
        return
    if asyncio.run(send_alert(webhook, fmt, target, alertable)):
        console.print(f"[green]Alerta enviada:[/green] {len(alertable)} hallazgo(s) nuevo(s) → webhook.")
    else:
        console.print("[yellow]No se pudo entregar la alerta al webhook (best-effort).[/yellow]")


def _emit_report_and_gate(
    findings: list[Finding],
    *,
    output_format: str,
    output_path: str,
    fail_on: str,
    quiet: bool,
    target: str,
    duration_s: float,
    html_title: str = "dastcore — Dynamic Security Report",
    group_by_category: bool = False,
    suppressions: list[Suppression] | None = None,
    ai_triage: bool = False,
    ai_triage_key: str | None = None,
    audience: str = "developer",
    gate_findings: list[Finding] | None = None,
) -> None:
    """Shared reporting/exit-gate used by `scan` and `ai`.

    Suppressed findings (triaged via `.dastcore-ignore`) stay in the machine-readable
    JSON/SARIF as an audit trail but drop out of the human console/HTML views and never
    trip the `--fail-on` gate.

    ``gate_findings`` (delta gating for CI): when given, only these findings can trip the
    ``--fail-on`` gate — the full report still shows everything, but the build fails only on the
    subset (e.g. findings NEW versus a baseline). ``None`` keeps the default (gate on all active).
    """
    findings = deduplicate(findings)
    apply_suppressions(findings, suppressions or [])
    active = [f for f in findings if not f.suppressed]
    suppressed = [f for f in findings if f.suppressed]
    gated = active if gate_findings is None else [f for f in gate_findings if not f.suppressed]

    if output_format == "pdf":
        from dastcore.report.pdf import render_pdf

        try:
            pdf_bytes = render_pdf(active, target=target, title=html_title, audience=audience)
        except RuntimeError as exc:  # fpdf2 not installed
            console.print(f"[bold red]{exc}[/bold red]")
            raise typer.Exit(code=1) from exc
        Path(output_path).write_bytes(pdf_bytes)  # --output is required for pdf (validated earlier)
        if not quiet:
            console.print()
            _print_findings_table(active)
            _print_summary(active, duration_s)
            _print_owasp_coverage(active)
            if suppressed:
                _print_suppressed_note(suppressed)
            if ai_triage:
                _print_ai_triage(active, api_key=ai_triage_key)
            console.print(f"\n[green]Reporte PDF escrito en {output_path}[/green]")
        _fail_on_gate(gated, fail_on)
        return

    if output_format == "html":
        report = render_html(
            active, target=target, title=html_title, group_by_category=group_by_category, audience=audience
        )
    else:
        # JSON/SARIF/DefectDojo carry every finding; suppressed ones are flagged in place.
        report = _RENDERERS[output_format](findings)

    if not quiet:
        console.print()
        _print_findings_table(active)
        _print_summary(active, duration_s)
        if suppressed:
            _print_suppressed_note(suppressed)
        if ai_triage:
            _print_ai_triage(active, api_key=ai_triage_key)

    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")
        if not quiet:
            console.print(f"\n[green]Reporte {output_format.upper()} escrito en {output_path}[/green]")
    else:
        if not quiet and output_format != "html":
            console.print(f"\n[bold]{output_format.upper()}:[/bold]")
        print(report)

    _fail_on_gate(gated, fail_on)


def _fail_on_gate(active: list[Finding], fail_on: str) -> None:
    """Exit with the CI failure code if any active finding meets the `--fail-on` threshold."""
    if fail_on == "none":
        return
    blocking = [f for f in active if meets_threshold(f.severity, fail_on)]  # type: ignore[arg-type]
    if blocking:
        console.print(
            f"\n[bold red]{len(blocking)} hallazgo(s) con severidad >= {fail_on}.[/bold red] "
            f"Saliendo con código {EXIT_FINDINGS_OVER_THRESHOLD} (--fail-on)."
        )
        raise typer.Exit(code=EXIT_FINDINGS_OVER_THRESHOLD)


@app.command("retest")
def retest(
    findings_file: str = typer.Argument(..., help="JSON de un escaneo previo (salida de `scan -f json`)."),
    i_have_authorization: bool = typer.Option(
        False, "--i-have-authorization", help="Confirma que tienes autorización para reescanear el objetivo."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Log de cada petición HTTP (DEBUG)."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Silencia la salida decorativa; solo emite el reporte."),
    allow_domain: list[str] = typer.Option(
        [], "--allow-domain", help="Scope permitido (repetible). Por defecto, los hosts de los hallazgos previos."
    ),
    deny_domain: list[str] = typer.Option([], "--deny-domain", help="Dominio(s) fuera de scope (repetible)."),
    oast_mode: str = typer.Option(
        "off", "--oast", help="OAST para reverificar hallazgos ciegos (OOB): off | local | interactsh."
    ),
    oast_server: str = typer.Option("oast.fun", "--oast-server", help="Servidor Interactsh cuando --oast interactsh."),
    requests_per_second: float = typer.Option(5.0, "--rps", help="Límite de requests por segundo."),
    concurrency: int = typer.Option(5, "--concurrency", help="Peticiones en paralelo."),
    max_requests: int = typer.Option(0, "--max-requests", help="Presupuesto total de peticiones (0 = sin límite)."),
    time_budget: float = typer.Option(0.0, "--time-budget", help="Presupuesto de tiempo en segundos (0 = sin límite)."),
    output_format: str = typer.Option("json", "--format", "-f", help="Formato del reporte: json | sarif | html."),
    output_path: str = typer.Option("", "--output", "-o", help="Ruta del reporte de hallazgos aún abiertos."),
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Umbral que hace fallar el proceso (exit 2) si sigue abierto: ... | none."
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
    """Reverifica los hallazgos de un escaneo previo: reescanea SOLO sus peticiones y
    marca cada uno como ABIERTO (sigue vulnerable), CORREGIDO o SIN VERIFICAR (OOB sin
    OAST). Emite un reporte de los que siguen abiertos y falla (exit 2) según --fail-on."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    if not quiet:
        _print_banner()

    if not i_have_authorization:
        console.print("\n[bold red]ABORTADO[/bold red]: se requiere [bold]--i-have-authorization[/bold].")
        raise typer.Exit(code=1)

    output_format = output_format.lower()
    if output_format not in ("json", "sarif", "html"):
        console.print(f"[bold red]Formato inválido:[/bold red] {output_format!r} (usa json | sarif | html).")
        raise typer.Exit(code=1)
    oast_mode = oast_mode.lower()
    if oast_mode not in ("off", "local", "interactsh"):
        console.print(f"[bold red]--oast inválido:[/bold red] {oast_mode!r} (usa off | local | interactsh).")
        raise typer.Exit(code=1)
    fail_on = fail_on.lower()
    valid_fail_on = ("info", "low", "medium", "high", "critical", "none")
    if fail_on not in valid_fail_on:
        console.print(f"[bold red]--fail-on inválido:[/bold red] {fail_on!r} (usa {' | '.join(valid_fail_on)}).")
        raise typer.Exit(code=1)

    try:
        prior_findings = load_prior_findings(_json.loads(Path(findings_file).read_text(encoding="utf-8")))
    except (OSError, ValueError, ValidationError) as exc:
        console.print(f"[bold red]JSON de hallazgos inválido:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if not prior_findings:
        console.print("[yellow]El reporte previo no contiene hallazgos que reverificar.[/yellow]")
        raise typer.Exit(code=0)

    scope, derived_target = _retest_scope_and_target(prior_findings, allow_domain, deny_domain)
    if not derived_target:
        console.print("[bold red]No pude derivar el objetivo:[/bold red] los hallazgos no traen URLs válidas.")
        raise typer.Exit(code=1)

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
        config = ScanConfig(
            target=derived_target,  # type: ignore[arg-type]
            scope=scope,
            auth=auth,
            rate_limit=RateLimitConfig(requests_per_second=requests_per_second, max_concurrency=concurrency),
            output=OutputConfig(format=output_format, path=output_path or None),
            i_have_authorization=i_have_authorization,
        )
    except (ValidationError, typer.BadParameter) as exc:
        console.print(f"[bold red]Configuración inválida:[/bold red]\n{exc}")
        raise typer.Exit(code=1) from exc

    budget = _Budget(max_requests or None, time_budget or None)

    if not quiet:
        console.print(f"\n[green]Autorización confirmada.[/green] Objetivo: [bold]{derived_target}[/bold]")
        console.print(
            f"Reverificando [bold]{len(prior_findings)}[/bold] hallazgo(s) previo(s) sobre "
            f"[bold]{len(base_requests_for(prior_findings))}[/bold] petición(es)…\n"
        )

    started_at = time.monotonic()
    try:
        new_findings = asyncio.run(_run_retest(config, prior_findings, oast_mode, oast_server, budget))
    except SessionLoginError as exc:
        console.print(f"\n[bold red]Error de autenticación:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    except httpx.HTTPError as exc:
        console.print(f"\n[bold red]Error de red al reverificar:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    active_rule_ids = frozenset(rule.id for rule in load_rules())
    outcomes = classify(
        prior_findings, new_findings, oast_attempted=oast_mode != "off", active_rule_ids=active_rule_ids
    )
    still_open = open_findings(outcomes)
    counts = summarize(outcomes)

    if not quiet:
        console.print()
        _print_retest_table(outcomes)
        _print_retest_summary(counts, time.monotonic() - started_at)

    if output_format == "html":
        report = render_html(still_open, target=derived_target, title="dastcore — Retest Report")
    else:
        report = _RENDERERS[output_format](still_open)
    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")
        if not quiet:
            console.print(f"\n[green]Reporte {output_format.upper()} (abiertos) escrito en {output_path}[/green]")
    else:
        if not quiet and output_format != "html":
            console.print(f"\n[bold]{output_format.upper()}:[/bold]")
        print(report)

    if fail_on != "none":
        blocking = [f for f in still_open if meets_threshold(f.severity, fail_on)]  # type: ignore[arg-type]
        if blocking:
            console.print(
                f"\n[bold red]{len(blocking)} hallazgo(s) siguen abiertos con severidad >= {fail_on}.[/bold red] "
                f"Saliendo con código {EXIT_FINDINGS_OVER_THRESHOLD} (--fail-on)."
            )
            raise typer.Exit(code=EXIT_FINDINGS_OVER_THRESHOLD)


@app.command("diff")
def diff(
    baseline_file: str = typer.Argument(..., help="JSON de la línea base (salida de `scan -f json`)."),
    current_file: str = typer.Argument(..., help="JSON del escaneo actual (salida de `scan -f json`)."),
    output_format: str = typer.Option(
        "markdown", "--format", "-f", help="Formato del reporte del diff: markdown | json | sarif | html."
    ),
    output_path: str = typer.Option("", "--output", "-o", help="Ruta del reporte (por defecto, stdout)."),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Falla (exit 2) solo si un hallazgo NUEVO alcanza este umbral: info | low | medium | high | critical | none.",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Silencia la salida decorativa; solo emite el reporte."),
) -> None:
    """Compara dos reportes JSON del mismo objetivo por id estable de hallazgo y reporta lo
    que CAMBIÓ: nuevos, corregidos y persistentes. El gate `--fail-on` se aplica SOLO a los
    hallazgos NUEVOS — ideal para un job de CI que debe fallar ante regresiones pero no ante
    deuda preexistente. Sin red y sin necesidad de autorización: es una comparación de ficheros."""
    if not quiet:
        _print_banner()

    output_format = output_format.lower()
    if output_format not in ("markdown", "json", "sarif", "html"):
        console.print(f"[bold red]Formato inválido:[/bold red] {output_format!r} (usa markdown | json | sarif | html).")
        raise typer.Exit(code=1)
    fail_on = fail_on.lower()
    valid_fail_on = ("info", "low", "medium", "high", "critical", "none")
    if fail_on not in valid_fail_on:
        console.print(f"[bold red]--fail-on inválido:[/bold red] {fail_on!r} (usa {' | '.join(valid_fail_on)}).")
        raise typer.Exit(code=1)

    try:
        base = load_prior_findings(_json.loads(Path(baseline_file).read_text(encoding="utf-8")))
        head = load_prior_findings(_json.loads(Path(current_file).read_text(encoding="utf-8")))
    except (OSError, ValueError, ValidationError) as exc:
        console.print(f"[bold red]JSON de hallazgos inválido:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    result = diff_findings(base, head)
    target = _diff_target(head or base)

    if not quiet:
        c = result.counts
        console.print(
            f"\n[bold]Diff:[/bold] [red]{c['new']} nuevos[/red] · "
            f"[green]{c['fixed']} corregidos[/green] · [dim]{c['persistent']} persistentes[/dim]"
        )

    if output_format == "markdown":
        report = render_markdown_diff(result, target=target)
    elif output_format == "html":
        report = render_html(result.new, target=target, title="dastcore — Diff (hallazgos nuevos)")
    else:
        report = _RENDERERS[output_format](result.new)  # only-new findings for CI ingestion

    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")
        if not quiet:
            console.print(f"\n[green]Reporte {output_format.upper()} escrito en {output_path}[/green]")
    else:
        _emit_text(report)

    if fail_on != "none":
        blocking = [f for f in result.new if meets_threshold(f.severity, fail_on)]  # type: ignore[arg-type]
        if blocking:
            console.print(
                f"\n[bold red]{len(blocking)} hallazgo(s) NUEVO(s) con severidad >= {fail_on}.[/bold red] "
                f"Saliendo con código {EXIT_FINDINGS_OVER_THRESHOLD} (--fail-on)."
            )
            raise typer.Exit(code=EXIT_FINDINGS_OVER_THRESHOLD)


def _emit_text(report: str) -> None:
    """Write a report to stdout UTF-8-safely (Markdown emoji break a cp1252 console)."""
    try:
        sys.stdout.write(report if report.endswith("\n") else report + "\n")
    except UnicodeEncodeError:
        sys.stdout.buffer.write((report if report.endswith("\n") else report + "\n").encode("utf-8", "replace"))


def _diff_target(findings: list[Finding]) -> str | None:
    """Best-effort target label from a finding set (scheme+host of the first finding)."""
    from urllib.parse import urlsplit

    for finding in findings:
        parts = urlsplit(finding.request.url)
        if parts.scheme and parts.netloc:
            return f"{parts.scheme}://{parts.netloc}"
    return None


async def _run_ai_scan(
    config: ScanConfig,
    target: str,
    prompt_field: str,
    template: str,
    response_path: str,
    headers: dict[str, str],
    wordlist: str,
    stream: bool,
    stream_path: str,
) -> list[Finding]:
    async with HttpClient(config.scope, rate_limit=config.rate_limit) as client:
        chat = AiChatClient(
            client,
            target,
            prompt_field=prompt_field,
            template=template or None,
            response_path=response_path or None,
            headers=headers or None,
            stream=stream,
            stream_path=stream_path or None,
        )
        rules = load_ai_rules(extra_wordlist=Path(wordlist) if wordlist else None)
        return await AiScanner(chat, rules).scan()


def _chat_for(client: HttpClient, profile: ChatEndpointProfile, headers: dict[str, str]) -> AiChatClient:
    kwargs = profile.client_kwargs()
    kwargs["headers"] = {**(kwargs.get("headers") or {}), **headers}  # CLI auth headers win
    # Discovery already proved the endpoint reachable, so treat later per-probe failures as
    # transient (empty answer) rather than aborting the whole multi-probe scan.
    return AiChatClient(client, profile.url, tolerant=True, **kwargs)


async def _run_ai_discover_scan(
    config: ScanConfig,
    base_url: str,
    headers: dict[str, str],
    wordlist: str,
    max_pages: int,
    victim_headers: dict[str, str] | None = None,
    victim_refs: Sequence[str] = (),
) -> tuple[ChatEndpointProfile | None, list[Finding]]:
    """Discover the embedded chatbot, then run the LLM rule set against the best endpoint."""
    # Carry any CLI auth headers through the crawl + probe so authenticated pages
    # (and the chat XHR behind a login) are reachable.
    session = SessionManager(AuthConfig(type="header", headers=headers)) if headers else None
    async with HttpClient(config.scope, rate_limit=config.rate_limit, session=session) as client:
        discovered = await HttpCrawler(client, max_pages=max_pages).crawl(base_url)
        try:
            headless, _ = await _run_headless(config, client, base_url, max_pages)
            discovered = [*discovered, *headless]
        except HeadlessUnavailableError:
            pass  # no browser: fall back to whatever the static crawler found
        profiles = await probe_chat_endpoints(client, discovered)
        if not profiles:
            return None, []
        best = profiles[0]
        if best.confidence == "low":
            # Ambiguous shape (a translate/search API can look the same). Report it as a
            # candidate but don't auto-attack — the caller surfaces it for a human to confirm.
            return best, []
        chat = _chat_for(client, best, headers)
        rules = load_ai_rules(extra_wordlist=Path(wordlist) if wordlist else None)
        findings = await AiScanner(chat, rules).scan()

        # Flagship cross-channel check: plant instructions through the app's write
        # endpoints and confirm the assistant executes them on retrieval.
        sinks = infer_write_endpoints(discovered, exclude_urls=[best.url])
        for sink in sinks:
            sink.headers = {**sink.headers, **headers}  # ensure the plant is authenticated
        if sinks:
            findings.extend(await StoredInjectionScanner(client, chat, sinks).scan())

        # Cross-tenant checks (need a second identity + how to name the victim).
        if victim_headers and victim_refs and sinks:
            attacker_sink = WriteEndpoint(
                url=sinks[0].url, field=sinks[0].field, headers={**sinks[0].headers, **headers}
            )
            victim_sink = WriteEndpoint(
                url=sinks[0].url, field=sinks[0].field, headers={**sinks[0].headers, **victim_headers}
            )
            # C · read leak: does the attacker's assistant surface the victim's data?
            attacker = TenantProbe("attacker", chat, attacker_sink, references=[])
            victim = TenantProbe(
                "victim", _chat_for(client, best, victim_headers), victim_sink, references=list(victim_refs)
            )
            findings.extend(await CrossTenantScanner(client, attacker, victim).scan())

            # D · unauthorized action: does the attacker's assistant *write* into the victim's
            # account? Verified out-of-band with a GET (as the victim) on the same resource.
            readback = ReadBack(url=victim_sink.url, method="GET", headers=dict(victim_headers))
            findings.extend(await ActionAgencyScanner(client, chat, readback, list(victim_refs)[0]).scan())
        return best, findings


@app.command("ai")
def ai(
    ctx: typer.Context,
    target: str = typer.Argument(None, help="URL del endpoint de chat/completion (opcional si --ai-config lo define)."),
    i_have_authorization: bool = typer.Option(
        False, "--i-have-authorization", help="Confirma que tienes autorización para probar el objetivo."
    ),
    ai_config: str = typer.Option(
        "", "--ai-config", help="YAML/JSON con la forma del endpoint propio (los flags ganan)."
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
        "", "--ai-template", help="Plantilla JSON del body con {{prompt}} o {{messages}} (anula el preset)."
    ),
    response_path: str = typer.Option(
        "", "--ai-response-path", help="Dot-path al texto de respuesta (anula el preset; auto si se omite)."
    ),
    stream: bool = typer.Option(
        False, "--ai-stream", help="El endpoint responde en streaming (SSE/NDJSON); reensambla los deltas."
    ),
    stream_path: str = typer.Option("", "--ai-stream-path", help="Dot-path al delta por chunk (auto si se omite)."),
    discover: bool = typer.Option(
        False,
        "--discover",
        help="Trata el objetivo como una app web: crawlea, autodetecta el endpoint del chatbot y lo escanea.",
    ),
    max_pages: int = typer.Option(200, "--max-pages", help="Máximo de páginas a recorrer en el crawl de --discover."),
    victim_bearer: str = typer.Option(
        "", "--victim-bearer", help="Token de un SEGUNDO tenant (víctima) para la prueba de fuga cross-tenant."
    ),
    victim_ref: list[str] = typer.Option(
        [], "--victim-ref", help="Cómo referirse al tenant víctima (repetible): 'unit 4B', 'bob'."
    ),
    wordlist: str = typer.Option("", "--ai-wordlist", help="Fichero de payloads de jailbreak extra (uno por línea)."),
    auth_bearer: str = typer.Option("", "--auth-bearer", help="Token Bearer / API key (cabecera Authorization)."),
    auth_header: list[str] = typer.Option([], "--auth-header", help="Cabecera estática 'Nombre=valor' (repetible)."),
    requests_per_second: float = typer.Option(5.0, "--rps", help="Límite de requests por segundo."),
    output_format: str = typer.Option("json", "--format", "-f", help="Formato del reporte: json | sarif | html."),
    output_path: str = typer.Option("", "--output", "-o", help="Ruta de archivo para el reporte."),
    fail_on: str = typer.Option("high", "--fail-on", help="Umbral que hace fallar el proceso (exit 2): ... | none."),
    suppress: str = typer.Option(
        "", "--suppress", help="Archivo de triaje (auto-detecta .dastcore-ignore si se omite)."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Silencia la salida decorativa; solo emite el reporte."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Log de cada petición HTTP (DEBUG)."),
) -> None:
    """Probar un chatbot / LLM (OWASP LLM Top 10): prompt injection (directa/indirecta),
    jailbreak, crescendo multi-turno, fuga de system prompt, secretos/PII, excessive
    agency, output inseguro y denial of wallet. Usa --ai-preset para OpenAI/Anthropic/Ollama/…"""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
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

    suppressions = _load_suppressions_or_exit(suppress)

    # Load an optional endpoint-shape config file; explicit CLI flags win over it.
    ai_file: dict = {}
    if ai_config:
        import yaml

        try:
            ai_file = yaml.safe_load(Path(ai_config).read_text(encoding="utf-8")) or {}
            if not isinstance(ai_file, dict):
                raise ValueError("--ai-config debe ser un mapeo (objeto) en su raíz")
        except (OSError, ValueError) as exc:
            console.print(f"[bold red]--ai-config inválido:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc

    target = target or ai_file.get("target")
    preset = _pick(ctx, "preset", preset, ai_file.get("preset"))
    model = _pick(ctx, "model", model, ai_file.get("model"))
    api_key = _pick(ctx, "api_key", api_key, ai_file.get("api_key"))
    template = _pick(ctx, "template", template, ai_file.get("template"))
    response_path = _pick(ctx, "response_path", response_path, ai_file.get("response_path"))
    prompt_field = _pick(ctx, "prompt_field", prompt_field, ai_file.get("prompt_field"))

    if not target:
        console.print("[bold red]Falta el endpoint:[/bold red] pásalo como argumento o en --ai-config.")
        raise typer.Exit(code=1)

    headers: dict[str, str] = dict(ai_file.get("headers") or {})
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
        if discover:
            victim_headers = {"Authorization": f"Bearer {victim_bearer}"} if victim_bearer else None
            profile, findings = asyncio.run(
                _run_ai_discover_scan(
                    config, str(config.target), headers, wordlist, max_pages, victim_headers, victim_ref
                )
            )
            if profile is None:
                console.print(
                    "\n[bold yellow]No se detectó ningún chatbot embebido[/bold yellow] en el crawl. "
                    "Configúralo a mano con --ai-template / --ai-response-path, o instala el motor headless "
                    "([bold]pip install 'dastcore[headless]'[/bold]) para capturar el XHR del widget."
                )
                raise typer.Exit(code=0)
            if profile.confidence == "low":
                # Ambiguous shape: reported as a candidate, not auto-attacked.
                console.print(
                    f"\n[bold yellow]Posible endpoint de chat (confianza baja)[/bold yellow] en "
                    f"[bold]{profile.url}[/bold] — {profile.evidence}.\n"
                    "Es ambiguo (una API de búsqueda/traducción puede tener la misma forma), así que "
                    "no se ataca automáticamente. Confírmalo y escanéalo directo con "
                    f"[bold]dastcore ai {profile.url} --ai-prompt-field {profile.prompt_field}[/bold]."
                )
                raise typer.Exit(code=0)
            if not quiet:
                console.print(
                    f"[green]Chatbot detectado[/green] ([bold]{profile.confidence}[/bold] confianza) en "
                    f"[bold]{profile.url}[/bold] — {profile.evidence}"
                )
        else:
            findings = asyncio.run(
                _run_ai_scan(
                    config,
                    str(config.target),
                    prompt_field,
                    template,
                    response_path,
                    headers,
                    wordlist,
                    stream,
                    stream_path,
                )
            )
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
        html_title="dastcore — LLM Security Report (OWASP LLM Top 10)",
        group_by_category=True,
        suppressions=suppressions,
    )


@app.command("recon")
def recon(
    program_path: str = typer.Option(..., "--program", help="Ruta a program.yaml con el scope autorizado."),
    profile: str = typer.Option("standard", "--profile", help="Perfil de recon: passive | standard | deep."),
    db_path: str = typer.Option(".dastcore/assets.db", "--db", help="Asset store SQLite (first_seen/last_seen)."),
    output_path: str = typer.Option("", "--output", "-o", help="Exporta los assets descubiertos a JSON."),
    i_have_authorization: bool = typer.Option(
        False, "--i-have-authorization", help="Confirmas autorización sobre el scope del programa."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Solo la tabla de resultados."),
) -> None:
    """Recon externo de la superficie de ataque de un programa autorizado (subdominios → hosts vivos)."""
    from dastcore.bugbounty import load_program
    from dastcore.core.scope import ScopeChecker
    from dastcore.recon import AssetStore, ReconOptions, run_recon

    if not quiet:
        _print_banner()
    if not i_have_authorization:
        console.print("\n[bold red]ABORTADO[/bold red]: se requiere [bold]--i-have-authorization[/bold] para el recon.")
        raise typer.Exit(code=1)
    try:
        program = load_program(program_path)
    except (OSError, ValueError) as exc:
        console.print(f"[red]No se pudo cargar el programa: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    if not program.seeds:
        console.print("[red]El programa no tiene 'seeds' de los que arrancar el recon.[/red]")
        raise typer.Exit(code=1)
    profile = profile if profile in ("passive", "standard", "deep") else "standard"

    checker = ScopeChecker(program.to_scope_config())
    store = AssetStore(db_path)
    opts = ReconOptions(profile=profile)
    active = "sí" if program.allows_active_scanning() else "no (solo pasivo)"
    console.print(
        f"[cyan]Recon[/cyan] {program.handle} · perfil [bold]{profile}[/bold] · scanning activo: {active} · "
        f"seeds: {', '.join(program.seeds)}"
    )
    asyncio.run(run_recon(program.seeds, opts, store, checker, allow_active=program.allows_active_scanning()))

    from dastcore.recon.tiering import by_tier, tier_counts

    assets = by_tier(store.all())  # highest-priority surface first (Tier 1 admin/API/internal → 3)
    tc = tier_counts(assets)
    table = Table(title=f"Assets in-scope ({len(assets)}) · Tier 1: {tc[1]} · Tier 2: {tc[2]} · Tier 3: {tc[3]}")
    for column in ("tier", "host", "url", "status", "tech", "source"):
        table.add_column(column)
    for asset in assets:
        style = {1: "bold red", 2: "yellow", 3: ""}.get(asset.tier, "")
        table.add_row(f"[{style}]T{asset.tier}[/{style}]" if style else f"T{asset.tier}",
                      asset.host, asset.url or "", str(asset.status_code or ""),
                      ",".join(asset.tech), asset.source)
    console.print(table)

    # Safe-harbor hygiene: resolve CNAMEs (passive — hits a resolver, not the target) and flag hosts
    # served by THIRD-PARTY infra. A bug-bounty safe harbor authorises the target's own systems, never a
    # third party's, so these should be excluded from scope even though the *name* is in scope.
    from dastcore.discovery.dns_records import gather_dns_records, third_party_hosts

    own_domains = [*program.scope.domains, *(w.lstrip("*.") for w in program.scope.wildcards)]
    try:
        records = asyncio.run(gather_dns_records([a.host for a in assets]))
        third_party = third_party_hosts(records, own_domains)
    except Exception:  # noqa: BLE001 — CNAME enrichment is best-effort, never fatal
        third_party = {}
    if third_party:
        console.print(
            f"\n[yellow]⚠  {len(third_party)} host(s) apuntan a infraestructura de TERCEROS "
            "(fuera del safe harbor — excluir del scope):[/yellow]"
        )
        for host, target in sorted(third_party.items()):
            console.print(f"   [yellow]{host}[/yellow] → {target}")
        console.print("[dim]Añádelos a scope.out_of_scope en el program.yaml.[/dim]")

    if output_path:
        Path(output_path).write_text(
            _json.dumps([a.model_dump() for a in assets], indent=2, ensure_ascii=False), encoding="utf-8"
        )
        console.print(f"[green]Assets escritos en {output_path}[/green]")
    store.close()


@app.command("hunt")
def hunt(
    program_path: str = typer.Option(..., "--program", help="Ruta a program.yaml con el scope autorizado."),
    profile: str = typer.Option("standard", "--profile", help="Perfil de recon: passive | standard | deep."),
    engine: str = typer.Option("http", "--engine", help="Motor de escaneo: http | headless | both."),
    max_pages: int = typer.Option(200, "--max-pages", help="Máximo de páginas por asset."),
    db_path: str = typer.Option(".dastcore/assets.db", "--db", help="Asset store SQLite del recon."),
    resume_path: str = typer.Option(".dastcore/hunt.json", "--resume", help="Checkpoint por asset (resumible)."),
    output_format: str = typer.Option("json", "--format", "-f", help="Formato del reporte: json | sarif | html."),
    output_path: str = typer.Option("", "--output", "-o", help="Ruta del reporte (por defecto, no se escribe)."),
    discover_ports: bool = typer.Option(
        False, "--discover-ports", help="Escaneo de puertos por host (servicios HTTP no estándar → nuevas raíces)."
    ),
    discover_vhosts: bool = typer.Option(
        False, "--discover-vhosts", help="Fuzzing de virtual hosts por host (se escanean por completo)."
    ),
    osint: bool = typer.Option(
        False, "--osint", help="OSINT organizacional (código público + buckets cloud), una vez por programa."
    ),
    screenshots: bool = typer.Option(
        False, "--screenshots", help="Screenshot headless de cada host escaneado (triaje visual)."
    ),
    i_have_authorization: bool = typer.Option(
        False, "--i-have-authorization", help="Confirmas autorización sobre el scope del programa."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Solo la tabla de hallazgos."),
) -> None:
    """Hunt: recon → escaneo de los assets vivos in-scope de un programa autorizado (resumible)."""
    from dastcore.bugbounty import load_program
    from dastcore.bugbounty.campaign import run_campaign
    from dastcore.recon import AssetStore, ReconOptions

    if not quiet:
        _print_banner()
    if not i_have_authorization:
        console.print("\n[bold red]ABORTADO[/bold red]: se requiere [bold]--i-have-authorization[/bold] para el hunt.")
        raise typer.Exit(code=1)
    try:
        program = load_program(program_path)
    except (OSError, ValueError) as exc:
        console.print(f"[red]No se pudo cargar el programa: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    if not program.seeds:
        console.print("[red]El programa no tiene 'seeds' de los que arrancar el recon.[/red]")
        raise typer.Exit(code=1)
    profile = profile if profile in ("passive", "standard", "deep") else "standard"
    engine = engine if engine in ("http", "headless", "both") else "http"

    store = AssetStore(db_path)
    started = time.monotonic()
    console.print(f"[cyan]Hunt[/cyan] {program.handle} · recon {profile} → escaneo ({engine})…")
    result = asyncio.run(
        run_campaign(
            program,
            authorized=i_have_authorization,
            asset_store=store,
            recon_opts=ReconOptions(profile=profile),
            engine=engine,
            max_pages=max_pages,
            checkpoint_path=resume_path,
            discover_ports=discover_ports,
            discover_vhosts=discover_vhosts,
            osint=osint,
            screenshots=screenshots,
        )
    )
    store.close()

    console.print(
        f"[cyan]Superficie:[/cyan] {len(result.assets)} assets · {len(result.scanned)} escaneados"
        + (
            ""
            if program.allows_active_scanning()
            else " · [yellow]solo recon (el programa prohíbe escaneo automático)[/yellow]"
        )
    )
    _print_findings_table(result.findings)
    _print_summary(result.findings, time.monotonic() - started)
    if output_path and result.findings:
        renderer = {"json": render_json, "sarif": render_sarif}.get(output_format)
        body = (
            renderer(result.findings)
            if renderer
            else render_html(result.findings, title=f"dastcore hunt — {program.handle}")
        )
        Path(output_path).write_text(body, encoding="utf-8")
        console.print(f"[green]Reporte escrito en {output_path}[/green]")


@app.command("benchmark")
def benchmark_cmd(
    output_format: str = typer.Option("text", "--output", "-o", help="text | json | md."),
    out_path: str = typer.Option("", "--out", help="Escribe el scorecard a un fichero."),
    compare: str = typer.Option(
        "", "--compare",
        help="JSON de hallazgos de OTRA herramienta (Finding[] o [{path,family}]) para puntuarla en el mismo target.",
    ),
) -> None:
    """Ejecuta el benchmark de precisión (target etiquetado, offline) e imprime precision/recall/F1 — para
    reproducir el cero-FP de forma verificable. Con --compare, puntúa otra herramienta en el mismo ground truth."""
    try:
        from dastcore.benchmark.app import EXPECTED
        from dastcore.benchmark.runner import run_benchmark
        from dastcore.benchmark.scorer import markdown_table, score_external
    except ImportError as exc:
        console.print(f"[red]El benchmark necesita Flask:[/red] pip install 'dastcore[benchmark]' ({exc})")
        raise typer.Exit(code=1) from exc

    _print_banner()
    console.print("[cyan]Ejecutando el benchmark de precisión (offline)…[/cyan]")
    results = [asyncio.run(run_benchmark())]
    if compare:
        try:
            results.append(score_external(compare, EXPECTED))
        except (OSError, ValueError) as exc:
            console.print(f"[yellow]No pude leer --compare: {exc}[/yellow]")

    if output_format == "json":
        body = _json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2)
    elif output_format == "md":
        body = markdown_table(results)
    else:
        body = "\n\n".join(r.scorecard() for r in results)

    if out_path:
        Path(out_path).write_text(body, encoding="utf-8")
        console.print(f"[green]Scorecard escrito en {out_path}[/green]")
    else:
        console.print(body)
    if results[0].false_positives:  # a false positive is a regression — signal it for CI
        raise typer.Exit(code=2)


@app.command("triage")
def triage_cmd(
    input_path: str = typer.Option(..., "--input", "-i", help="JSON de hallazgos (salida de `scan`/`hunt` -f json)."),
    output_format: str = typer.Option("text", "--output", "-o", help="text | json."),
    top: int = typer.Option(0, "--top", help="Muestra solo los N clusters prioritarios (0 = todos)."),
) -> None:
    """Copilot de triaje: agrupa los hallazgos por clase+punto de inyección *entre hosts*, los prioriza y
    separa los de posible falso positivo — para saber qué mirar primero. Determinista, sin IA."""
    try:
        data = _json.loads(Path(input_path).read_text(encoding="utf-8"))
        findings = [Finding.model_validate(item) for item in data]
    except (OSError, ValueError) as exc:
        console.print(f"[red]No se pudo leer '{input_path}': {exc}[/red]")
        raise typer.Exit(code=1) from exc
    digest = build_digest(findings)
    if output_format == "json":
        console.print_json(_json.dumps(digest.to_dict(), ensure_ascii=False))
        return
    _print_triage_digest(digest, top=top)


@app.command("import-program")
def import_program_cmd(
    policy_file: str = typer.Argument(..., help="Fichero de texto con la política/scope pegada del programa."),
    out_path: str = typer.Option("program.yaml", "--out", "-o", help="Fichero program.yaml a escribir (para `hunt`)."),
    platform: str = typer.Option("hackerone", "--platform", help="hackerone | bugcrowd | intigriti | immunefi | self."),
    handle: str = typer.Option("", "--handle", help="Handle del programa (si no, se deduce del enlace pegado)."),
) -> None:
    """Importa un programa (Modo A): parsea la política pegada → program.yaml listo para revisar y usar con `hunt`."""
    import yaml as _yaml

    from dastcore.bugbounty import parse_program_policy

    _print_banner()
    try:
        text = Path(policy_file).read_text(encoding="utf-8")
    except OSError as exc:
        console.print(f"[red]No se pudo leer '{policy_file}': {exc}[/red]")
        raise typer.Exit(code=1) from exc

    result = parse_program_policy(text, platform=platform, handle=handle)
    program = result.program

    console.print(f"\n[bold cyan]Programa importado[/bold cyan]: {program.handle} ({program.platform})")
    console.print(f"  En alcance : {', '.join(program.scope.allow_patterns()) or '[yellow]ninguno[/yellow]'}")
    if program.scope.out_of_scope:
        console.print(f"  Fuera      : {', '.join(program.scope.out_of_scope)}")
    console.print(f"  Límites    : {program.limits.requests_per_second} req/s · concurrencia "
                  f"{program.limits.max_concurrency}"
                  + ("" if program.allows_active_scanning() else " · [yellow]solo recon[/yellow]"))
    if program.required_headers:
        console.print(f"  Cabeceras  : {program.required_headers}")
    console.print(f"  Bug-bounty : {'sí' if program.bug_bounty_mode else 'no'}")
    if result.filtered:
        console.print(f"  [dim]Descartados (no-web): {', '.join(result.filtered[:6])}"
                      f"{'…' if len(result.filtered) > 6 else ''}[/dim]")
    if result.notes:
        console.print("\n[bold]Notas para revisar:[/bold]")
        for note in result.notes:
            console.print(f"  • {note}")

    if not program.scope.allow_patterns():
        console.print("\n[red]No se detectó ningún host en alcance — revisa el texto pegado.[/red]")
        raise typer.Exit(code=1)

    Path(out_path).write_text(
        _yaml.safe_dump(program.model_dump(exclude_defaults=True), sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    console.print(f"\n[green]Escrito {out_path}[/green]. Revísalo y lanza el hunt:")
    console.print(f"  [cyan]dastcore hunt {out_path} --i-have-authorization[/cyan]")


@app.command("report")
def report_cmd(
    input_path: str = typer.Option(..., "--input", help="JSON de hallazgos (salida de `scan`/`hunt` -f json)."),
    finding_id: str = typer.Option("", "--finding", help="ID del hallazgo (vacío = el de mayor prioridad)."),
    platform: str = typer.Option("generic", "--platform", help="hackerone | bugcrowd | generic."),
    program_path: str = typer.Option("", "--program", help="Opcional: program.yaml (payout/handle)."),
    sast_path: str = typer.Option(
        "", "--sast", help="Opcional: SARIF de SastScore; confirma SAST+DAST y sube confianza."
    ),
    output_path: str = typer.Option("", "--output", "-o", help="Ruta del borrador Markdown (por defecto, stdout)."),
) -> None:
    """Genera un borrador de submission (Markdown, impact-first) para revisión humana; nunca lo envía."""
    from dastcore.bugbounty import load_program, triage_for_bounty
    from dastcore.bugbounty.report import PLATFORMS, render_bounty_report
    from dastcore.report.correlation import correlate_sast_dast, parse_sarif

    try:
        data = _json.loads(Path(input_path).read_text(encoding="utf-8"))
        findings = [Finding.model_validate(item) for item in data]
    except (OSError, ValueError) as exc:
        console.print(f"[red]No se pudieron cargar los hallazgos: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    if not findings:
        console.print("[red]El archivo de hallazgos está vacío.[/red]")
        raise typer.Exit(code=1)
    if sast_path:
        try:
            sast = parse_sarif(_json.loads(Path(sast_path).read_text(encoding="utf-8")))
            correlate_sast_dast(findings, sast)  # raises confidence on findings confirmed by SAST
        except (OSError, ValueError) as exc:
            console.print(f"[yellow]No se pudo leer el SARIF de SAST ({exc}); continúo sin correlación.[/yellow]")
    platform = platform if platform in PLATFORMS else "generic"
    program = None
    if program_path:
        try:
            program = load_program(program_path)
        except (OSError, ValueError):
            program = None

    bounties = triage_for_bounty(findings, program)
    if not bounties:
        console.print("[yellow]Ningún hallazgo pasó el triaje bounty (ruido/FP).[/yellow]")
        raise typer.Exit(code=1)
    if finding_id:
        chosen = next((b for b in bounties if b.finding.id == finding_id), None)
        if chosen is None:
            available = ", ".join(b.finding.id for b in bounties[:10])
            console.print(f"[red]No se encontró el hallazgo '{finding_id}'. Disponibles: {available}[/red]")
            raise typer.Exit(code=1)
    else:
        chosen = bounties[0]  # el de mayor prioridad

    draft = render_bounty_report(chosen, program, platform)
    if output_path:
        Path(output_path).write_text(draft, encoding="utf-8")
        console.print(f"[green]Borrador ({platform}) escrito en {output_path}[/green]")
    else:
        console.print(draft)


@app.command("seclists")
def seclists_cmd(
    install: bool = typer.Option(
        False, "--install", help="Descarga los diccionarios de SecLists (grandes, ~35 MB, una sola vez)."
    ),
) -> None:
    """Gestiona los diccionarios de SecLists para el descubrimiento (subdominios, rutas, parámetros).

    Sin flags, muestra qué diccionarios están descargados. Con --install los descarga a
    ~/.dastcore/seclists; luego se seleccionan por nombre (--content-wordlist seclists-content, etc.)
    o desde el desplegable del panel."""
    from dastcore.discovery.seclists import download_presets, seclists_dir, status

    if install:
        console.print(f"[green]Descargando SecLists a[/green] [bold]{seclists_dir()}[/bold] …")
        done = asyncio.run(download_presets(on_progress=lambda n: console.print(f"  [dim]✓ {n}[/dim]")))
        console.print(f"\n[bold green]Listo:[/bold green] {len(done)} diccionario(s) disponibles.\n")

    console.print(f"[bold]SecLists[/bold]  ·  {seclists_dir()}")
    for row in status():
        mark = "[green]✓[/green]" if row["downloaded"] else "[dim]—[/dim]"
        size = f"{int(row['size']) / 1024 / 1024:.1f} MB" if row["downloaded"] else ""  # type: ignore[call-overload]
        console.print(f"  {mark} [bold]{row['name']}[/bold]  [dim]({row['category']})[/dim]  {size}")
    if not any(r["downloaded"] for r in status()):
        console.print("\n[yellow]Aún no hay diccionarios.[/yellow] Ejecuta [bold]dastcore seclists --install[/bold].")


@app.command("wordlists")
def wordlists_cmd(
    add: bool = typer.Option(False, "--add", help="Añade un diccionario propio (requiere --name y --url o --file)."),
    category: str = typer.Option("content", "--category", help="Categoría: content | subdomains | params."),
    name: str = typer.Option("", "--name", help="Nombre del diccionario (aparecerá en los desplegables)."),
    url: str = typer.Option("", "--url", help="URL de descarga del diccionario."),
    file: str = typer.Option("", "--file", help="Fichero local cuyo contenido se copia como diccionario propio."),
) -> None:
    """Diccionarios propios: descarga uno (o copia un fichero) y queda disponible para todos los escaneos.

    Sin flags, lista los diccionarios propios ya añadidos por categoría. Con --add --name X y --url/--file,
    lo guarda en ~/.dastcore/seclists/custom y se selecciona por su ruta (o desde el desplegable del panel)."""
    from dastcore.discovery.seclists import add_custom_wordlist, custom_wordlists

    if add:
        if not name or (not url and not file):
            console.print("[red]--add requiere --name y (--url o --file).[/red]")
            raise typer.Exit(code=1)
        text = Path(file).read_text(encoding="utf-8", errors="ignore") if file else None
        try:
            path = asyncio.run(add_custom_wordlist(category, name, url=url or None, text=text))
        except (ValueError, httpx.HTTPError, OSError) as exc:
            console.print(f"[red]No se pudo añadir el diccionario:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        console.print(f"[green]Añadido[/green] [bold]{path.stem}[/bold] → {path}")

    console.print("[bold]Diccionarios propios[/bold]")
    any_found = False
    for cat in ("content", "subdomains", "params"):
        options = custom_wordlists(cat)
        if options:
            any_found = True
            console.print(f"  [dim]{cat}[/dim]")
            for value, label in options:
                console.print(f"    [bold]{label}[/bold]  [dim]{value}[/dim]")
    if not any_found:
        console.print(
            "  [yellow]Ninguno todavía.[/yellow] Añade uno: "
            "[bold]dastcore wordlists --add --name mi-lista --url https://…/lista.txt[/bold]"
        )


@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Interfaz donde escuchar. 127.0.0.1 = solo local."),
    port: int = typer.Option(8000, "--port", help="Puerto del panel web."),
    db_path: str = typer.Option(
        "", "--db", help="Ruta del SQLite con el historial (por defecto ~/.dastcore/dastcore.db)."
    ),
) -> None:
    """Lanza el panel web local (dashboard): iniciar escaneos desde un formulario,
    ver el progreso en vivo y navegar el historial de hallazgos, reusando el motor."""
    try:
        from dastcore.web.server import default_db_path, run_server
    except ModuleNotFoundError as exc:
        console.print(
            f"[bold red]El panel web requiere dependencias extra:[/bold red] {exc.name}.\n"
            "Instálalas con: [bold]pip install 'dastcore[web]'[/bold]"
        )
        raise typer.Exit(code=1) from exc

    from dastcore.obslog import configure_logging

    configure_logging()
    _print_banner()
    resolved_db = db_path or str(default_db_path())
    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            f"\n[bold yellow]Aviso:[/bold yellow] escuchando en [bold]{host}[/bold] (no solo local). "
            "El panel puede lanzar escaneos intrusivos: exponlo solo en redes de confianza."
        )
    console.print(
        f"\n[green]Panel dastcore en[/green] [bold]http://{host}:{port}[/bold]  ·  "
        f"historial: [dim]{resolved_db}[/dim]\n[dim]Ctrl+C para detener.[/dim]\n"
    )
    run_server(host, port, resolved_db)


@app.command("cloud-serve")
def cloud_serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Interfaz donde escuchar."),
    port: int = typer.Option(8800, "--port", help="Puerto del control-plane."),
    db_path: str = typer.Option("", "--db", help="SQLite del control-plane (por defecto ~/.dastcore/cloud.db)."),
    admin_token: str = typer.Option(
        "", "--admin-token", help="Token de administración para crear proyectos (se genera si se omite)."
    ),
) -> None:
    """Lanza el control-plane cloud: encola trabajos de escaneo y guarda resultados,
    que los runners self-hosted reclaman y ejecutan en la red del objetivo."""
    try:
        import uvicorn

        from dastcore.cloud.app import create_app
    except ModuleNotFoundError as exc:
        console.print(
            f"[bold red]El control-plane requiere dependencias extra:[/bold red] {exc.name}.\n"
            "Instálalas con: [bold]pip install 'dastcore[web]'[/bold]"
        )
        raise typer.Exit(code=1) from exc

    import os as _os
    import secrets as _secrets
    from pathlib import Path as _Path

    from dastcore.obslog import configure_logging

    configure_logging()
    _print_banner()
    resolved_db = db_path or _os.environ.get("DASTCORE_DB", "") or str(_Path.home() / ".dastcore" / "cloud.db")
    # Precedence: --admin-token flag > DASTCORE_ADMIN_TOKEN env (for container deploys) > generated.
    provided_token = admin_token or _os.environ.get("DASTCORE_ADMIN_TOKEN", "")
    token = provided_token or ("admin_" + _secrets.token_urlsafe(24))
    if not provided_token:
        console.print(
            f"\n[yellow]Admin token generado:[/yellow] [bold]{token}[/bold]  [dim](úsalo para crear proyectos)[/dim]"
        )
    console.print(
        f"\n[green]Control-plane dastcore en[/green] [bold]http://{host}:{port}[/bold]  ·  "
        f"[dim]{resolved_db}[/dim]\n[dim]Ctrl+C para detener.[/dim]\n"
    )
    uvicorn.run(create_app(resolved_db, admin_token=token), host=host, port=port, log_level="warning")


async def _run_runner(
    server: str, token: str, project_key: str, runner_name: str, poll_seconds: float, once: bool
) -> None:
    from dastcore.cloud.runner import register_runner, run_forever, run_once

    async with httpx.AsyncClient(base_url=server.rstrip("/"), timeout=None) as client:
        runner_token = token
        if not runner_token:
            runner_token = await register_runner(client, project_key, runner_name)
            console.print(f"[green]Runner registrado[/green] como [bold]{runner_name}[/bold].")
        if once:
            handled = await run_once(client, runner_token)
            console.print("Trabajo ejecutado." if handled else "No había trabajos en cola.")
        else:
            await run_forever(client, runner_token, poll_seconds=poll_seconds)


@app.command("runner")
def runner(
    server: str = typer.Argument(..., help="URL del control-plane (p.ej. https://cloud.example.com)."),
    token: str = typer.Option("", "--token", help="Token de runner (si ya lo tienes)."),
    project_key: str = typer.Option(
        "", "--project-key", help="API key del proyecto: registra este runner y obtiene su token."
    ),
    i_have_authorization: bool = typer.Option(
        False, "--i-have-authorization", help="Confirma autorización para escanear los objetivos que reciba."
    ),
    runner_name: str = typer.Option("runner", "--name", help="Nombre de este runner (aparece en el control-plane)."),
    poll_seconds: float = typer.Option(5.0, "--poll", help="Segundos entre sondeos cuando no hay trabajos."),
    once: bool = typer.Option(False, "--once", help="Ejecuta un solo trabajo (si lo hay) y termina."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Log de actividad (INFO)."),
) -> None:
    """Runner self-hosted: reclama trabajos del control-plane y los escanea localmente.

    Ejecútalo dentro de la red que tiene acceso a los objetivos. El tráfico intrusivo
    sale de esta máquina, no del cloud. Pasa un --token de runner, o --project-key para
    registrarte y obtener uno automáticamente."""
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    _print_banner()
    if not i_have_authorization:
        console.print("\n[bold red]ABORTADO[/bold red]: se requiere [bold]--i-have-authorization[/bold].")
        raise typer.Exit(code=1)
    if not token and not project_key:
        console.print(
            "\n[bold red]Falta credencial:[/bold red] pasa [bold]--token[/bold] o [bold]--project-key[/bold]."
        )
        raise typer.Exit(code=1)

    console.print(
        f"\n[green]Runner[/green] [bold]{runner_name}[/bold] conectado a [bold]{server}[/bold]"
        + (" · un solo trabajo" if once else f" · sondeo cada {poll_seconds}s")
        + "\n[dim]Ctrl+C para detener.[/dim]\n"
    )
    try:
        asyncio.run(_run_runner(server, token, project_key, runner_name, poll_seconds, once))
    except httpx.HTTPError as exc:
        console.print(f"\n[bold red]Error hablando con el control-plane:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc


@auth_app.command("record")
def auth_record(
    url: str = typer.Argument(..., help="URL de la página de login por la que empezar la grabación."),
    out: str = typer.Option("login-macro.json", "--out", "-o", help="Fichero donde guardar la macro."),
) -> None:
    """Abre un navegador, graba tu login (fills/clicks) y guarda una macro reproducible.

    Las contraseñas se graban como el placeholder {{password}}, nunca el valor literal —
    lo aportas al reproducir con --auth-macro-var password=…"""
    from dastcore.auth.recorder import record_macro, save_macro
    from dastcore.discovery.crawler_headless import HeadlessUnavailableError

    console.print(f"\n[green]Grabando login[/green] desde [bold]{url}[/bold] (navegador headed)…")
    try:
        macro = asyncio.run(record_macro(url))
    except HeadlessUnavailableError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from exc
    save_macro(macro, out)
    console.print(f"[green]Macro guardada[/green] en [bold]{out}[/bold] · {len(macro.steps)} paso(s).")
    console.print(
        f"Úsala con: [bold]dastcore scan <url> --i-have-authorization --auth-macro {out} "
        "--auth-macro-var password=…[/bold]"
    )


@auth_app.command("replay")
def auth_replay(
    macro_file: str = typer.Argument(..., help="Fichero de macro (.json) a reproducir."),
    base_url: str = typer.Option("", "--base-url", help="Reapunta el login grabado a otro origen (mismo path)."),
    var: list[str] = typer.Option([], "--var", help="Valor runtime de un placeholder: 'name=valor' (repetible)."),
) -> None:
    """Reproduce una macro headless y muestra las cookies de sesión obtenidas (para verificarla)."""
    from dastcore.auth.recorder import load_macro, replay_macro
    from dastcore.discovery.crawler_headless import HeadlessUnavailableError

    try:
        runtime = _parse_kv_list(var, "--var")
        cookies = asyncio.run(replay_macro(load_macro(macro_file), runtime=runtime, base_url=base_url or None))
    except HeadlessUnavailableError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from exc
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]No se pudo leer/reproducir la macro:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    if not cookies:
        console.print("[bold yellow]La macro no estableció cookies de sesión.[/bold yellow] Revisa los pasos.")
        raise typer.Exit(code=1)
    console.print(f"[green]{len(cookies)} cookie(s) de sesión:[/green]")
    console.print(_json.dumps(cookies, indent=2, ensure_ascii=False))


def _load_findings_file(path: str) -> list[Finding]:
    """Parse a scan JSON report (`scan -f json`) into findings, or exit with a clear error."""
    try:
        return load_prior_findings(_json.loads(Path(path).read_text(encoding="utf-8")))
    except (OSError, ValueError, ValidationError) as exc:
        console.print(f"[bold red]JSON de hallazgos inválido:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc


def _severity_breakdown(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    parts = [f"{counts[sev]} {sev}" for sev in ("critical", "high", "medium", "low", "info") if counts.get(sev)]
    return " · ".join(parts) if parts else "sin hallazgos"


@baseline_app.command("promote")
def baseline_promote(
    current_file: str = typer.Argument(
        ..., help="JSON del escaneo a adoptar como línea base (salida de scan -f json)."
    ),
    baseline_path: str = typer.Option(
        _DEFAULT_BASELINE, "--baseline", "-b", help="Ruta del fichero de línea base a escribir."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Silencia el resumen."),
) -> None:
    """Adopta un escaneo como la nueva línea base para `dastcore diff` en CI.

    Valida el JSON, lo escribe normalizado en la ruta de línea base (creando los directorios
    necesarios) y muestra un resumen. Ejecútalo cuando aceptes deliberadamente el estado actual
    de hallazgos: a partir de ahí, `dastcore diff <baseline> <actual>` solo falla ante
    hallazgos NUEVOS respecto a esta línea base."""
    findings = _load_findings_file(current_file)
    path = Path(baseline_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_json(findings), encoding="utf-8")
    if not quiet:
        console.print(
            f"[green]Línea base actualizada:[/green] {len(findings)} hallazgos "
            f"({_severity_breakdown(findings)}) → [bold]{path}[/bold]"
        )


@baseline_app.command("status")
def baseline_status(
    baseline_path: str = typer.Option(
        _DEFAULT_BASELINE, "--baseline", "-b", help="Ruta del fichero de línea base a inspeccionar."
    ),
) -> None:
    """Muestra un resumen de la línea base actual (cuántos hallazgos y de qué severidad)."""
    if not Path(baseline_path).exists():
        console.print(f"[yellow]No hay línea base en[/yellow] [bold]{baseline_path}[/bold] (usa 'baseline promote').")
        raise typer.Exit(code=0)
    findings = _load_findings_file(baseline_path)
    console.print(
        f"[bold]Línea base:[/bold] {baseline_path}\n{len(findings)} hallazgos · {_severity_breakdown(findings)}"
    )


if __name__ == "__main__":
    app()
