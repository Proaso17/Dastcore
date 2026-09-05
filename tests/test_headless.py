"""Phase 5: headless (Playwright) crawler + DOM-based XSS.

These tests require Playwright and its Chromium browser. If either is missing
they skip cleanly rather than fail, so the rest of the suite stays green on
machines without a browser installed (`python -m playwright install chromium`).
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
import pytest

pytest.importorskip("playwright.async_api")

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.discovery.crawler_headless import HeadlessEngine, HeadlessUnavailableError
from dastcore.discovery.crawler_http import HttpCrawler
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner

_SCOPE = ScopeConfig(allow_domains=["127.0.0.1"])


@asynccontextmanager
async def headless_engine(**kwargs):
    try:
        async with HeadlessEngine(_SCOPE, **kwargs) as engine:
            yield engine
    except HeadlessUnavailableError as exc:
        pytest.skip(str(exc))


async def test_headless_discovers_js_rendered_links_and_xhr(vuln_app_url: str) -> None:
    async with headless_engine(max_pages=10) as engine:
        discovered = await engine.crawl(f"{vuln_app_url}/spa")

    urls = {req.url for req in discovered}
    # JS-generated link, invisible to a static crawler
    assert any(u.endswith("/spa/item") for u in urls), urls
    # captured fetch() XHR call
    assert any(u.endswith("/api/spa-data") for u in urls), urls

    item = next(req for req in discovered if req.url.endswith("/spa/item"))
    assert item.params.get("id") in {"1", "2"}


async def test_static_crawler_is_blind_to_spa_content(vuln_app_url: str) -> None:
    """Contrast: the static crawler only sees the empty shell — this is the differentiator."""
    async with HttpClient(_SCOPE) as client:
        discovered = await HttpCrawler(client).crawl(f"{vuln_app_url}/spa")
    urls = {req.url for req in discovered}
    assert any(u.endswith("/spa") for u in urls)
    assert not any(u.endswith("/spa/item") for u in urls)
    assert not any(u.endswith("/api/spa-data") for u in urls)


async def test_headless_detects_dom_based_xss(vuln_app_url: str) -> None:
    async with headless_engine() as engine:
        findings = await engine.scan_dom_xss([f"{vuln_app_url}/spa"])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "dom-xss"
    assert finding.severity == "high"
    assert finding.injection_point.location == "fragment"
    assert finding.evidence[0].type == "dom_execution"


async def test_headless_no_dom_xss_false_positive_on_clean_page(vuln_app_url: str) -> None:
    """/greet reflects a query param server-side but has no client-side fragment sink."""
    async with headless_engine() as engine:
        findings = await engine.scan_dom_xss([f"{vuln_app_url}/greet", f"{vuln_app_url}/health"])
    assert findings == []


async def test_headless_recycles_browser_without_losing_functionality(vuln_app_url: str) -> None:
    # Recycle after every page opened → the crawl must still discover the SPA's JS-rendered endpoints,
    # proving the fresh browser re-applies auth/stealth/localStorage material (the OOM guard for long scans).
    async with headless_engine(max_pages=10, recycle_every=1) as engine:
        discovered = await engine.crawl(f"{vuln_app_url}/spa")
    urls = {req.url for req in discovered}
    assert any(u.endswith("/spa/item") for u in urls), urls


async def test_headless_navigation_cap_stops_the_crawl(vuln_app_url: str) -> None:
    # A hard cap of 1 total navigation stops the crawl almost immediately — it must return cleanly,
    # never run unbounded (the robustness guard that prevents 3-hour scans / OOM).
    async with headless_engine(max_pages=50, max_navigations=1) as engine:
        discovered = await engine.crawl(f"{vuln_app_url}/spa")
    assert isinstance(discovered, list)
    assert engine._nav_count <= 1  # the cap was honored: it did not keep opening pages


async def test_local_storage_injection_makes_the_spa_authenticate(vuln_app_url: str) -> None:
    # Seed localStorage before the SPA boots (as for a Supabase session): the page then calls its API
    # with the token, which the crawl captures — proving the browser rendered "logged in".
    async with headless_engine(local_storage={"sb-test-auth-token": "SESSION-XYZ"}) as engine:
        discovered = await engine.crawl(f"{vuln_app_url}/spa-localstorage")
    urls = {req.url + "?" + "&".join(f"{k}={v}" for k, v in req.params.items()) for req in discovered}
    assert any("/api/ls-echo" in u and "SESSION-XYZ" in u for u in urls), urls


async def test_without_local_storage_the_spa_stays_logged_out(vuln_app_url: str) -> None:
    async with headless_engine() as engine:  # no seeded session
        discovered = await engine.crawl(f"{vuln_app_url}/spa-localstorage")
    assert not any("/api/ls-echo" in req.url for req in discovered)  # the gated API call never fires


def test_supabase_local_storage_only_for_supabase_form_login() -> None:
    import asyncio

    from dastcore.cli import _supabase_local_storage
    from dastcore.config import AuthConfig, FormLoginConfig

    # A non-Supabase / non-form auth yields nothing (feature is inert unless it applies).
    assert asyncio.run(_supabase_local_storage(AuthConfig(type="none"))) == {}
    plain = AuthConfig(type="form", form=FormLoginConfig(login_url="https://app.example.com/login"))
    assert asyncio.run(_supabase_local_storage(plain)) == {}


def test_is_dangerous_flags_destructive_labels_only() -> None:
    from dastcore.discovery.crawler_headless import _is_dangerous

    for bad in ("Eliminar cuenta", "Delete", "Logout", "Cerrar sesión", "Pagar ahora", "Enviar",
                "Confirmar", "Guardar cambios", "Transferir", "Cancelar"):
        assert _is_dangerous(bad) is True, bad
    for ok in ("Ver detalles", "Abrir", "Más info", "Siguiente", "Perfil", "Inicio", "Detalles", "Filtrar"):
        assert _is_dangerous(ok) is False, ok


async def test_interactive_crawl_finds_click_only_endpoints_and_skips_destructive(vuln_app_url: str) -> None:
    async with headless_engine(interactive=True) as engine:
        discovered = await engine.crawl(f"{vuln_app_url}/spa-click")
    urls = {req.url for req in discovered}
    assert any(u.endswith("/api/click-data") for u in urls), urls  # the SAFE click triggered its XHR
    assert not any("danger-deleted" in u for u in urls), urls  # the destructive button was NEVER clicked


async def test_non_interactive_crawl_misses_click_only_endpoints(vuln_app_url: str) -> None:
    # Contrast: without interaction the load-only crawl never triggers the click's fetch, so it's missed.
    async with headless_engine(interactive=False) as engine:
        discovered = await engine.crawl(f"{vuln_app_url}/spa-click")
    assert not any(req.url.endswith("/api/click-data") for req in discovered)


async def test_headless_detects_client_side_template_injection(vuln_app_url: str) -> None:
    """/csti reflects input into a client-side {{ }} template engine — the product only appears
    after JS renders, never in the raw response, so it's CSTI (not SSTI)."""
    req = HttpRequest(method="GET", url=f"{vuln_app_url}/csti", params={"name": "seed"})
    async with headless_engine() as engine:
        findings = await engine.scan_csti([req])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "csti"
    assert f.severity == "high"
    assert f.injection_point.name == "name"
    assert f.evidence[0].type == "dom_execution"


async def test_headless_no_csti_false_positive_on_server_side_reflection(vuln_app_url: str) -> None:
    """/greet reflects the param server-side but never evaluates {{ }} in the browser — no CSTI."""
    req = HttpRequest(method="GET", url=f"{vuln_app_url}/greet", params={"name": "seed"})
    async with headless_engine() as engine:
        findings = await engine.scan_csti([req])
    assert findings == []


async def test_headless_reuses_authenticated_session(vuln_app_url: str) -> None:
    login = httpx.post(f"{vuln_app_url}/auth/form-login", json={"username": "carol", "password": "carol-pw"})
    sid = login.cookies["sid"]

    async with headless_engine(cookies={"sid": sid}, cookie_url=vuln_app_url) as engine:
        discovered = await engine.crawl(f"{vuln_app_url}/dashboard")
    urls = {req.url for req in discovered}
    assert any(u.endswith("/dashboard/secret") for u in urls), urls


async def test_headless_without_session_cannot_see_authenticated_links(vuln_app_url: str) -> None:
    async with headless_engine() as engine:
        discovered = await engine.crawl(f"{vuln_app_url}/dashboard")
    urls = {req.url for req in discovered}
    assert not any(u.endswith("/dashboard/secret") for u in urls)


async def test_headless_discovered_endpoint_is_scannable(vuln_app_url: str) -> None:
    """Full value: headless finds /spa/item, then the normal active scanner confirms its reflected XSS."""
    async with headless_engine(max_pages=10) as engine:
        discovered = await engine.crawl(f"{vuln_app_url}/spa")

    rules = load_rules()
    async with HttpClient(_SCOPE) as client:
        findings = await Scanner(client, rules).scan(discovered)
    assert any(f.id.startswith("xss-reflected:") and "/spa/item" in f.request.url for f in findings), [
        f.id for f in findings
    ]
