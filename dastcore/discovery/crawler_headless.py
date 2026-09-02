"""Headless crawler (Playwright / Chromium).

Renders JavaScript so it can see what a static HTML crawl cannot: SPA content,
JS-generated links and forms, and the XHR/fetch API calls a page makes at
runtime. It reuses the authenticated session by seeding the browser context
with the scanner's cookies and header material, and it enforces scope on every
captured URL. Discovered items are returned as the same `HttpRequest` model the
static crawler produces, so the active scanner consumes both uniformly.

Playwright is imported lazily so the rest of dastcore works without it installed.
"""

from __future__ import annotations

import json
import re
from collections import deque
from urllib.parse import parse_qsl, urlsplit

from dastcore.config import ScopeConfig
from dastcore.core.models import Finding, HttpRequest
from dastcore.core.scope import ScopeChecker
from dastcore.detectors.csti import probe_csti
from dastcore.detectors.dom_xss import probe_dom_xss
from dastcore.discovery.crawler_http import _is_logout

_FORM_EXTRACT_JS = """
() => Array.from(document.querySelectorAll('form')).map(f => ({
  action: f.action,
  method: (f.getAttribute('method') || 'GET').toUpperCase(),
  inputs: Object.fromEntries(
    Array.from(f.querySelectorAll('input,textarea,select'))
      .filter(i => i.name)
      .map(i => [i.name, i.value || ''])
  )
}))
"""


# A realistic recent-Chrome UA — the default headless UA contains "HeadlessChrome", which bot-detection
# (Cloudflare, Akamai…) flags instantly. Overridable so a researcher can match their real browser's UA.
_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# Launch flags that reduce automation fingerprints. AutomationControlled is the big one: it stops
# Chromium from advertising itself as automated (removes the tell that sets navigator.webdriver).
_STEALTH_LAUNCH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--disable-dev-shm-usage",
]

# Injected before any page script runs: patches the properties bot-detectors check to tell a headless
# browser from a real one (webdriver flag, window.chrome, plugins, languages, permissions API).
_STEALTH_INIT_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.chrome = window.chrome || { runtime: {} };
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
const _q = window.navigator.permissions && window.navigator.permissions.query;
if (_q) {
  window.navigator.permissions.query = (p) =>
    p && p.name === 'notifications'
      ? Promise.resolve({ state: Notification.permission })
      : _q(p);
}
"""


# Interactive-crawl safety: elements we may click to trigger navigation/XHR (never form-submit buttons),
# and labels that mark a *destructive* control we must never click, so an interactive crawl can't cause
# side effects (delete/logout/pay/submit…). The label guard is re-checked at click time (DOM may shift).
_SAFE_CLICK_SELECTOR = (
    "button:not([type=submit]):not([type=reset]), [role=button], [role=tab], [role=menuitem], "
    "[role=link], a:not([href]), a[href^='#'], nav li, .tab, .nav-link, [data-toggle], [aria-expanded]"
)
_DANGEROUS_LABEL = re.compile(
    r"delete|remove|borrar|elimin|logout|log\s*out|sign\s*out|cerrar\s*sesi|salir|"
    r"pay|pagar|buy|comprar|purchase|checkout|order|submit|enviar|send|confirm|confirmar|"
    r"save|guardar|update|actualizar|create|crear|add\b|añadir|agregar|transfer|transferir|"
    r"deactivate|disable|desactivar|cancel|cancelar|reset|restablecer|approve|aprobar|reject|"
    r"publish|publicar|unsubscribe|block|ban|archive|archivar|invite|invitar|upload|subir",
    re.IGNORECASE,
)


def _is_dangerous(label: str) -> bool:
    """True if an element's visible text/label suggests a state-changing action we must not click."""
    return bool(_DANGEROUS_LABEL.search(label or ""))


class HeadlessUnavailableError(RuntimeError):
    """Raised when Playwright or its Chromium browser is not available."""


class HeadlessEngine:
    """Owns the browser lifecycle; provides authenticated JS-rendering crawl + DOM-XSS."""

    def __init__(
        self,
        scope: ScopeConfig,
        *,
        cookies: dict[str, str] | None = None,
        cookie_url: str | None = None,
        extra_headers: dict[str, str] | None = None,
        max_pages: int = 100,
        nav_timeout_ms: int = 8000,
        stealth: bool = True,
        user_agent: str | None = None,
        proxy: str | None = None,
        interactive: bool = False,
        max_clicks: int = 12,
    ) -> None:
        self._scope = ScopeChecker(scope)
        self._cookies = cookies or {}
        self._cookie_url = cookie_url
        self._headers = extra_headers or {}
        self._max_pages = max_pages
        self._nav_timeout = nav_timeout_ms
        # Stealth: present the headless browser as a normal one so bot-detection/WAFs (Cloudflare…) let
        # it through. On by default; a caller can pass a user_agent to match their real browser exactly.
        self._stealth = stealth
        self._user_agent = user_agent or (_DEFAULT_UA if stealth else None)
        # Interactive SPA crawl (opt-in): after load, click SAFE elements to trigger the XHR/fetch a
        # React/Vue app only makes on interaction — discovering the real API surface. Off by default,
        # so a normal scan is unchanged; safe-click heuristics never touch destructive controls.
        self._interactive = interactive
        self._max_clicks = max(0, max_clicks)
        # Route the browser through a proxy/VPN so its traffic exits from a trusted IP (bypasses WAF
        # IP-reputation blocks). Same proxy the HTTP client uses, so both engines share the exit IP.
        self._proxy = proxy
        self._captured: dict[str, HttpRequest] = {}
        self._pw = None
        self._browser = None
        self._context = None

    async def __aenter__(self) -> HeadlessEngine:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:  # pragma: no cover - depends on optional dep
            raise HeadlessUnavailableError(
                "Playwright no está instalado. Instala el extra: pip install 'dastcore[headless]'"
            ) from exc

        self._pw = await async_playwright().start()
        launch_args = _STEALTH_LAUNCH_ARGS if self._stealth else []
        launch_kwargs: dict = {"args": launch_args}
        if self._proxy:
            launch_kwargs["proxy"] = {"server": self._proxy}  # route the browser via the proxy/VPN
        try:
            self._browser = await self._pw.chromium.launch(**launch_kwargs)
        except Exception as exc:  # pragma: no cover - depends on browser download
            await self._pw.stop()
            raise HeadlessUnavailableError(
                "No se pudo lanzar Chromium. Ejecuta: python -m playwright install chromium"
            ) from exc

        # A real-looking context: a proper UA + viewport + locale, and an Accept-Language header — the
        # cheap tells a WAF checks before it even runs a JS challenge.
        context_kwargs: dict = {"extra_http_headers": self._headers or None}
        if self._user_agent:
            context_kwargs["user_agent"] = self._user_agent
        if self._stealth:
            context_kwargs["viewport"] = {"width": 1280, "height": 800}
            context_kwargs["locale"] = "en-US"
            headers = {"Accept-Language": "en-US,en;q=0.9", **(self._headers or {})}
            context_kwargs["extra_http_headers"] = headers
        self._context = await self._browser.new_context(**context_kwargs)
        if self._stealth:
            await self._context.add_init_script(_STEALTH_INIT_JS)  # runs before any page script
        if self._cookies and self._cookie_url:
            await self._context.add_cookies(
                [{"name": name, "value": value, "url": self._cookie_url} for name, value in self._cookies.items()]
            )
        self._context.on("request", self._on_request)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._context is not None:
            await self._context.close()
        if self._browser is not None:
            await self._browser.close()
        if self._pw is not None:
            await self._pw.stop()

    # --- XHR/fetch capture -------------------------------------------------------------

    def _on_request(self, request) -> None:
        try:
            if request.resource_type not in ("xhr", "fetch"):
                return
            if not self._scope.is_in_scope(request.url):
                return
            captured = self._request_from_capture(request.method, request.url, request.post_data)
            self._captured.setdefault(captured.signature(), captured)
        except Exception:  # never let a listener error break navigation
            return

    @staticmethod
    def _request_from_capture(method: str, url: str, post_data: str | None) -> HttpRequest:
        parts = urlsplit(url)
        params = dict(parse_qsl(parts.query))
        base_url = url.split("?", 1)[0].split("#", 1)[0]
        if method == "GET" or not post_data:
            return HttpRequest(method=method, url=base_url, params=params)  # type: ignore[arg-type]
        try:
            parsed = json.loads(post_data)
            if isinstance(parsed, dict):
                return HttpRequest(method=method, url=base_url, params=params, json_body=parsed)  # type: ignore[arg-type]
        except (json.JSONDecodeError, ValueError):
            pass
        form = dict(parse_qsl(post_data))
        if form:
            return HttpRequest(method=method, url=base_url, params=params, data=form)  # type: ignore[arg-type]
        return HttpRequest(method=method, url=base_url, params=params)  # type: ignore[arg-type]

    # --- crawl -------------------------------------------------------------------------

    async def crawl(self, start_url: str) -> list[HttpRequest]:
        seen_urls: set[str] = set()
        seen_signatures: set[str] = set()
        discovered: list[HttpRequest] = []
        queue: deque[str] = deque([start_url])

        while queue and len(seen_urls) < self._max_pages:
            url = queue.popleft().split("#", 1)[0]
            if url in seen_urls:
                continue
            seen_urls.add(url)
            if not self._scope.is_in_scope(url):
                continue

            anchors, forms = await self._render_and_extract(url)
            if anchors is None:
                continue

            self._record(self._page_request(url), discovered, seen_signatures)

            for href in anchors:
                absolute = href.split("#", 1)[0]
                if absolute not in seen_urls and self._scope.is_in_scope(absolute) and not _is_logout(absolute):
                    queue.append(absolute)

            for form in forms:
                form_request = self._form_request(form)
                if form_request is not None:
                    self._record(form_request, discovered, seen_signatures)

        for captured in self._captured.values():
            self._record(captured, discovered, seen_signatures)

        return discovered

    async def _render_and_extract(self, url: str):
        page = await self._context.new_page()
        try:
            try:
                await page.goto(url, wait_until="load", timeout=self._nav_timeout)
            except Exception:
                return None, None
            await page.wait_for_timeout(200)
            try:
                await page.wait_for_load_state("networkidle", timeout=2000)
            except Exception:
                pass
            try:
                anchors = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                forms = await page.evaluate(_FORM_EXTRACT_JS)
            except Exception:
                anchors, forms = [], []
            if self._interactive:
                # Click safe controls to trigger the SPA's interaction-time XHR/fetch (captured passively
                # by _on_request). Best-effort: any failure here never aborts the crawl.
                try:
                    await self._interact_and_capture(page)
                except Exception:  # noqa: BLE001
                    pass
            return anchors, forms
        finally:
            await page.close()

    async def _interact_and_capture(self, page) -> None:
        """Click up to ``max_clicks`` SAFE, non-destructive controls to surface interaction-time API
        calls (React/Vue apps fetch on click/route change, not on load). Never submits forms; the
        destructive-label guard is re-checked at click time, so no state-changing action is triggered."""
        import time as _time

        try:
            labels = await page.eval_on_selector_all(
                _SAFE_CLICK_SELECTOR,
                "els => els.map(e => (e.innerText || e.getAttribute('aria-label') || "
                "e.getAttribute('title') || '').trim().slice(0, 60))",
            )
        except Exception:  # noqa: BLE001
            return
        safe_idx = [i for i, text in enumerate(labels) if not _is_dangerous(text)][: self._max_clicks]
        deadline = _time.monotonic() + 8.0  # cap total interaction time per page
        for idx in safe_idx:
            if _time.monotonic() > deadline:
                break
            loc = page.locator(_SAFE_CLICK_SELECTOR).nth(idx)
            try:
                text = (await loc.inner_text(timeout=500)) or ""
            except Exception:  # noqa: BLE001 — element gone (DOM shifted): skip
                continue
            if _is_dangerous(text):  # re-check at click time — the DOM may have changed since we listed
                continue
            try:
                await loc.click(timeout=1500, no_wait_after=True, force=False)
            except Exception:  # noqa: BLE001 — not clickable / navigated / detached: skip
                continue
            await page.wait_for_timeout(120)  # let the click's XHR fire (captured by _on_request)
            try:
                await page.wait_for_load_state("networkidle", timeout=1200)
            except Exception:  # noqa: BLE001
                pass

    # --- Screenshots ------------------------------------------------------------------

    async def screenshot(self, url: str, path: str) -> bool:
        """Render ``url`` and save a PNG screenshot to ``path``. Scope-enforced; False on any failure.

        Reuses the authenticated, scope-checked context, so it captures the page exactly as the scanner
        sees it (logged in, in scope). A navigation/render failure is swallowed — a screenshot is a
        nice-to-have for triage, never something that should break a scan."""
        base = url.split("#", 1)[0]
        if not self._scope.is_in_scope(base):
            return False
        page = await self._context.new_page()
        try:
            try:
                await page.goto(base, wait_until="load", timeout=self._nav_timeout)
            except Exception:  # noqa: BLE001 — unreachable/slow page: no screenshot, not fatal
                return False
            await page.wait_for_timeout(200)
            try:
                await page.wait_for_load_state("networkidle", timeout=2000)
            except Exception:  # noqa: BLE001 — best-effort settle
                pass
            await page.screenshot(path=path, full_page=False)
            return True
        except Exception:  # noqa: BLE001 — capture failed: skip, keep scanning
            return False
        finally:
            await page.close()

    # --- DOM-XSS ----------------------------------------------------------------------

    async def scan_dom_xss(self, urls: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        checked: set[str] = set()
        for url in urls:
            base = url.split("#", 1)[0]
            if base in checked or not self._scope.is_in_scope(base):
                continue
            checked.add(base)
            finding = await probe_dom_xss(self._context, base)
            if finding is not None:
                findings.append(finding)
        return findings

    # --- CSTI (client-side template injection) ----------------------------------------

    async def scan_csti(self, requests: list[HttpRequest], *, max_points: int = 40) -> list[Finding]:
        """Probe reflected query parameters for AngularJS/Vue client-side template injection."""
        findings: list[Finding] = []
        seen: set[str] = set()
        probed = 0
        for req in requests:
            if req.method != "GET" or not (req.params or {}) or not self._scope.is_in_scope(req.url):
                continue
            key = urlsplit(req.url).path + "?" + ",".join(sorted(req.params))
            if key in seen:
                continue
            seen.add(key)
            if probed >= max_points:
                break
            probed += 1
            findings.extend(await probe_csti(self._context, req))
        return findings

    # --- helpers ----------------------------------------------------------------------

    @staticmethod
    def _record(request: HttpRequest, discovered: list[HttpRequest], seen_signatures: set[str]) -> None:
        sig = request.signature()
        if sig not in seen_signatures:
            seen_signatures.add(sig)
            discovered.append(request)

    @staticmethod
    def _page_request(url: str) -> HttpRequest:
        parts = urlsplit(url)
        params = dict(parse_qsl(parts.query))
        return HttpRequest(method="GET", url=url.split("?", 1)[0], params=params)

    def _form_request(self, form: dict) -> HttpRequest | None:
        inputs = form.get("inputs") or {}
        if not inputs:
            return None
        action = (form.get("action") or "").split("#", 1)[0]
        if not action or not self._scope.is_in_scope(action):
            return None
        method = (form.get("method") or "GET").upper()
        if method == "GET":
            base_url = action.split("?", 1)[0]
            existing = dict(parse_qsl(urlsplit(action).query))
            existing.update(inputs)
            return HttpRequest(method="GET", url=base_url, params=existing)
        return HttpRequest(method=method, url=action.split("?", 1)[0], data=inputs)  # type: ignore[arg-type]
