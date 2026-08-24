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
from collections import deque
from urllib.parse import parse_qsl, urlsplit

from dastcore.config import ScopeConfig
from dastcore.core.models import Finding, HttpRequest
from dastcore.core.scope import ScopeChecker
from dastcore.detectors.dom_xss import probe_dom_xss

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
    ) -> None:
        self._scope = ScopeChecker(scope)
        self._cookies = cookies or {}
        self._cookie_url = cookie_url
        self._headers = extra_headers or {}
        self._max_pages = max_pages
        self._nav_timeout = nav_timeout_ms
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
        try:
            self._browser = await self._pw.chromium.launch()
        except Exception as exc:  # pragma: no cover - depends on browser download
            await self._pw.stop()
            raise HeadlessUnavailableError(
                "No se pudo lanzar Chromium. Ejecuta: python -m playwright install chromium"
            ) from exc

        self._context = await self._browser.new_context(extra_http_headers=self._headers or None)
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
                if absolute not in seen_urls and self._scope.is_in_scope(absolute):
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
            return anchors, forms
        finally:
            await page.close()

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
