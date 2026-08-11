"""Browser login macros: record a login once, replay it headlessly to (re)authenticate.

The classic DAST pain point is a JavaScript-driven login the scanner can't reproduce with
a plain form POST. A *login macro* is a small, replayable sequence of browser actions
(navigate, fill, click, wait) captured from a real login and stored as JSON. `replay_macro`
drives a headless browser through it and returns the resulting session cookies, which the
scanner then carries — and can re-run automatically when the session drops.

Values may contain `{{name}}` placeholders resolved at replay time (a password from an env
var, an OTP typed in), so a secret/MFA code never has to live in the macro file.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

# Reuse the "headless engine unavailable" error so callers handle one type.
from dastcore.discovery.crawler_headless import HeadlessUnavailableError

_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")


class MacroStep(BaseModel):
    """One recorded browser action."""

    action: Literal["goto", "fill", "click", "press", "wait_for_url", "wait_for_selector"]
    selector: str = ""  # CSS selector for fill/click/press/wait_for_selector
    value: str = ""  # URL for goto/wait_for_url; text for fill; key for press
    timeout_ms: int = 15000


class LoginMacro(BaseModel):
    """A replayable login: where it starts and the ordered actions that authenticate."""

    start_url: str
    steps: list[MacroStep] = Field(default_factory=list)
    # After replay, a session cookie whose name matches confirms success (optional heuristic).
    success_cookie: str = ""


def _resolve(value: str, runtime: dict[str, str]) -> str:
    """Substitute `{{name}}` placeholders from `runtime` (missing → left as-is)."""
    return _PLACEHOLDER.sub(lambda m: runtime.get(m.group(1), m.group(0)), value)


def save_macro(macro: LoginMacro, path: str | Path) -> None:
    Path(path).write_text(macro.model_dump_json(indent=2), encoding="utf-8")


def load_macro(path: str | Path) -> LoginMacro:
    return LoginMacro.model_validate_json(Path(path).read_text(encoding="utf-8"))


async def _run_step(page: object, step: MacroStep, runtime: dict[str, str]) -> None:
    value = _resolve(step.value, runtime)
    timeout = step.timeout_ms
    if step.action == "goto":
        await page.goto(value or step.selector, timeout=timeout)  # type: ignore[attr-defined]
    elif step.action == "fill":
        await page.fill(step.selector, value, timeout=timeout)  # type: ignore[attr-defined]
    elif step.action == "click":
        await page.click(step.selector, timeout=timeout)  # type: ignore[attr-defined]
    elif step.action == "press":
        await page.press(step.selector, value, timeout=timeout)  # type: ignore[attr-defined]
    elif step.action == "wait_for_url":
        await page.wait_for_url(value, timeout=timeout)  # type: ignore[attr-defined]
    elif step.action == "wait_for_selector":
        await page.wait_for_selector(step.selector, timeout=timeout)  # type: ignore[attr-defined]


async def replay_macro(
    macro: LoginMacro,
    *,
    runtime: dict[str, str] | None = None,
    base_url: str | None = None,
    headless: bool = True,
) -> dict[str, str]:
    """Replay `macro` in a headless browser and return the session cookies it established.

    `base_url` overrides the macro's `start_url` origin (to point a recorded login at a
    different environment). Raises `HeadlessUnavailableError` if Playwright/Chromium isn't
    installed.
    """
    runtime = runtime or {}
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:  # pragma: no cover - optional dep
        raise HeadlessUnavailableError(
            "Playwright no está instalado. Instala el extra: pip install 'dastcore[headless]'"
        ) from exc

    start_url = _rebase(macro.start_url, base_url)
    pw = await async_playwright().start()
    try:
        browser = await pw.chromium.launch(headless=headless)
    except Exception as exc:  # pragma: no cover - depends on browser download
        await pw.stop()
        raise HeadlessUnavailableError(
            "No se pudo lanzar Chromium. Ejecuta: python -m playwright install chromium"
        ) from exc
    try:
        context = await browser.new_context()
        page = await context.new_page()
        await page.goto(start_url, timeout=15000)
        for step in macro.steps:
            await _run_step(page, step, runtime)
        cookies = await context.cookies()
    finally:
        await browser.close()
        await pw.stop()
    return {c["name"]: c["value"] for c in cookies if c.get("name")}


def _rebase(url: str, base_url: str | None) -> str:
    """Point a recorded URL at a different origin, preserving its path/query."""
    if not base_url:
        return url
    from urllib.parse import urlsplit, urlunsplit

    src, base = urlsplit(url), urlsplit(base_url)
    return urlunsplit((base.scheme, base.netloc, src.path, src.query, src.fragment))


# Injected into the page during recording: reports a `fill` on input change and a `click`
# on buttons/links, each with a stable-ish CSS selector, back to Python via a binding.
_RECORDER_JS = r"""
(() => {
  function sel(el) {
    if (el.id) return '#' + CSS.escape(el.id);
    if (el.name) return el.tagName.toLowerCase() + '[name="' + el.name + '"]';
    const t = el.getAttribute('type'); if (t) return el.tagName.toLowerCase() + '[type="' + t + '"]';
    return el.tagName.toLowerCase();
  }
  document.addEventListener('change', (e) => {
    const el = e.target;
    if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT')) {
      const secret = el.type === 'password';
      window.__dast_record({action: 'fill', selector: sel(el), value: secret ? '{{password}}' : el.value});
    }
  }, true);
  document.addEventListener('click', (e) => {
    const el = e.target.closest('button, a, [type=submit], input[type=button]');
    if (el) window.__dast_record({action: 'click', selector: sel(el), value: ''});
  }, true);
})();
"""


async def record_macro(start_url: str, *, prompt=input, timeout_ms: int = 15000) -> LoginMacro:
    """Open a *headed* browser at `start_url`, record the user's fills/clicks into a macro,
    and return it once they finish (the `prompt` callable blocks until they press Enter).

    Password fields are recorded as the `{{password}}` placeholder, never the literal value.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:  # pragma: no cover - optional dep
        raise HeadlessUnavailableError("Playwright no está instalado (pip install 'dastcore[headless]').") from exc

    steps: list[MacroStep] = []

    async def _on_record(_source: object, step: dict) -> None:
        try:
            steps.append(MacroStep.model_validate(step))
        except Exception:  # noqa: BLE001 - ignore malformed events from the page
            pass

    pw = await async_playwright().start()
    browser = await pw.chromium.launch(headless=False)
    try:
        context = await browser.new_context()
        await context.expose_binding("__dast_record", _on_record)
        await context.add_init_script(_RECORDER_JS)
        page = await context.new_page()
        await page.goto(start_url, timeout=timeout_ms)
        import asyncio

        await asyncio.get_running_loop().run_in_executor(
            None, prompt, "Completa el login en el navegador y pulsa Enter aquí para guardar la macro… "
        )
    finally:
        await browser.close()
        await pw.stop()
    return LoginMacro(start_url=start_url, steps=steps)
