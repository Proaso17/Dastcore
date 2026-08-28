"""Headless stealth: the browser must not look automated, so bot-detection / WAFs (Cloudflare…) let it
crawl. Needs a real Chromium — skipped where Playwright/Chromium isn't installed."""

from __future__ import annotations

import pytest

from dastcore.config import ScopeConfig
from dastcore.discovery.crawler_headless import HeadlessEngine, HeadlessUnavailableError

pytest.importorskip("playwright")


async def _navigator(engine: HeadlessEngine) -> dict:
    page = await engine._context.new_page()
    try:
        await page.goto("about:blank")
        return {
            "webdriver": await page.evaluate("navigator.webdriver"),
            "ua": await page.evaluate("navigator.userAgent"),
            "languages": await page.evaluate("navigator.languages"),
            "chrome": await page.evaluate("typeof window.chrome"),
            "plugins": await page.evaluate("navigator.plugins.length"),
        }
    finally:
        await page.close()


async def test_stealth_hides_automation_signals() -> None:
    try:
        async with HeadlessEngine(ScopeConfig(allow_domains=["x"])) as engine:  # stealth default on
            nav = await _navigator(engine)
    except HeadlessUnavailableError:
        pytest.skip("Chromium not installed")
    assert nav["webdriver"] in (None, False)  # navigator.webdriver hidden
    assert "Headless" not in nav["ua"]  # no HeadlessChrome tell
    assert nav["languages"] == ["en-US", "en"] and nav["chrome"] == "object" and nav["plugins"] >= 1


async def test_custom_user_agent_is_used() -> None:
    ua = "Mozilla/5.0 (X11; Linux x86_64) MyRealBrowser/1.0"
    try:
        async with HeadlessEngine(ScopeConfig(allow_domains=["x"]), user_agent=ua) as engine:
            nav = await _navigator(engine)
    except HeadlessUnavailableError:
        pytest.skip("Chromium not installed")
    assert nav["ua"] == ua  # the researcher's real UA (to pair with their cf_clearance cookie)
