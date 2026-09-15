"""Optional external dependencies dastcore can use, and a safe installer for the web panel.

dastcore works out of the box, but a few *optional* tools unlock deeper scanning: sqlmap (the deep
SQLi sweep) and the Playwright Chromium browser (headless crawling of SPAs / XHR endpoints). This
module reports whether each is present and installs it on request.

Safety: only the fixed commands in the registry below can be run — the web route passes a dependency
*key*, never a command, so there is no way to install an arbitrary package or inject a shell command.
Each command is a fixed argv list run without a shell.
"""

from __future__ import annotations

import asyncio
import contextlib
import glob
import os
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass

_INSTALL_TIMEOUT = 600.0  # installs (pip, browser download) can be slow


def _sqlmap_installed() -> bool:
    return shutil.which("sqlmap") is not None


def _playwright_chromium_installed() -> bool:
    """Best-effort: the Playwright package imports and a Chromium build exists in a browsers cache."""
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    candidates: list[str] = []
    env_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env_path and env_path not in ("0", ""):
        candidates.append(env_path)
    home = os.path.expanduser("~")
    candidates += [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "ms-playwright"),
        os.path.join(home, ".cache", "ms-playwright"),
        os.path.join(home, "Library", "Caches", "ms-playwright"),
        os.path.join(home, "AppData", "Local", "ms-playwright"),
    ]
    return any(base and glob.glob(os.path.join(base, "chromium-*")) for base in candidates)


@dataclass(frozen=True)
class Dependency:
    key: str
    label: str
    description: str
    check: Callable[[], bool]
    install_cmd: tuple[str, ...]


def _registry() -> dict[str, Dependency]:
    """The allowlist of optional dependencies and their fixed install commands."""
    return {
        "sqlmap": Dependency(
            key="sqlmap",
            label="sqlmap",
            description="Barrido profundo de SQL injection (se usa automáticamente en el panel si está).",
            check=_sqlmap_installed,
            install_cmd=(sys.executable, "-m", "pip", "install", "--upgrade", "sqlmap"),
        ),
        "playwright": Dependency(
            key="playwright",
            label="Navegador Playwright (Chromium)",
            description="Crawler headless para SPAs y endpoints XHR/fetch, y detección de DOM XSS/CSTI.",
            check=_playwright_chromium_installed,
            install_cmd=(sys.executable, "-m", "playwright", "install", "chromium"),
        ),
    }


def dependency_status() -> list[dict[str, object]]:
    """Each optional dependency with whether it is currently installed."""
    return [
        {"key": d.key, "label": d.label, "description": d.description, "installed": d.check()}
        for d in _registry().values()
    ]


def is_known_dependency(key: str) -> bool:
    return key in _registry()


async def install_dependency(key: str) -> tuple[bool, str]:
    """Install one optional dependency by its registry key (allowlisted — never an arbitrary command).

    Returns (ok, output-tail). Runs the fixed argv list with no shell."""
    dep = _registry().get(key)
    if dep is None:
        return False, f"dependencia desconocida: {key!r}"
    try:
        proc = await asyncio.create_subprocess_exec(
            *dep.install_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
    except (OSError, ValueError) as exc:
        return False, f"no se pudo lanzar la instalación: {exc}"
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=_INSTALL_TIMEOUT)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.kill()
        return False, "la instalación excedió el tiempo límite"
    text = out.decode("utf-8", "replace")
    ok = proc.returncode == 0 and dep.check()
    return ok, " ".join(text.split())[-800:]
