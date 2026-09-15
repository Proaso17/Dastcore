"""Optional-dependency registry + installer for the web panel: status reporting and the allowlisted,
shell-free installer (unknown keys refused; only fixed argv commands run)."""

from __future__ import annotations

import sys
from pathlib import Path

from dastcore.integrations import deps


def test_dependency_status_lists_known_tools() -> None:
    status = deps.dependency_status()
    keys = {d["key"] for d in status}
    assert {"sqlmap", "playwright"} <= keys
    for d in status:
        assert set(d) == {"key", "label", "description", "installed"}
        assert isinstance(d["installed"], bool)


def test_unknown_key_is_refused_not_run() -> None:
    assert deps.is_known_dependency("sqlmap") is True
    assert deps.is_known_dependency("rm -rf /") is False


async def test_install_unknown_key_never_runs_a_command() -> None:
    ok, msg = await deps.install_dependency("; touch pwned")
    assert ok is False and "desconocida" in msg


async def test_install_runs_the_fixed_command(monkeypatch, tmp_path: Path) -> None:
    # Point a fake dependency's install at a stub that succeeds and 'installs' a marker file.
    marker = tmp_path / "installed"
    stub = tmp_path / "stub.py"
    stub.write_text(f"import pathlib; pathlib.Path({str(marker)!r}).write_text('ok')", encoding="utf-8")

    fake = deps.Dependency(
        key="fake",
        label="fake",
        description="d",
        check=marker.exists,
        install_cmd=(sys.executable, str(stub)),
    )
    monkeypatch.setattr(deps, "_registry", lambda: {"fake": fake})

    assert deps.is_known_dependency("fake") is True
    ok, _out = await deps.install_dependency("fake")
    assert ok is True and marker.exists()


async def test_install_reports_failure_when_check_still_false(monkeypatch, tmp_path: Path) -> None:
    stub = tmp_path / "noop.py"
    stub.write_text("pass", encoding="utf-8")  # runs fine but 'installs' nothing
    fake = deps.Dependency(
        key="fake", label="fake", description="d", check=lambda: False, install_cmd=(sys.executable, str(stub))
    )
    monkeypatch.setattr(deps, "_registry", lambda: {"fake": fake})
    ok, _out = await deps.install_dependency("fake")
    assert ok is False  # command succeeded but the dependency is still not present
