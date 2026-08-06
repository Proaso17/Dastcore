"""Uvicorn runner for the dashboard, invoked by ``dastcore serve``."""

from __future__ import annotations

from pathlib import Path


def default_db_path() -> Path:
    """Where scan history lives by default: ``~/.dastcore/dastcore.db``."""
    return Path.home() / ".dastcore" / "dastcore.db"


def run_server(host: str, port: int, db_path: str | Path) -> None:
    """Build the app and serve it with uvicorn (blocking)."""
    import uvicorn

    from dastcore.web.app import create_app

    app = create_app(db_path)
    uvicorn.run(app, host=host, port=port, log_level="warning")
