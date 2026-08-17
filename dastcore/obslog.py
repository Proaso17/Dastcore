"""Observability for dastcore's FastAPI apps: log configuration + per-request access logs.

``configure_logging`` is called once by the serve entrypoints (``cloud-serve`` / ``serve``). It sets
a level and format from the environment so an operator can see what the app is doing in production:

- ``DASTCORE_LOG_LEVEL`` (default ``INFO``)
- ``DASTCORE_LOG_JSON=1`` → one JSON object per line (friendly to log aggregators); otherwise a plain,
  human-readable line.

``add_request_logging`` attaches a middleware that logs one line per request (method, path, status,
duration) under ``dastcore.access`` — the signal you want first when a deploy misbehaves. It never
raises: an error in the handler still flows to the Tier-A error page, and is logged there too.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI

_configured = False


class _JsonFormatter(logging.Formatter):
    """Render each record as a single JSON line (timestamp, level, logger, message + any extras)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": round(record.created, 3),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in getattr(record, "extra_fields", {}).items():
            payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str | None = None, *, as_json: bool | None = None) -> None:
    """Install a stream handler on the ``dastcore`` logger. Idempotent (safe to call more than once)."""
    global _configured
    if _configured:
        return
    level = (level or os.environ.get("DASTCORE_LOG_LEVEL", "INFO")).upper()
    if as_json is None:
        as_json = os.environ.get("DASTCORE_LOG_JSON", "") not in ("", "0", "false", "no")

    handler = logging.StreamHandler()
    handler.setFormatter(
        _JsonFormatter() if as_json else logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    root = logging.getLogger("dastcore")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level, logging.INFO))
    root.propagate = False
    _configured = True


def add_request_logging(app: FastAPI) -> None:
    """Log one access line per request (method, path, status, duration) under ``dastcore.access``."""
    access = logging.getLogger("dastcore.access")

    @app.middleware("http")
    async def _access_log(request, call_next):  # type: ignore[no-untyped-def]
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        access.info(
            "%s %s -> %s (%sms)",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
            extra={"extra_fields": {
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "ms": elapsed_ms,
            }},
        )
        return response
