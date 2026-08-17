"""Observability: per-request access logging and the optional JSON log format."""

from __future__ import annotations

import json
import logging

import httpx
from fastapi import FastAPI
from httpx import ASGITransport

import dastcore.obslog as obslog
from dastcore.obslog import _JsonFormatter, add_request_logging, configure_logging


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


async def test_request_logging_emits_one_access_line_per_request() -> None:
    app = FastAPI()

    @app.get("/ping")
    def ping() -> dict:
        return {"ok": True}

    add_request_logging(app)
    capture = _Capture()
    access = logging.getLogger("dastcore.access")
    access.addHandler(capture)
    access.setLevel(logging.INFO)
    try:
        async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            await client.get("/ping")
    finally:
        access.removeHandler(capture)

    assert any("GET /ping -> 200" in message for message in capture.messages)


def test_json_formatter_emits_valid_json_with_extra_fields() -> None:
    record = logging.LogRecord("dastcore.access", logging.INFO, __file__, 1, "hit", None, None)
    record.extra_fields = {"path": "/x", "status": 200, "ms": 4.2}  # type: ignore[attr-defined]
    data = json.loads(_JsonFormatter().format(record))
    assert data["msg"] == "hit" and data["level"] == "INFO"
    assert data["path"] == "/x" and data["status"] == 200 and data["ms"] == 4.2


def test_configure_logging_is_idempotent_and_sets_level() -> None:
    logger = logging.getLogger("dastcore")
    saved = (logger.handlers[:], logger.level, logger.propagate, obslog._configured)
    try:
        obslog._configured = False
        logger.handlers.clear()
        configure_logging("DEBUG")
        assert logger.level == logging.DEBUG
        handler_count = len(logger.handlers)
        configure_logging("INFO")  # already configured -> no-op (level and handlers unchanged)
        assert logger.level == logging.DEBUG and len(logger.handlers) == handler_count
    finally:
        logger.handlers[:], logger.level, logger.propagate, obslog._configured = saved
