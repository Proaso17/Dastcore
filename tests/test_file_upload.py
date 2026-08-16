"""Unrestricted file upload: an endpoint that stores and then executes/serves a dangerous file is
flagged (the uploaded marker is retrieved back); one that allowlists extensions is not."""

from __future__ import annotations

import re
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.file_upload import run_file_upload_checks

_ALLOWED = {"png", "jpg", "jpeg", "gif"}


def _php_eval(source: str) -> str:
    """Faithful stand-in for a PHP interpreter for our benign echo payload."""
    m = re.search(r'<\?php echo "(.*?)"\.\((\d+)\*(\d+)\)\."(.*?)"; \?>', source)
    return f"{m.group(1)}{int(m.group(2)) * int(m.group(3))}{m.group(4)}" if m else source


def _app(*, validate: bool):
    from flask import Flask, Response, jsonify, request

    app = Flask(__name__)
    store: dict[str, bytes] = {}

    @app.post("/upload")
    def upload():
        f = request.files.get("file")
        if f is None:
            return Response("no file", status=400)
        ext = f.filename.rsplit(".", 1)[-1].lower()
        if validate and ext not in _ALLOWED:
            return Response("tipo no permitido", status=400)
        store[f.filename] = f.read()
        return jsonify({"status": "ok", "url": f"/files/{f.filename}"})

    @app.get("/files/<name>")
    def serve(name: str):
        if name not in store:
            return Response("not found", status=404)
        content = store[name].decode("utf-8", "replace")
        if name.endswith(".php"):
            return Response(_php_eval(content), mimetype="text/html")  # server executes PHP
        if name.endswith(".svg"):
            return Response(content, mimetype="image/svg+xml")
        return Response(content, mimetype="text/html")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def vuln_url() -> Iterator[str]:
    url, server = _serve(_app(validate=False))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def safe_url() -> Iterator[str]:
    url, server = _serve(_app(validate=True))
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _req(base: str) -> HttpRequest:
    return HttpRequest(method="POST", url=f"{base}/upload", data={"file": ""})


async def test_executable_upload_is_flagged_as_rce(vuln_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_file_upload_checks(client, [_req(vuln_url)])
    assert len(findings) == 1
    assert findings[0].rule_id == "unrestricted-file-upload" and findings[0].cwe == "CWE-434"
    assert findings[0].severity == "critical"  # the .php executed on retrieval


async def test_extension_allowlist_is_not_flagged(safe_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_file_upload_checks(client, [_req(safe_url)])
    assert findings == []  # .php/.html/.svg all rejected by the allowlist
