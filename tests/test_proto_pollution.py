"""Server-side prototype pollution via the `json spaces` oracle. An app that deep-merges the
request body (so `__proto__.json spaces` reaches Object.prototype and Express-style
serialisation indents later JSON responses) is flagged; an app that rejects `__proto__` and a
non-JSON endpoint are silent. The prototype is always reset afterwards."""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.proto_pollution import check_proto_pollution


def _deep_merge(target: dict, src: dict) -> None:
    """A naive recursive merge — the classic prototype-pollution sink (honours __proto__)."""
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_merge(target[key], value)
        else:
            target[key] = value


def _app():
    from flask import Flask, Response, request

    app = Flask(__name__)
    # A stand-in for Object.prototype: "json spaces" set here changes later serialisation.
    proto: dict[str, object] = {}

    def _dumps(obj: dict) -> str:
        spaces = proto.get("json spaces")
        indent = int(spaces) if isinstance(spaces, int) and spaces else None
        return json.dumps(obj, indent=indent)

    @app.post("/vuln")  # VULNERABLE: merges the body, so __proto__ pollutes the shared prototype
    def vuln() -> Response:
        body = request.get_json(silent=True) or {}
        obj: dict[str, object] = {}
        _deep_merge(obj, body)
        if "__proto__" in body:  # the sink writes __proto__'s keys onto the prototype
            _deep_merge(proto, body["__proto__"])
        return Response(_dumps({"ok": True, "id": 1}), mimetype="application/json")

    @app.post("/safe")  # HARDENED: rejects/ignores __proto__, never touches the prototype
    def safe() -> Response:
        body = request.get_json(silent=True) or {}
        clean = {k: v for k, v in body.items() if k not in ("__proto__", "constructor", "prototype")}
        return Response(json.dumps({"ok": True, **clean, "id": 1}), mimetype="application/json")

    @app.post("/text")  # non-JSON endpoint → not applicable
    def text() -> Response:
        return Response("ok", mimetype="text/plain")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def pp_server() -> Iterator[str]:
    url, server = _serve(_app())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _post(url: str) -> HttpRequest:
    return HttpRequest(method="POST", url=url, json_body={"name": "bob"})


async def test_prototype_pollution_is_flagged(pp_server: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await check_proto_pollution(client, _post(f"{pp_server}/vuln"))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "prototype-pollution" and f.cwe == "CWE-1321"
    assert f.injection_point.name == "__proto__"


async def test_prototype_is_reset_after_probe(pp_server: str) -> None:
    async with HttpClient(_scope()) as client:
        await check_proto_pollution(client, _post(f"{pp_server}/vuln"))
        # after the probe resets json spaces to 0, a fresh write is compact again
        resp = await client.request("POST", f"{pp_server}/vuln", json={"name": "x"})
    assert "\n" not in resp.text  # prototype restored → compact serialisation


async def test_hardened_app_is_not_flagged(pp_server: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_proto_pollution(client, _post(f"{pp_server}/safe")) == []


async def test_non_json_endpoint_is_not_flagged(pp_server: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await check_proto_pollution(client, _post(f"{pp_server}/text")) == []
