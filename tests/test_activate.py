"""Endpoint activation: discovered API paths that only 404/405 as GET are probed for their real
verb + JSON body, so the scanner can inject into them. Offline — a fake client scripts responses."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.discovery.activate import (
    _endpoint_key,
    _infer_fields_from_error,
    _looks_like_api,
    activate_endpoints,
)


class _FakeApi:
    """A scriptable client: per (method, path) -> HttpResponse; anything unset is a 404."""

    def __init__(self, routes: dict[tuple[str, str], HttpResponse]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str]] = []

    async def request(
        self, method: str, url: str, *, json: object | None = None, timeout: float | None = None,
        retries: int | None = None, **_kw: object,
    ) -> HttpResponse:
        from urllib.parse import urlsplit

        path = urlsplit(url).path
        self.calls.append((method, path))
        hit = self.routes.get((method, path))
        return hit if hit is not None else HttpResponse(status_code=404, text="not found", url=url)


def _json(status: int, body: str) -> HttpResponse:
    return HttpResponse(status_code=status, headers={"content-type": "application/json"}, text=body)


def test_looks_like_api() -> None:
    assert _looks_like_api("https://t.test/api/auth/register")
    assert _looks_like_api("https://t.test/v1/users")
    assert not _looks_like_api("https://t.test/about")
    assert not _looks_like_api("https://t.test/assets/app.js")


def test_endpoint_key_ignores_query() -> None:
    a = _endpoint_key("https://t.test/api/x?a=1")
    b = _endpoint_key("https://t.test/api/x?b=2")
    assert a == b == "https://t.test/api/x"


def test_infer_fields_bilingual() -> None:
    assert _infer_fields_from_error('{"error":"Email y contraseña son obligatorios"}') == ["email", "password"]
    assert _infer_fields_from_error('{"error":"username and password required"}') == ["password", "username"]
    assert _infer_fields_from_error("no field names here") == []


async def test_activates_json_endpoint_from_post_probe() -> None:
    # No Allow header; the empty POST returns a 400 JSON error naming the required fields.
    client = _FakeApi({
        ("POST", "/api/auth/register"): _json(400, '{"error":"Email y contraseña son obligatorios"}'),
    })
    reqs = [HttpRequest(method="GET", url="https://t.test/api/auth/register")]
    out = await activate_endpoints(client, reqs)  # type: ignore[arg-type]
    assert len(out) == 1
    r = out[0]
    assert r.method == "POST"
    assert r.json_body == {"email": "probe@example.com", "password": "Probe-Passw0rd1"}
    assert r.url == "https://t.test/api/auth/register"


async def test_activates_from_allow_header() -> None:
    client = _FakeApi({
        ("OPTIONS", "/api/items"): HttpResponse(status_code=204, headers={"allow": "GET, POST, OPTIONS"}, text=""),
        ("POST", "/api/items"): _json(400, '{"error":"title and message required"}'),
    })
    reqs = [HttpRequest(method="GET", url="https://t.test/api/items")]
    out = await activate_endpoints(client, reqs)  # type: ignore[arg-type]
    assert len(out) == 1 and out[0].method == "POST"
    assert set(out[0].json_body) == {"title", "message"}  # type: ignore[arg-type]


async def test_non_api_get_is_ignored() -> None:
    client = _FakeApi({})
    reqs = [HttpRequest(method="GET", url="https://t.test/about")]
    out = await activate_endpoints(client, reqs)  # type: ignore[arg-type]
    assert out == []
    assert client.calls == []  # a non-API path is never even probed


async def test_non_json_endpoint_is_skipped() -> None:
    # /api/x exists but POST {} returns HTML 404 (not a JSON API) -> no activation, zero FP.
    client = _FakeApi({
        ("POST", "/api/legacy"): HttpResponse(status_code=404, headers={"content-type": "text/html"}, text="<html>"),
    })
    reqs = [HttpRequest(method="GET", url="https://t.test/api/legacy")]
    out = await activate_endpoints(client, reqs)  # type: ignore[arg-type]
    assert out == []


async def test_falls_back_to_default_fields_when_error_is_opaque() -> None:
    client = _FakeApi({
        ("POST", "/api/thing"): _json(422, '{"error":"invalid"}'),  # no field names to mine
    })
    reqs = [HttpRequest(method="GET", url="https://t.test/api/thing")]
    out = await activate_endpoints(client, reqs)  # type: ignore[arg-type]
    assert len(out) == 1
    assert "email" in out[0].json_body and "password" in out[0].json_body  # type: ignore[operator]
