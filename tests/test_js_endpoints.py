"""JS endpoint extraction: the API hidden in SPA bundles becomes scoped, scannable requests
(query strings kept as injection points), with static assets / MIME noise filtered out."""

from __future__ import annotations

from urllib.parse import urlsplit

from dastcore.core.models import HttpResponse
from dastcore.discovery.js_endpoints import (
    JsEndpointDiscoverer,
    extract_endpoints,
    extract_write_calls,
)


def test_extract_keeps_api_paths_and_drops_noise() -> None:
    js = (
        'fetch("/api/v1/users").then(r=>r.json());'
        'const detail="/backup?q=1";'
        'import("/static/chunks/main.js");'      # static asset -> dropped
        'const mime="application/json";'          # MIME -> dropped
        'img.src="/assets/logo.png";'             # image -> dropped
        'axios.get("orders/list");'               # relative API path -> kept
    )
    endpoints = extract_endpoints(js)
    assert "/api/v1/users" in endpoints
    assert "/backup?q=1" in endpoints
    assert "orders/list" in endpoints
    assert not any(e.endswith(".js") or e.endswith(".png") for e in endpoints)
    assert "application/json" not in endpoints


class _FakeClient:
    def __init__(self, pages: dict[str, str]) -> None:
        self.pages = pages

    def is_in_scope(self, url: str) -> bool:
        return True

    async def get(self, url: str, **_kwargs: object) -> HttpResponse:
        return HttpResponse(status_code=200, text=self.pages.get(urlsplit(url).path, ""), url=url)


def test_extract_write_calls_recovers_method_and_body_params() -> None:
    """#14: the server-side API surface (POST/PUT/PATCH/DELETE) a GET-only miner misses — with body
    param names as injection points."""
    js = (
        'fetch("/api/v1/orders", { method: "POST", body: JSON.stringify({productId: 1, quantity: 2}) });'
        'axios.put("/api/profile/42", {theme: t});'
        'xhr.open("DELETE", "/api/items/9");'
        'fetch("/api/list");'  # GET fetch → NOT a write call
    )
    calls = {(m, u): keys for m, u, keys in extract_write_calls(js)}
    assert ("POST", "/api/v1/orders") in calls
    assert set(calls[("POST", "/api/v1/orders")]) >= {"productId", "quantity"}  # body keys mined
    assert ("PUT", "/api/profile/42") in calls
    assert ("DELETE", "/api/items/9") in calls
    assert not any(u == "/api/list" for _m, u in calls)  # a GET fetch is not a write call


async def test_discoverer_emits_method_aware_write_requests() -> None:
    html = '<html><head><script src="/static/app.js"></script></head></html>'
    js = 'fetch("/api/orders", { method: "POST", body: JSON.stringify({productId: 1}) });'
    client = _FakeClient({"/": html, "/static/app.js": js})

    requests = await JsEndpointDiscoverer(client).discover("http://spa.test/")  # type: ignore[arg-type]

    post = next((r for r in requests if r.method == "POST" and r.url == "http://spa.test/api/orders"), None)
    assert post is not None, "the POST API endpoint was not discovered"
    assert post.json_body is not None and "productId" in post.json_body  # body key is an injection point


async def test_discoverer_never_emits_a_destructive_delete_request() -> None:
    """Safety: a mined DELETE must NOT become a scannable request — auto-issuing it could wipe target data
    (extract_write_calls still reports DELETE for visibility, but discover() drops it)."""
    html = '<html><head><script src="/static/app.js"></script></head></html>'
    js = 'xhr.open("DELETE", "/api/items/9"); fetch("/api/orders", {method:"POST", body: JSON.stringify({x:1})});'
    client = _FakeClient({"/": html, "/static/app.js": js})

    requests = await JsEndpointDiscoverer(client).discover("http://spa.test/")  # type: ignore[arg-type]

    assert not any(r.method == "DELETE" for r in requests)  # never auto-issue a destructive DELETE
    assert any(r.method == "POST" for r in requests)  # but POST/PUT/PATCH are still discovered


async def test_discoverer_turns_bundle_endpoints_into_scoped_requests() -> None:
    html = '<html><head><script src="/static/app.js"></script></head><body></body></html>'
    js = 'const api="/api/v1/users"; fetch("/backup?q=1"); import("/static/chunk.js");'
    client = _FakeClient({"/": html, "/static/app.js": js})

    requests = await JsEndpointDiscoverer(client).discover("http://spa.test/")  # type: ignore[arg-type]

    by_url = {r.url: r for r in requests}
    assert "http://spa.test/api/v1/users" in by_url
    backup = by_url.get("http://spa.test/backup")
    assert backup is not None and backup.params.get("q") == "1"  # the query param is captured for testing
    assert not any("chunk.js" in u for u in by_url)  # the bundle itself is not a target
