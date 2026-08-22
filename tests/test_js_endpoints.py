"""JS endpoint extraction: the API hidden in SPA bundles becomes scoped, scannable requests
(query strings kept as injection points), with static assets / MIME noise filtered out."""

from __future__ import annotations

from urllib.parse import urlsplit

from dastcore.core.models import HttpResponse
from dastcore.discovery.js_endpoints import JsEndpointDiscoverer, extract_endpoints


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
