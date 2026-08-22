"""JavaScript endpoint extraction — the surface hidden in front-end bundles.

Modern SPAs (Next.js, React, Vue…) ship their whole API map inside JavaScript: `fetch("/api/v1/users")`,
route tables, base URLs. None of it is linked in HTML, so a static crawler never sees it — but it's the
real attack surface. Like LinkFinder/katana, this fetches a page's script bundles and regex-extracts the
paths and URLs they reference, resolves them against the origin, scope-gates them, and turns each into a
request the scanner tests (query strings become injection points).

Extraction is deliberately conservative: only quoted absolute paths (``/...``), same-looking relative
API paths, and full URLs — with static assets (``.js``/``.css``/images/fonts/maps), MIME types and other
noise filtered out — so what reaches the scanner is signal, not junk. Bad guesses just 404.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from selectolax.parser import HTMLParser

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import HttpRequest
from dastcore.discovery.historical import url_to_request

# Quoted absolute path: "/api/v1/users", '/admin/config?x=1' (optional query kept — it's an injection point).
_ABS_PATH = re.compile(r"""['"`](/[a-zA-Z0-9_\-./~%@]+(?:\?[a-zA-Z0-9_\-.=&%\[\]]*)?)['"`]""")
# Quoted relative API path: "api/v2/users" — at least one slash, starts with a letter.
_REL_PATH = re.compile(r"""['"`]([a-zA-Z][a-zA-Z0-9_\-]*(?:/[a-zA-Z0-9_\-.]+)+(?:\?[a-zA-Z0-9_\-.=&%\[\]]*)?)['"`]""")
# Quoted absolute URL.
_URL = re.compile(r"""['"`](https?://[a-zA-Z0-9_\-./:~%?=&@]+)['"`]""")

_STATIC_EXT = (
    ".js", ".mjs", ".cjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3", ".wasm", ".pdf",
)
_MIME_PREFIX = ("text/", "image/", "application/", "audio/", "video/", "font/", "multipart/", "charset")
_NOISE = ("//", "./node_modules", "/@", "w3.org", "schema.org")


def _is_useful(endpoint: str) -> bool:
    """Keep API-looking paths/URLs; drop static assets, MIME types and framework noise."""
    path = urlsplit(endpoint).path if "://" in endpoint else endpoint.split("?", 1)[0]
    low = endpoint.lower()
    if len(path) < 2 or path == "/":
        return False
    if any(path.lower().endswith(ext) for ext in _STATIC_EXT):
        return False
    if low.startswith(_MIME_PREFIX) or any(n in low for n in _NOISE):
        return False
    if path.startswith("/_next/static") or path.startswith("/static/") or "/_nuxt/" in path:
        return False  # framework asset dirs
    return True


def extract_endpoints(js_text: str) -> set[str]:
    """Every candidate endpoint (absolute path, relative API path, or URL) referenced in the JS."""
    found: set[str] = set()
    for pattern in (_ABS_PATH, _REL_PATH, _URL):
        for match in pattern.finditer(js_text):
            found.add(match.group(1))
    return {endpoint for endpoint in found if _is_useful(endpoint)}


class JsEndpointDiscoverer:
    """Fetch a page's script bundles and extract the endpoints they reference, as scoped requests."""

    def __init__(self, client: HttpClient, *, max_scripts: int = 25, max_endpoints: int = 500, timeout: float = 6.0):
        self._client = client
        self._max_scripts = max_scripts
        self._max_endpoints = max_endpoints
        self._timeout = timeout

    async def _get(self, url: str) -> str | None:
        try:
            resp = await self._client.get(url, timeout=self._timeout, retries=0)
        except (OutOfScopeError, BudgetExceededError):
            return None
        except Exception:  # noqa: BLE001 — a dead script must not abort extraction
            return None
        return resp.text

    def _script_urls(self, html: str, origin: str) -> list[str]:
        urls: list[str] = []
        for node in HTMLParser(html).css("script[src]"):
            src = node.attributes.get("src")
            if src:
                urls.append(urljoin(origin, src))
        return list(dict.fromkeys(urls))[: self._max_scripts]

    async def discover(self, base_url: str) -> list[HttpRequest]:
        origin = base_url if base_url.endswith("/") else base_url + "/"
        if not self._client.is_in_scope(origin):
            return []
        html = await self._get(origin)
        if html is None:
            return []

        endpoints: set[str] = set()
        for script_url in self._script_urls(html, origin):
            if not self._client.is_in_scope(script_url):
                continue
            js = await self._get(script_url)
            if js:
                endpoints |= extract_endpoints(js)
            if len(endpoints) >= self._max_endpoints:
                break

        requests: dict[str, HttpRequest] = {}
        for endpoint in endpoints:
            absolute = urljoin(origin, endpoint)
            if not self._client.is_in_scope(absolute):
                continue
            req = url_to_request(absolute)
            if req is not None:
                requests.setdefault(req.signature(), req)
        return list(requests.values())
