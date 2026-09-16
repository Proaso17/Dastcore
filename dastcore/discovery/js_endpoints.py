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

import json
import re
from urllib.parse import parse_qsl, urljoin, urlsplit

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


# --- write-method API calls (the server-side injection surface a GET-only miner misses) --------------------
# fetch("/api/x", { method: "POST", body: JSON.stringify({a,b}) }) — url, then a following method + body.
_FETCH_CALL = re.compile(
    r"""fetch\(\s*['"`]([^'"`]+)['"`]\s*,\s*\{(?P<opts>[^{}]*(?:\{[^{}]*\}[^{}]*)*)\}""", re.DOTALL)
_FETCH_METHOD = re.compile(r"""method\s*:\s*['"`](POST|PUT|PATCH|DELETE)['"`]""", re.IGNORECASE)
# axios.post("/api/x", {a,b}) / $http.put(... / client.patch(... — method is the call name.
_METHOD_CALL = re.compile(
    r"""(?:axios|http|client|api|\$http|this\.\$?http)?\.?(post|put|patch|delete)\(\s*['"`]([^'"`]+)['"`]"""
    r"""\s*(?:,\s*\{(?P<body>[^{}]*(?:\{[^{}]*\}[^{}]*)*)\})?""",
    re.IGNORECASE)
# XMLHttpRequest: xhr.open("POST", "/api/x")
_XHR_OPEN = re.compile(r"""\.open\(\s*['"`](POST|PUT|PATCH|DELETE)['"`]\s*,\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE)
# Top-level object keys in a body literal ({a:…, b:…} or JSON.stringify({a,b})) — best-effort injection points.
_BODY_KEY = re.compile(r"""['"]?([a-zA-Z_]\w{0,40})['"]?\s*[:,}]""")
_STRINGIFY = re.compile(r"""JSON\.stringify\(\s*\{([^{}]*)\}""", re.DOTALL)


def _body_keys(blob: str | None) -> tuple[str, ...]:
    """Best-effort top-level body param names from a body literal, as SQLi/mass-assignment injection points."""
    if not blob:
        return ()
    inner = _STRINGIFY.search(blob)
    text = inner.group(1) if inner else blob
    keys = [m.group(1) for m in _BODY_KEY.finditer(text)]
    # drop obvious non-keys (method verbs, JS keywords) and cap
    drop = {"post", "put", "patch", "delete", "get", "method", "headers", "body", "true", "false", "null",
            "function", "return", "const", "let", "var", "await", "async"}
    return tuple(dict.fromkeys(k for k in keys if k.lower() not in drop))[:12]


def extract_write_calls(js_text: str) -> list[tuple[str, str, tuple[str, ...]]]:
    """Every write-method API call (POST/PUT/PATCH/DELETE) referenced in the JS, as (method, endpoint,
    body-param-names). This is the server-side injection surface (SQLi/mass-assignment/authz/BFLA on the
    API) that a GET-only path miner never reaches. Body keys are best-effort; a wrong guess just 404s /
    fails its detector's oracle, so it can never create a false positive."""
    out: list[tuple[str, str, tuple[str, ...]]] = []
    seen: set[tuple[str, str]] = set()

    def add(method: str, endpoint: str, keys: tuple[str, ...]) -> None:
        if not _is_useful(endpoint):
            return
        key = (method.upper(), endpoint)
        if key in seen:
            return
        seen.add(key)
        out.append((method.upper(), endpoint, keys))

    for m in _FETCH_CALL.finditer(js_text):
        url, opts = m.group(1), m.group("opts")
        method = _FETCH_METHOD.search(opts)
        if method:  # a fetch() with no explicit method is a GET — already covered by extract_endpoints
            add(method.group(1), url, _body_keys(opts))
    for m in _METHOD_CALL.finditer(js_text):
        add(m.group(1), m.group(2), _body_keys(m.group("body")))
    for m in _XHR_OPEN.finditer(js_text):
        add(m.group(1), m.group(2), ())
    return out


def extract_from_sourcemap(text: str) -> set[str]:
    """Endpoints mined from a JS sourcemap's original source. A deployed ``.js.map`` embeds the
    unminified ``sourcesContent`` — far richer and cleaner to parse than the minified bundle."""
    try:
        data = json.loads(text)
    except ValueError:
        return set()
    found: set[str] = set()
    for src in data.get("sourcesContent") or []:
        if isinstance(src, str):
            found |= extract_endpoints(src)
    return found


async def harvest_sourcemaps(
    client: HttpClient, origin: str, script_urls: list[str], *, max_scripts: int = 25, timeout: float = 6.0
) -> list[HttpRequest]:
    """For each bundle, fetch its ``<script>.map`` sourcemap (a common misconfig in production) and
    mine endpoints from the original source, returned as scope-gated requests."""
    endpoints: set[str] = set()
    for url in script_urls[:max_scripts]:
        map_url = url + ".map"
        if not client.is_in_scope(map_url):
            continue
        try:
            resp = await client.get(map_url, timeout=timeout, retries=0)
        except (OutOfScopeError, BudgetExceededError):
            continue
        except Exception:  # noqa: BLE001 — a missing sourcemap must not abort discovery
            continue
        if resp.status_code < 400 and resp.text:
            endpoints |= extract_from_sourcemap(resp.text)

    requests: dict[str, HttpRequest] = {}
    for endpoint in endpoints:
        absolute = urljoin(origin, endpoint)
        if not client.is_in_scope(absolute):
            continue
        req = url_to_request(absolute)
        if req is not None:
            requests.setdefault(req.signature(), req)
    return list(requests.values())


class JsEndpointDiscoverer:
    """Fetch a page's script bundles and extract the endpoints they reference, as scoped requests."""

    def __init__(
        self,
        client: HttpClient,
        *,
        max_scripts: int = 25,
        max_endpoints: int = 500,
        timeout: float = 6.0,
        harvest_maps: bool = False,
    ):
        self._client = client
        self._max_scripts = max_scripts
        self._max_endpoints = max_endpoints
        self._timeout = timeout
        self._harvest_maps = harvest_maps  # also fetch each bundle's .map sourcemap and mine its source

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

    def _write_request(
        self, origin: str, method: str, endpoint: str, keys: tuple[str, ...]
    ) -> HttpRequest | None:
        """Build a scope-gated, method-aware request from a mined write call, with the best-effort body
        param names as JSON injection points (placeholder values the scanner then mutates)."""
        absolute = urljoin(origin, endpoint)
        if not self._client.is_in_scope(absolute):
            return None
        parts = urlsplit(absolute)
        base = absolute.split("?", 1)[0].split("#", 1)[0]
        params = dict(parse_qsl(parts.query))
        json_body = dict.fromkeys(keys, "test") if keys else None
        return HttpRequest(method=method, url=base, params=params, json_body=json_body)  # type: ignore[arg-type]

    async def discover(self, base_url: str) -> list[HttpRequest]:
        origin = base_url if base_url.endswith("/") else base_url + "/"
        if not self._client.is_in_scope(origin):
            return []
        html = await self._get(origin)
        if html is None:
            return []

        script_urls = self._script_urls(html, origin)
        endpoints: set[str] = set()
        write_calls: list[tuple[str, str, tuple[str, ...]]] = []
        for script_url in script_urls:
            if not self._client.is_in_scope(script_url):
                continue
            js = await self._get(script_url)
            if js:
                endpoints |= extract_endpoints(js)
                write_calls.extend(extract_write_calls(js))  # POST/PUT/PATCH/DELETE API surface
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
        # Write-method calls become method-aware requests (with best-effort JSON body params as injection
        # points) so the SQLi/mass-assignment/authz/BFLA detectors reach the server-side API surface.
        # DELETE is deliberately NOT auto-issued: it is destructive with no analog to the POST forms the
        # scanner already submits, so scanning a mined DELETE could wipe target data. (extract_write_calls
        # still reports DELETE for visibility; it is just never turned into a scannable request here.)
        for method, endpoint, keys in write_calls:
            if method == "DELETE":
                continue
            req = self._write_request(origin, method, endpoint, keys)
            if req is not None:
                requests.setdefault(req.signature(), req)
        if self._harvest_maps:  # mine each bundle's sourcemap for the original, unminified source
            for req in await harvest_sourcemaps(
                self._client, origin, script_urls, max_scripts=self._max_scripts, timeout=self._timeout
            ):
                requests.setdefault(req.signature(), req)
        return list(requests.values())
