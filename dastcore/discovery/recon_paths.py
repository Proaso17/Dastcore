"""robots.txt / sitemap.xml recon — mine the paths a site *tells you* about.

``robots.txt`` ``Disallow``/``Allow`` rules and ``sitemap.xml`` ``<loc>`` URLs are a classic,
high-signal source of paths a blind crawler never reaches — admin panels, exports, staging routes,
old sections. This fetches and parses both (following the ``Sitemap:`` directive and sitemap-index
files), scope-gates every URL through the shared client, and returns them as requests the scanner
then crawls and tests. Purely additive: bad or duplicate paths are de-duped and 404s are harmless.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import HttpRequest
from dastcore.discovery.historical import url_to_request

_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def parse_robots(text: str) -> tuple[set[str], set[str]]:
    """Return (paths, sitemap_urls) from a robots.txt body. Wildcard-only rules are skipped (they are
    patterns, not real paths); the leading path token of each Allow/Disallow is kept."""
    paths: set[str] = set()
    sitemaps: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith(("disallow:", "allow:")):
            value = line.split(":", 1)[1].strip()
            path = value.split()[0] if value else ""  # drop trailing comments/globs after whitespace
            if path and path != "/" and "*" not in path:
                paths.add(path)
        elif low.startswith("sitemap:"):
            url = line.split(":", 1)[1].strip()
            if url:
                sitemaps.add(url)
    return paths, sitemaps


def parse_sitemap(xml: str) -> set[str]:
    """Every ``<loc>`` URL in a sitemap or sitemap-index document."""
    return {m.group(1).strip() for m in _LOC_RE.finditer(xml)}


class ReconPathDiscoverer:
    """Fetch robots.txt + sitemap(s), parse them, and return the referenced URLs as scoped requests."""

    def __init__(self, client: HttpClient, *, max_urls: int = 500, max_sitemaps: int = 10, timeout: float = 6.0):
        self._client = client
        self._max_urls = max_urls
        self._max_sitemaps = max_sitemaps
        self._timeout = timeout

    async def _get(self, url: str) -> str | None:
        if not self._client.is_in_scope(url):
            return None
        try:
            resp = await self._client.get(url, timeout=self._timeout, retries=0)
        except (OutOfScopeError, BudgetExceededError):
            return None
        except Exception:  # noqa: BLE001 — a missing robots/sitemap must not abort discovery
            return None
        return resp.text if resp.status_code < 400 else None

    async def discover(self, base_url: str) -> list[HttpRequest]:
        origin = base_url if base_url.endswith("/") else base_url + "/"
        paths: set[str] = set()
        sitemaps: set[str] = set()

        robots = await self._get(urljoin(origin, "robots.txt"))
        if robots:
            found_paths, found_sitemaps = parse_robots(robots)
            paths |= found_paths
            sitemaps |= found_sitemaps
        sitemaps.add(urljoin(origin, "sitemap.xml"))  # the conventional location, even if robots omits it

        locs: set[str] = set()
        seen: set[str] = set()
        queue = list(sitemaps)
        while queue and len(seen) < self._max_sitemaps:
            sm_url = queue.pop()
            if sm_url in seen:
                continue
            seen.add(sm_url)
            body = await self._get(sm_url)
            if not body:
                continue
            for loc in parse_sitemap(body):
                if loc.lower().endswith(".xml") and loc not in seen:
                    queue.append(loc)  # a sitemap-index points at more sitemaps
                else:
                    locs.add(loc)

        for path in paths:
            locs.add(urljoin(origin, path))

        requests: dict[str, HttpRequest] = {}
        for url in list(locs)[: self._max_urls]:
            if not self._client.is_in_scope(url):
                continue
            req = url_to_request(url)
            if req is not None:
                requests.setdefault(req.signature(), req)
        return list(requests.values())
