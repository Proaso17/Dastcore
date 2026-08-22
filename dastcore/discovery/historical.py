"""Historical URL mining — passive attack-surface discovery from public archives.

The single highest-ROI recon technique in bug bounty: public archives (the Wayback Machine, Common
Crawl…) remember URLs a site once served — dead-but-live endpoints, old API versions, and above all
**parametrised URLs**, whose query parameters are ready-made injection points. It is fully passive: the
requests go to the archive, never to the target, so it costs the target nothing and needs no wordlist.

Discovered URLs are scope-gated before anything is scanned. Each in-scope URL becomes a GET
``HttpRequest`` (query string parsed into params, mirroring the crawler), and its hostname is fed to
subdomain discovery as a seed. Sources are pluggable; ``fetch_wayback_urls`` is the built-in one.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from urllib.parse import parse_qsl, urlsplit

import httpx

from dastcore.core.models import HttpRequest

# A source takes a registrable domain and returns the URLs it knows about (best-effort, may be empty).
Source = Callable[[str], Awaitable[list[str]]]


async def fetch_wayback_urls(domain: str, *, limit: int = 5000, timeout: float = 20.0) -> list[str]:
    """Every URL the Wayback Machine has for ``*.domain`` (deduped), via its CDX API. Best-effort."""
    params = {
        "url": f"*.{domain}/*",
        "output": "text",
        "fl": "original",
        "collapse": "urlkey",  # one row per distinct URL
        "limit": str(limit),
    }
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get("https://web.archive.org/cdx/search/cdx", params=params)
        return [line.strip() for line in resp.text.splitlines() if line.strip()]
    except (httpx.HTTPError, OSError):
        return []


async def fetch_commoncrawl_urls(domain: str, *, limit: int = 5000, timeout: float = 30.0) -> list[str]:
    """URLs Common Crawl has indexed for ``*.domain`` (newest crawl). Best-effort, fail-open."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            info = await client.get("https://index.commoncrawl.org/collinfo.json")
            indexes = info.json()
            if not indexes:
                return []
            cdx_api = str(indexes[0]["cdx-api"])  # collinfo is newest-first
            resp = await client.get(cdx_api, params={"url": f"*.{domain}/*", "output": "json", "limit": str(limit)})
    except (httpx.HTTPError, OSError, ValueError, KeyError, IndexError, TypeError):
        return []
    urls: list[str] = []
    for line in resp.text.splitlines():
        try:
            urls.append(str(json.loads(line)["url"]))
        except (ValueError, KeyError, TypeError):
            continue
    return urls


async def fetch_urlscan_urls(domain: str, *, timeout: float = 20.0) -> list[str]:
    """URLs urlscan.io has captured for ``domain`` (the scanned page URLs). Best-effort, fail-open."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(
                "https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": "1000"}
            )
        return [
            str((row.get("page") or {}).get("url", ""))
            for row in resp.json().get("results", [])
            if (row.get("page") or {}).get("url")
        ]
    except (httpx.HTTPError, OSError, ValueError, AttributeError, TypeError):
        return []


async def fetch_otx_urls(domain: str, *, timeout: float = 20.0) -> list[str]:
    """URLs AlienVault OTX has seen for ``domain``. Best-effort, fail-open."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list",
                params={"limit": "500"},
            )
        return [str(row.get("url", "")) for row in resp.json().get("url_list", []) if row.get("url")]
    except (httpx.HTTPError, OSError, ValueError, AttributeError, TypeError):
        return []


# The default URL archives, run together. Each is passive (hits the archive, not the target) and fail-open.
_DEFAULT_URL_SOURCES: list[Source] = [
    fetch_wayback_urls,
    fetch_commoncrawl_urls,
    fetch_urlscan_urls,
    fetch_otx_urls,
]


async def gather_historical_urls(domain: str, *, sources: list[Source] | None = None) -> list[str]:
    """Run every source for ``domain`` concurrently and return the deduplicated union of URLs.

    Fail-open: sources run independently, so one being down or rate-limited never blocks the others.
    """
    domain = domain.strip().lower().lstrip("*.").rstrip(".")
    if not domain:
        return []
    chosen = sources if sources is not None else _DEFAULT_URL_SOURCES
    results = await asyncio.gather(*(source(domain) for source in chosen), return_exceptions=True)
    seen: set[str] = set()
    ordered: list[str] = []
    for res in results:
        if not isinstance(res, list):
            continue  # a source raised -> skip it, keep the rest
        for url in res:
            if url and url not in seen:
                seen.add(url)
                ordered.append(url)
    return ordered


def url_to_request(url: str) -> HttpRequest | None:
    """A historical URL as a GET request: query string parsed into params (the injection points)."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    base_url = f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"
    return HttpRequest(method="GET", url=base_url, params=dict(parse_qsl(parts.query)))


def prioritise(requests: list[HttpRequest], limit: int) -> list[HttpRequest]:
    """Parametrised URLs first (they carry injection points), then the rest, capped at ``limit``."""
    with_params = [r for r in requests if r.params]
    without = [r for r in requests if not r.params]
    return (with_params + without)[:limit]
