"""Supabase-aware discovery — recover a Supabase project's tables from the front-end bundle.

A Supabase app's real authorization surface is its PostgREST data API
(``https://<ref>.supabase.co/rest/v1/<table>``), where Row-Level-Security decides who may read
what. But the OpenAPI schema root that would list the tables is, by default, restricted to the
``service_role`` key — so a black-box scan can't enumerate tables from the API itself.

The front-end bundle, however, names every table it touches: the supabase-js client calls
``.from('<table>')`` / ``.rpc('<fn>')``, and REST URLs appear verbatim as ``/rest/v1/<table>``.
This module fetches the app's script bundles (like the JS-endpoint miner), regex-extracts those
table names, and turns each into a bounded ``GET /rest/v1/<table>?select=*&limit=1`` probe. Fed
through the scanner with an ``anon`` and an ``authed`` identity, those probes reveal RLS/BOLA
gaps — e.g. a table an anonymous visitor can read that should be private.

Extraction is gated on the bundle actually referencing Supabase (a ``*.supabase.co`` host or a
``/rest/v1/`` path), so a non-Supabase app's ``Array.from(...)`` calls never masquerade as tables.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

from selectolax.parser import HTMLParser

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import HttpRequest

# `.from('table')` — supabase-js. The negative lookbehinds drop Array.from / Buffer.from so an
# ordinary iterable call can't be mistaken for a table.
_FROM_CALL = re.compile(r"""(?<!Array)(?<!Buffer)\.from\(\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]""")
# `.rpc('fn')` — a stored function exposed under /rest/v1/rpc/<fn>.
_RPC_CALL = re.compile(r"""\.rpc\(\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]""")
# REST URLs baked into the bundle: /rest/v1/<table> (any trailing ?select=… is ignored — we add ours).
_REST_PATH = re.compile(r"""/rest/v1/([a-zA-Z_][a-zA-Z0-9_]*)""")
# A Supabase project host; its presence confirms this really is a Supabase app (ref = 20 chars).
_SUPABASE_HOST = re.compile(r"""https?://([a-z0-9]{20})\.supabase\.co""")

# PostgREST virtual/reserved path words that are not user tables.
_NON_TABLE = frozenset({"rpc", "rest", "v1"})
_MAX_TABLES = 100


@dataclass
class SupabaseRefs:
    """What a front-end bundle reveals about its Supabase backend."""

    tables: set[str] = field(default_factory=set)
    rpcs: set[str] = field(default_factory=set)
    project_refs: set[str] = field(default_factory=set)

    @property
    def is_supabase(self) -> bool:
        return bool(self.project_refs or self.tables or self.rpcs)


def mine_supabase_refs(text: str) -> SupabaseRefs:
    """Extract the table names, RPC names and project refs a JS/HTML bundle references.

    Table/RPC names are trusted only when the bundle also references Supabase (a ``*.supabase.co``
    host or a ``/rest/v1/`` path), so an unrelated app's ``Array.from('abc')`` is never taken for a
    table."""
    refs = SupabaseRefs()
    refs.project_refs = {m.group(1) for m in _SUPABASE_HOST.finditer(text)}
    rest_tables = {m.group(1) for m in _REST_PATH.finditer(text)}
    is_supabase = bool(refs.project_refs) or bool(rest_tables)

    tables = set(rest_tables)
    rpcs: set[str] = set()
    if is_supabase:
        tables |= {m.group(1) for m in _FROM_CALL.finditer(text)}
        rpcs = {m.group(1) for m in _RPC_CALL.finditer(text)}

    refs.tables = {t for t in tables if t not in _NON_TABLE}
    refs.rpcs = {r for r in rpcs if r not in _NON_TABLE}
    return refs


def _rest_base(url: str) -> str:
    """Normalize any project/target URL to the PostgREST base ``…/rest/v1`` (no trailing slash)."""
    url = url.rstrip("/")
    idx = url.find("/rest/v1")
    if idx != -1:
        return url[: idx + len("/rest/v1")]
    return url + "/rest/v1"


def table_probes(rest_base: str, tables: set[str]) -> list[HttpRequest]:
    """One bounded read per table: ``GET <base>/<table>?select=*&limit=1`` — enough to tell whether
    an identity can read the table at all (RLS), without pulling a dataset."""
    base = _rest_base(rest_base)
    return [
        HttpRequest(method="GET", url=f"{base}/{table}", params={"select": "*", "limit": "1"})
        for table in sorted(tables)[:_MAX_TABLES]
    ]


class SupabaseDiscoverer:
    """Fetch a Supabase app's front-end bundles, recover its table list, and emit per-table probes."""

    def __init__(self, client: HttpClient, *, max_scripts: int = 25, timeout: float = 6.0):
        self._client = client
        self._max_scripts = max_scripts
        self._timeout = timeout

    async def _get(self, url: str) -> str | None:
        try:
            resp = await self._client.get(url, timeout=self._timeout, retries=0)
        except (OutOfScopeError, BudgetExceededError):
            return None
        except Exception:  # noqa: BLE001 — a dead script must not abort discovery
            return None
        return resp.text

    def _script_urls(self, html: str, origin: str) -> list[str]:
        urls: list[str] = []
        for node in HTMLParser(html).css("script[src]"):
            src = node.attributes.get("src")
            if src:
                urls.append(urljoin(origin, src))
        return list(dict.fromkeys(urls))[: self._max_scripts]

    async def collect_refs(self, frontend_url: str) -> SupabaseRefs:
        """Mine the front-end page and its script bundles for Supabase table/RPC/project references."""
        origin = frontend_url if frontend_url.endswith("/") else frontend_url + "/"
        refs = SupabaseRefs()
        if not self._client.is_in_scope(origin):
            return refs
        html = await self._get(origin)
        if html is None:
            return refs
        found = mine_supabase_refs(html)
        refs.tables |= found.tables
        refs.rpcs |= found.rpcs
        refs.project_refs |= found.project_refs
        for script_url in self._script_urls(html, origin):
            if not self._client.is_in_scope(script_url):
                continue
            js = await self._get(script_url)
            if js:
                found = mine_supabase_refs(js)
                refs.tables |= found.tables
                refs.rpcs |= found.rpcs
                refs.project_refs |= found.project_refs
        return refs

    async def discover(self, frontend_url: str, rest_base: str) -> list[HttpRequest]:
        """Recover tables from ``frontend_url`` and return in-scope per-table probes against
        ``rest_base`` (the PostgREST data API)."""
        refs = await self.collect_refs(frontend_url)
        return [p for p in table_probes(rest_base, refs.tables) if self._client.is_in_scope(p.url)]
