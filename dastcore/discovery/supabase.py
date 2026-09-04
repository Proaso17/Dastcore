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

import asyncio
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

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
_MAX_CANDIDATES = 400  # cap the enumeration so a huge wordlist can't blow up the request count
_SUPABASE_HOST_RE = re.compile(r"^([a-z0-9]{20})\.supabase\.co$")

# pg_graphql introspection: its Query type exposes one `<table>Collection` field per table, so this
# minimal query recovers the table list even when the REST OpenAPI schema is service_role-locked.
_INTROSPECTION_QUERY = "{ __schema { queryType { fields { name } } } }"

# A compact wordlist of table names common to SaaS/Supabase apps, probed against the API when the
# schema can't be read any other way. Bad guesses are dropped by the PostgREST oracle (42P01), so
# this only adds signal. Kept deliberately small; the oracle does the real work.
_COMMON_TABLES: tuple[str, ...] = (
    "users", "user", "profiles", "profile", "accounts", "account", "members", "member", "teams", "team",
    "organizations", "organization", "orgs", "org", "customers", "customer", "clients", "client",
    "employees", "staff", "roles", "role", "permissions", "user_roles", "memberships", "invites",
    "sessions", "tokens", "api_keys", "credentials", "settings", "preferences", "config", "configs",
    "orders", "order", "order_items", "line_items", "products", "product", "items", "item", "inventory",
    "categories", "category", "tags", "carts", "cart", "wishlists", "coupons", "discounts",
    "payments", "payment", "invoices", "invoice", "transactions", "subscriptions", "subscription",
    "plans", "prices", "wallets", "balances", "refunds", "charges", "billing",
    "posts", "post", "articles", "comments", "comment", "reviews", "ratings", "likes", "follows",
    "messages", "message", "chats", "chat", "conversations", "conversation", "threads", "notifications",
    "notification", "events", "event", "logs", "audit_logs", "activity", "activities", "feed",
    "files", "file", "documents", "document", "images", "media", "attachments", "uploads", "assets",
    "projects", "project", "tasks", "task", "tickets", "ticket", "issues", "boards", "workspaces",
    "bookings", "booking", "reservations", "reservation", "appointments", "appointment", "schedules",
    "listings", "listing", "properties", "property", "rooms", "room", "services", "service",
    "contacts", "contact", "leads", "lead", "companies", "company", "addresses", "address", "locations",
    "reports", "report", "metrics", "stats", "analytics", "dashboards", "favorites", "bookmarks",
    "webhooks", "integrations", "connections", "devices", "device", "keys", "secrets", "emails",
)


def is_supabase_project(url: str) -> str:
    """Return the Supabase project ref if ``url``'s host is ``<ref>.supabase.co``, else ""."""
    host = urlsplit(url).netloc.split("@")[-1].split(":")[0].lower()
    match = _SUPABASE_HOST_RE.match(host)
    return match.group(1) if match else ""


def graphql_url_for(url: str) -> str:
    """The pg_graphql endpoint for a Supabase project URL: ``https://<ref>.supabase.co/graphql/v1``."""
    ref = is_supabase_project(url)
    return f"https://{ref}.supabase.co/graphql/v1" if ref else ""


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


@dataclass
class SupabaseProfile:
    """Result of autonomously profiling a Supabase project: the confirmed tables, the probes to run,
    and enough provenance to explain in the report how the surface was found (or why it wasn't)."""

    tables: set[str] = field(default_factory=set)
    probes: list[HttpRequest] = field(default_factory=list)
    graphql_tables: set[str] = field(default_factory=set)
    frontend_tables: set[str] = field(default_factory=set)
    introspection_enabled: bool = False  # pg_graphql introspection returned a schema
    oracle_blind: bool = False  # PostgREST oracle couldn't distinguish existence (wordlist untrusted)


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

    async def introspect_graphql_tables(self, graphql_url: str) -> set[str]:
        """Recover table names via pg_graphql introspection. Supabase exposes GraphQL at
        ``/graphql/v1`` with one ``<table>Collection`` query field per table — and introspection is
        often left enabled even when the REST OpenAPI schema is locked to ``service_role``. Returns
        an empty set if introspection is disabled/unreachable."""
        if not graphql_url or not self._client.is_in_scope(graphql_url):
            return set()
        try:
            resp = await self._client.post(
                graphql_url, json={"query": _INTROSPECTION_QUERY}, timeout=self._timeout, retries=0
            )
        except (OutOfScopeError, BudgetExceededError):
            return set()
        except Exception:  # noqa: BLE001 — a disabled/erroring GraphQL must not abort discovery
            return set()
        try:
            fields = json.loads(resp.text)["data"]["__schema"]["queryType"]["fields"]
        except (ValueError, KeyError, TypeError):
            return set()
        tables = {
            f["name"][: -len("Collection")]
            for f in fields
            if isinstance(f, dict) and isinstance(f.get("name"), str) and f["name"].endswith("Collection")
        }
        return {t for t in tables if t and t not in _NON_TABLE}

    async def _table_status(self, rest_base: str, table: str) -> bool | None:
        """PostgREST existence oracle for one table. ``False`` = does not exist (404 / ``42P01``);
        ``True`` = exists (readable, empty, or permission-blocked); ``None`` = couldn't tell."""
        try:
            resp = await self._client.get(
                f"{rest_base}/{table}", params={"limit": "0"}, timeout=self._timeout, retries=0
            )
        except (OutOfScopeError, BudgetExceededError):
            return None
        except Exception:  # noqa: BLE001
            return None
        body = (resp.text or "")[:400]
        if resp.status_code == 404 or "42P01" in body or "does not exist" in body:
            return False
        if resp.status_code in (200, 206, 401, 403, 416):
            return True
        return None

    async def confirm_tables(self, rest_base: str, candidates: set[str]) -> set[str] | None:
        """Keep only the candidate names that are real tables, per the PostgREST oracle. Calibrates
        first against a random non-existent name: if that isn't classified as "does not exist", the
        oracle is blind here (e.g. everything 401s), so we return ``None`` rather than a set full of
        false positives — the caller then trusts only its exact-source names."""
        base = _rest_base(rest_base)
        if await self._table_status(base, "dast_zzz_nonexistent_probe_x9") is not False:
            return None  # oracle can't distinguish existence here — don't trust wordlist guesses
        names = sorted(candidates)[:_MAX_CANDIDATES]
        results = await asyncio.gather(*(self._table_status(base, name) for name in names))
        return {name for name, exists in zip(names, results, strict=True) if exists}

    async def profile(
        self,
        rest_base: str,
        *,
        frontend_url: str = "",
        graphql_url: str = "",
        use_wordlist: bool = True,
        extra_tables: tuple[str, ...] = (),
    ) -> SupabaseProfile:
        """Autonomously enumerate a Supabase project's tables and return the confirmed set + RLS probes.

        Candidates are gathered from every available source — pg_graphql introspection, front-end
        mining, an explicit list, and a built-in wordlist — then validated against the PostgREST
        oracle. If the oracle is blind (see ``confirm_tables``), only the exact-source names
        (GraphQL/front-end/explicit) are trusted, never the wordlist guesses."""
        base = _rest_base(rest_base)
        prof = SupabaseProfile()
        if graphql_url:
            prof.graphql_tables = await self.introspect_graphql_tables(graphql_url)
            prof.introspection_enabled = bool(prof.graphql_tables)
        if frontend_url:
            prof.frontend_tables = (await self.collect_refs(frontend_url)).tables

        exact = {t for t in (set(extra_tables) | prof.graphql_tables | prof.frontend_tables) if t not in _NON_TABLE}
        candidates = set(exact)
        if use_wordlist:
            candidates |= set(_COMMON_TABLES)
        confirmed = await self.confirm_tables(base, candidates)
        prof.oracle_blind = confirmed is None
        prof.tables = confirmed if confirmed is not None else exact  # oracle blind → trust exact sources only
        prof.probes = [p for p in table_probes(base, prof.tables) if self._client.is_in_scope(p.url)]
        return prof
