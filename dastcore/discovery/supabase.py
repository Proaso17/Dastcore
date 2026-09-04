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
import base64
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from selectolax.parser import HTMLParser

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# `.from('table')` — supabase-js. The negative lookbehinds drop Array.from / Buffer.from so an
# ordinary iterable call can't be mistaken for a table.
_FROM_CALL = re.compile(r"""(?<!Array)(?<!Buffer)\.from\(\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]""")
# `.rpc('fn')` — a stored function exposed under /rest/v1/rpc/<fn>.
_RPC_CALL = re.compile(r"""\.rpc\(\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]""")
# REST URLs baked into the bundle: /rest/v1/<table> (any trailing ?select=… is ignored — we add ours).
_REST_PATH = re.compile(r"""/rest/v1/([a-zA-Z_][a-zA-Z0-9_]*)""")
# Edge Functions the front-end invokes: functions.invoke('name') or a baked /functions/v1/<name> URL.
_EDGE_INVOKE = re.compile(r"""\.invoke\(\s*['"]([a-zA-Z0-9_-]+)['"]""")
_EDGE_PATH = re.compile(r"""/functions/v1/([a-zA-Z0-9_-]+)""")
# A Supabase project host; its presence confirms this really is a Supabase app (ref = 20 chars).
_SUPABASE_HOST = re.compile(r"""https?://([a-z0-9]{20})\.supabase\.co""")
# A JWT (three base64url segments). Supabase keys are JWTs; the anon key is meant to be public, but a
# `service_role` key in the front-end is a full RLS bypass — the single worst Supabase misconfig.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_PRIVILEGED_ROLES = frozenset({"service_role"})


def _jwt_role(token: str) -> str | None:
    """Decode a JWT's payload (no signature check) and return its ``role`` claim, if any."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)  # restore base64 padding
        return json.loads(base64.urlsafe_b64decode(payload)).get("role")
    except Exception:  # noqa: BLE001 — a non-JWT / malformed token simply has no role
        return None


def _redact(token: str) -> str:
    return f"{token[:14]}…{token[-6:]}" if len(token) > 24 else "…"

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
    service_role_keys: set[str] = field(default_factory=set)  # redacted service_role JWTs found in the bundle
    edge_functions: set[str] = field(default_factory=set)  # Supabase Edge Function names the bundle invokes

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
    edge = {m.group(1) for m in _EDGE_PATH.finditer(text)}
    if is_supabase:
        tables |= {m.group(1) for m in _FROM_CALL.finditer(text)}
        rpcs = {m.group(1) for m in _RPC_CALL.finditer(text)}
        edge |= {m.group(1) for m in _EDGE_INVOKE.finditer(text)}

    refs.tables = {t for t in tables if t not in _NON_TABLE}
    refs.rpcs = {r for r in rpcs if r not in _NON_TABLE}
    refs.edge_functions = edge
    # A leaked service_role key = full RLS bypass. The anon key is a JWT too, but role=anon is expected.
    refs.service_role_keys = {
        _redact(tok) for tok in _JWT_RE.findall(text) if _jwt_role(tok) in _PRIVILEGED_ROLES
    }
    return refs


def _merge_refs(into: SupabaseRefs, found: SupabaseRefs) -> None:
    """Union every field of ``found`` into ``into`` (used to accumulate refs across bundles)."""
    into.tables |= found.tables
    into.rpcs |= found.rpcs
    into.project_refs |= found.project_refs
    into.service_role_keys |= found.service_role_keys
    into.edge_functions |= found.edge_functions


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
    service_role_exposed: set[str] = field(default_factory=set)  # redacted service_role keys in the front-end
    rpcs: set[str] = field(default_factory=set)  # RPC function names mined from the front-end
    edge_functions: set[str] = field(default_factory=set)  # Edge Function names mined from the front-end


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
        _merge_refs(refs, mine_supabase_refs(html))
        for script_url in self._script_urls(html, origin):
            if not self._client.is_in_scope(script_url):
                continue
            js = await self._get(script_url)
            if js:
                _merge_refs(refs, mine_supabase_refs(js))
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
            fe_refs = await self.collect_refs(frontend_url)
            prof.frontend_tables = fe_refs.tables
            prof.service_role_exposed = fe_refs.service_role_keys
            prof.rpcs = fe_refs.rpcs
            prof.edge_functions = fe_refs.edge_functions

        exact = {t for t in (set(extra_tables) | prof.graphql_tables | prof.frontend_tables) if t not in _NON_TABLE}
        candidates = set(exact)
        if use_wordlist:
            candidates |= set(_COMMON_TABLES)
        confirmed = await self.confirm_tables(base, candidates)
        prof.oracle_blind = confirmed is None
        prof.tables = confirmed if confirmed is not None else exact  # oracle blind → trust exact sources only
        prof.probes = [p for p in table_probes(base, prof.tables) if self._client.is_in_scope(p.url)]
        return prof


# Write-side RLS probe -----------------------------------------------------------------------------
# The read probes above only prove SELECT protection. A table can block reads yet still let a role
# INSERT/UPDATE/DELETE — a common Supabase misconfig. This tests INSERT authorization *safely*: an
# empty-body insert either is refused by RLS (secure), fails a data constraint after RLS lets it
# through (a finding — but nothing is written), or actually creates a row (a finding — which we then
# delete). It never sends UPDATE/DELETE, and it mutates only in the last case, with best-effort
# cleanup. It is an active/mutating test, so callers must gate it behind an explicit opt-in.

_RLS_DENIED = ("42501", "row-level security", "permission denied", "not authorized", "no autoriz", "pgrst301")
_WRITE_AUTHORIZED_ERR = ("23502", "23503", "23505", "23514", "violates", "null value", "invalid input")


def _write_finding(url: str, table: str, identity: str, status: int, body: str, *, created: bool) -> Finding:
    request = HttpRequest(method="POST", url=url, json_body={})
    if created:
        name = f"RLS de escritura ABIERTO: '{identity}' pudo INSERTAR una fila en '{table}'"
        detail = (
            f"POST {url} devolvió {status}: se CREÓ una fila (se intentó borrarla). El rol '{identity}' "
            f"puede escribir en '{table}' — el RLS de INSERT no lo impide."
        )
    else:
        name = f"RLS de escritura ABIERTO: '{identity}' está autorizado a INSERTAR en '{table}'"
        detail = (
            f"POST {url} devolvió {status} con un error de restricción de datos (no de permiso): el RLS "
            f"AUTORIZÓ la escritura y solo la validación del dato la frenó. No se escribió nada, pero el "
            f"rol '{identity}' podría insertar con un cuerpo válido."
        )
    return Finding(
        id=f"supabase-write-rls:{table}:{identity}",
        rule_id="supabase-write-rls",
        name=name,
        severity="critical" if created else "high",
        cwe="CWE-284",
        owasp="API5:2023",
        injection_point=InjectionPoint(location="body", name="-", base_value="", request_template=request),
        evidence=[Evidence(type="status", data=detail[:300], confidence="high")],
        request=request,
        response=HttpResponse(status_code=status, url=url, text=body[:300]),
        remediation=(
            "Activa RLS en la tabla y define políticas de INSERT/UPDATE/DELETE con WITH CHECK que "
            "restrinjan la escritura al propietario (p. ej. auth.uid() = user_id). Por defecto, deniega: "
            "sin política, ningún rol anónimo/autenticado debería poder escribir."
        ),
    )


async def _cleanup_created_rows(client: HttpClient, base: str, table: str, body: str) -> None:
    """Best-effort delete of any row an INSERT probe created, matched by its returned ``id``."""
    try:
        rows = json.loads(body)
    except ValueError:
        return
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return
    for row in rows:
        if isinstance(row, dict) and "id" in row:
            try:
                await client.request(
                    "DELETE", f"{base}/{table}", params={"id": f"eq.{row['id']}"}, timeout=6.0, retries=0
                )
            except Exception:  # noqa: BLE001 — cleanup is best-effort; a failure is logged upstream, not raised
                pass


async def probe_write_rls(
    client: HttpClient, rest_base: str, tables: set[str], *, identity: str = "anon"
) -> tuple[list[Finding], int]:
    """Safely test whether ``identity`` (whatever session ``client`` carries) can INSERT into each table.
    Returns (findings, n_conclusive) — a finding per writable table, and how many tables gave a
    definitive answer (blocked or writable; inconclusive/errored ones aren't counted). See the module
    note above for the safety model."""
    base = _rest_base(rest_base)
    findings: list[Finding] = []
    tested = 0
    for table in sorted(tables):
        url = f"{base}/{table}"
        if not client.is_in_scope(url):
            continue
        try:
            resp = await client.post(
                url, json={}, headers={"Prefer": "return=representation"}, timeout=8.0, retries=0
            )
        except (OutOfScopeError, BudgetExceededError):
            continue
        except Exception:  # noqa: BLE001 — a single failed probe must not abort the others
            continue
        body = resp.text or ""
        low = body.lower()
        if resp.status_code in (401, 403) or any(s in low for s in _RLS_DENIED):
            tested += 1  # conclusive: RLS refused the write → secure
            continue
        if resp.status_code == 201:  # a row was actually inserted → clean it up, then flag
            await _cleanup_created_rows(client, base, table, body)
            findings.append(_write_finding(url, table, identity, resp.status_code, body, created=True))
            tested += 1
        elif resp.status_code in (400, 409, 422) and any(s in low for s in _WRITE_AUTHORIZED_ERR):
            findings.append(_write_finding(url, table, identity, resp.status_code, body, created=False))
            tested += 1
        # any other response (e.g. 400 PGRST parse/column errors) is inconclusive → not counted
    return findings, tested


# Cross-user BOLA probe ----------------------------------------------------------------------------
# The read probes prove anon can't read; this proves user A can't read user B's *specific* rows. It
# complements the collection test: when a table's listing IS filtered per-user (so A's list excludes
# B's rows), we take an id B can see but A cannot, and have A fetch it directly by id. If A gets it,
# object-level authorization is broken (RLS filters the collection but not a targeted lookup) — a
# classic BOLA/IDOR. Read-only, and only the `id` column is ever requested (no PII pulled).


async def _read_ids(
    client: HttpClient, base: str, table: str, *, id_filter: list[str] | None = None, limit: int = 20
) -> list[str] | None:
    """Read up to ``limit`` ``id`` values from a table (only the id column). ``None`` = table has no
    ``id`` column or wasn't readable; ``[]`` = readable but no rows for this identity."""
    params = {"select": "id", "limit": str(limit)}
    if id_filter:
        params["id"] = "in.(" + ",".join(id_filter) + ")"
    try:
        resp = await client.get(f"{base}/{table}", params=params, timeout=8.0, retries=0)
    except (OutOfScopeError, BudgetExceededError):
        return None
    except Exception:  # noqa: BLE001
        return None
    try:
        rows = json.loads(resp.text)
    except ValueError:
        return None
    if not isinstance(rows, list):
        return None
    return [str(row["id"]) for row in rows if isinstance(row, dict) and "id" in row]


def _bola_finding(url: str, table: str, name_a: str, name_b: str, leaked: list[str]) -> Finding:
    request = HttpRequest(method="GET", url=url)
    detail = (
        f"'{name_a}' leyó por id {len(leaked)} fila(s) de '{table}' que su propio listado NO incluye y que "
        f"pertenecen a '{name_b}' (ids: {', '.join(leaked[:5])}). El RLS filtra la colección pero no una "
        f"búsqueda dirigida por id → autorización a nivel de objeto rota (BOLA/IDOR)."
    )
    return Finding(
        id=f"supabase-bola:{table}:{name_a}<-{name_b}",
        rule_id="supabase-bola",
        name=f"BOLA: '{name_a}' puede leer filas de '{name_b}' en '{table}'",
        severity="high",
        cwe="CWE-639",
        owasp="API1:2023",
        injection_point=InjectionPoint(location="query", name="id", base_value="", request_template=request),
        evidence=[Evidence(type="differential", data=detail[:300], confidence="high")],
        request=request,
        response=HttpResponse(status_code=200, url=url, text=", ".join(leaked[:10])),
        remediation=(
            "Define políticas RLS de SELECT que restrinjan cada fila a su propietario "
            "(p. ej. USING (auth.uid() = user_id)); no basta con filtrar por defecto — un lookup por id "
            "debe respetar la misma política."
        ),
    )


async def probe_cross_user_bola(
    client_a: HttpClient, client_b: HttpClient, rest_base: str, tables: set[str], *, name_a: str, name_b: str
) -> tuple[list[Finding], int]:
    """Test whether identity A can read identity B's own rows by id (see the module note above).
    Returns (findings, n_comparable) — a finding per leaking table, and how many tables actually had
    B-private rows for A to try (0 means the test had nothing to compare, so 'no leak' isn't a signal)."""
    base = _rest_base(rest_base)
    findings: list[Finding] = []
    comparable = 0
    for table in sorted(tables):
        url = f"{base}/{table}"
        a_ids = await _read_ids(client_a, base, table)
        b_ids = await _read_ids(client_b, base, table)
        if a_ids is None or b_ids is None:
            continue  # no `id` column or unreadable → id-based BOLA not applicable
        private_to_b = [i for i in b_ids if i not in set(a_ids)][:3]  # rows B sees that A's listing doesn't
        if not private_to_b:
            continue  # collection isn't per-user-filtered here (RLS-off is caught by the read/authz test)
        comparable += 1
        got = await _read_ids(client_a, base, table, id_filter=private_to_b)
        leaked = [i for i in (got or []) if i in private_to_b]
        if leaked:
            findings.append(_bola_finding(url, table, name_a, name_b, leaked))
    return findings, comparable


# Auxiliary Supabase surface (Storage / Auth) ------------------------------------------------------
# Beyond the PostgREST tables, a Supabase project exposes Storage (`/storage/v1`) and Auth
# (`/auth/v1`). These GET-only probes surface data/config exposure without mutating anything.


async def _get_json(client: HttpClient, url: str) -> object | None:
    try:
        resp = await client.get(url, timeout=8.0, retries=0)
    except (OutOfScopeError, BudgetExceededError):
        return None
    except Exception:  # noqa: BLE001
        return None
    if resp.status_code >= 400:
        return None
    try:
        return json.loads(resp.text)
    except ValueError:
        return None


def _aux_finding(id_: str, url: str, name: str, severity: str, detail: str, remediation: str) -> Finding:
    request = HttpRequest(method="GET", url=url)
    return Finding(
        id=id_,
        rule_id="supabase-surface",
        name=name,
        severity=severity,
        cwe="CWE-200",
        owasp="API7:2023",
        injection_point=InjectionPoint(location="header", name="-", base_value="", request_template=request),
        evidence=[Evidence(type="status", data=detail[:300], confidence="high")],
        request=request,
        response=HttpResponse(status_code=200, url=url, text=detail[:300]),
        remediation=remediation,
    )


async def probe_supabase_aux(client: HttpClient, project_url: str) -> list[Finding]:
    """GET-only probes of Supabase's Storage and Auth surface (no mutation). Flags listable/public
    storage buckets and open self-signup — the common misconfigs outside the REST tables."""
    ref = is_supabase_project(project_url)
    if not ref:
        return []
    base = f"https://{ref}.supabase.co"
    findings: list[Finding] = []

    # Storage: can this identity list the project's buckets? Are any public?
    buckets = await _get_json(client, f"{base}/storage/v1/bucket")
    if isinstance(buckets, list) and buckets:
        names = [b.get("name") for b in buckets if isinstance(b, dict) and b.get("name")]
        findings.append(
            _aux_finding(
                "supabase-storage-listable",
                f"{base}/storage/v1/bucket",
                f"Supabase Storage: {len(names)} bucket(s) listables por esta identidad",
                "low",
                f"El endpoint de Storage devolvió la lista de buckets: {', '.join(map(str, names[:15]))}.",
                "Restringe el listado de buckets con políticas de Storage; no debería ser enumerable por anon.",
            )
        )
        public = [b.get("name") for b in buckets if isinstance(b, dict) and b.get("public")]
        if public:
            findings.append(
                _aux_finding(
                    "supabase-storage-public",
                    f"{base}/storage/v1/bucket",
                    f"Supabase Storage: bucket(s) público(s) — {', '.join(map(str, public[:15]))}",
                    "medium",
                    f"Estos buckets son públicos (world-readable): {', '.join(map(str, public[:15]))}.",
                    "Confirma que cada bucket público debe serlo; si no, ponlo privado y sirve con URLs firmadas.",
                )
            )

    # Auth: open self-signup with autoconfirm lets anyone create working accounts.
    settings = await _get_json(client, f"{base}/auth/v1/settings")
    if isinstance(settings, dict) and settings.get("disable_signup") is False and settings.get("mailer_autoconfirm"):
        findings.append(
            _aux_finding(
                "supabase-open-signup",
                f"{base}/auth/v1/settings",
                "Supabase Auth: registro abierto con autoconfirmación de email",
                "low",
                "disable_signup=false y mailer_autoconfirm=true: cualquiera puede crear cuentas activas sin "
                "verificar email.",
                "Si el registro no es público, desactívalo (disable_signup) o exige confirmación de email.",
            )
        )
    return findings
