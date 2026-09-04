"""Supabase-aware discovery: mine table names from a front-end bundle → per-table RLS probes."""

from __future__ import annotations

import json
from types import SimpleNamespace

from dastcore.discovery.supabase import (
    SupabaseDiscoverer,
    graphql_url_for,
    is_supabase_project,
    mine_supabase_refs,
    probe_cross_user_bola,
    probe_write_rls,
    table_probes,
)

# A realistic (if tiny) supabase-js bundle snippet: a project host, .from()/.rpc() calls, a REST URL.
_BUNDLE = """
    const c = createClient("https://abcdefghij1234567890.supabase.co", "eyJhbGci.anon.key");
    async function load(){
      await c.from('profiles').select('*');
      await c.from("orders").select('id');
      await c.rpc('get_dashboard_stats');
      await fetch("/rest/v1/invoices?select=id");
    }
"""


def test_mine_extracts_tables_rpcs_and_ref() -> None:
    refs = mine_supabase_refs(_BUNDLE)
    assert refs.tables == {"profiles", "orders", "invoices"}
    assert refs.rpcs == {"get_dashboard_stats"}
    assert refs.project_refs == {"abcdefghij1234567890"}
    assert refs.is_supabase is True


def test_mine_ignores_from_calls_without_supabase_context() -> None:
    # No supabase host and no /rest/v1 path → not a Supabase app → .from() is not treated as a table.
    plain = "const xs = Array.from(document.querySelectorAll('a')); store.from('cache');"
    refs = mine_supabase_refs(plain)
    assert refs.tables == set()
    assert refs.is_supabase is False


def test_mine_excludes_array_and_buffer_from_even_in_supabase_bundle() -> None:
    bundle = (
        "createClient('https://abcdefghij1234567890.supabase.co','k');"
        "Array.from('NOTATABLE'); Buffer.from('ALSONOT'); db.from('real_table');"
    )
    refs = mine_supabase_refs(bundle)
    assert "real_table" in refs.tables
    assert "NOTATABLE" not in refs.tables
    assert "ALSONOT" not in refs.tables


def test_table_probes_are_bounded_reads() -> None:
    probes = table_probes("https://x.supabase.co/rest/v1/", {"orders", "profiles"})
    assert [p.url for p in probes] == [
        "https://x.supabase.co/rest/v1/orders",
        "https://x.supabase.co/rest/v1/profiles",
    ]
    for p in probes:
        assert p.method == "GET"
        assert p.params == {"select": "*", "limit": "1"}  # minimal: one row, just to test readability


def test_rest_base_normalization_from_project_root() -> None:
    # A project root (no /rest/v1) still resolves to the correct PostgREST base.
    probes = table_probes("https://x.supabase.co", {"t"})
    assert probes[0].url == "https://x.supabase.co/rest/v1/t"


class _FakeClient:
    """Minimal HttpClient stand-in: everything in scope, one canned page, no network."""

    def __init__(self, page: str):
        self._page = page

    def is_in_scope(self, url: str) -> bool:
        return True

    async def get(self, url: str, timeout: float = 6.0, retries: int = 0):
        return SimpleNamespace(text=self._page)


async def test_discover_builds_probes_from_frontend() -> None:
    client = _FakeClient(_BUNDLE)
    disc = SupabaseDiscoverer(client)  # type: ignore[arg-type]
    probes = await disc.discover("https://app.example.com", "https://abcdefghij1234567890.supabase.co/rest/v1/")
    urls = {p.url for p in probes}
    assert urls == {
        "https://abcdefghij1234567890.supabase.co/rest/v1/profiles",
        "https://abcdefghij1234567890.supabase.co/rest/v1/orders",
        "https://abcdefghij1234567890.supabase.co/rest/v1/invoices",
    }


async def test_discover_returns_nothing_for_non_supabase_app() -> None:
    client = _FakeClient("<html><body>just a normal site, Array.from(x)</body></html>")
    disc = SupabaseDiscoverer(client)  # type: ignore[arg-type]
    probes = await disc.discover("https://app.example.com", "https://x.supabase.co/rest/v1/")
    assert probes == []


# --- autonomous profiling: GraphQL introspection + PostgREST oracle ---------------------------

def test_is_supabase_project_and_graphql_url() -> None:
    ref = "abcdefghij1234567890"
    assert is_supabase_project(f"https://{ref}.supabase.co/rest/v1/") == ref
    assert is_supabase_project("https://beta-panel.getnyma.com") == ""
    assert graphql_url_for(f"https://{ref}.supabase.co/rest/v1/") == f"https://{ref}.supabase.co/graphql/v1"
    assert graphql_url_for("https://example.com") == ""


class _RoutedClient:
    """Fake client that answers GraphQL introspection and the PostgREST existence oracle by route."""

    def __init__(self, *, existing=(), introspect_fields=None, blind=False):
        self.existing = set(existing)
        self.introspect_fields = introspect_fields  # None => introspection disabled
        self.blind = blind

    def is_in_scope(self, url: str) -> bool:
        return True

    async def post(self, url: str, json=None, timeout: float = 6.0, retries: int = 0):
        if self.introspect_fields is None:
            return SimpleNamespace(status_code=200, text='{"errors":[{"message":"unknown field"}]}')
        body = {"data": {"__schema": {"queryType": {"fields": self.introspect_fields}}}}
        return SimpleNamespace(status_code=200, text=jsondumps(body))

    async def get(self, url: str, params=None, timeout: float = 6.0, retries: int = 0):
        table = url.rstrip("/").rsplit("/", 1)[-1]
        if self.blind:
            return SimpleNamespace(status_code=401, text="{}")  # everything looks protected → oracle blind
        if table in self.existing:
            return SimpleNamespace(status_code=200, text="[]")
        return SimpleNamespace(
            status_code=404, text='{"code":"42P01","message":"relation \\"public.' + table + '\\" does not exist"}'
        )


def jsondumps(obj) -> str:
    return json.dumps(obj)


async def test_introspect_graphql_recovers_tables() -> None:
    fields = [{"name": "profilesCollection"}, {"name": "ordersCollection"}, {"name": "node"}, {"name": "__type"}]
    disc = SupabaseDiscoverer(_RoutedClient(introspect_fields=fields))  # type: ignore[arg-type]
    tables = await disc.introspect_graphql_tables("https://x.supabase.co/graphql/v1")
    assert tables == {"profiles", "orders"}


async def test_introspect_graphql_empty_when_disabled() -> None:
    disc = SupabaseDiscoverer(_RoutedClient(introspect_fields=None))  # type: ignore[arg-type]
    assert await disc.introspect_graphql_tables("https://x.supabase.co/graphql/v1") == set()


async def test_confirm_tables_keeps_only_real_ones() -> None:
    disc = SupabaseDiscoverer(_RoutedClient(existing={"orders", "profiles"}))  # type: ignore[arg-type]
    confirmed = await disc.confirm_tables("https://x.supabase.co/rest/v1", {"orders", "profiles", "ghost_table"})
    assert confirmed == {"orders", "profiles"}  # ghost_table 404s with 42P01 → dropped


async def test_confirm_tables_returns_none_when_oracle_blind() -> None:
    # If a known-bogus name doesn't classify as "missing" (everything 401s), the oracle is blind.
    disc = SupabaseDiscoverer(_RoutedClient(blind=True))  # type: ignore[arg-type]
    assert await disc.confirm_tables("https://x.supabase.co/rest/v1", {"orders"}) is None


async def test_profile_combines_graphql_wordlist_and_confirms() -> None:
    # GraphQL names 'secret_notes'; 'orders' comes from the built-in wordlist; both are real. A wordlist
    # word that isn't a real table ('users' here) is dropped by the oracle.
    fields = [{"name": "secret_notesCollection"}]
    client = _RoutedClient(existing={"secret_notes", "orders"}, introspect_fields=fields)
    disc = SupabaseDiscoverer(client)  # type: ignore[arg-type]
    prof = await disc.profile(
        "https://x.supabase.co/rest/v1/", graphql_url="https://x.supabase.co/graphql/v1"
    )
    urls = {p.url for p in prof.probes}
    assert "https://x.supabase.co/rest/v1/secret_notes" in urls
    assert "https://x.supabase.co/rest/v1/orders" in urls
    assert "https://x.supabase.co/rest/v1/users" not in urls  # in wordlist but not a real table
    assert prof.tables == {"secret_notes", "orders"}
    assert prof.introspection_enabled is True
    assert prof.oracle_blind is False
    assert prof.graphql_tables == {"secret_notes"}


async def test_profile_when_oracle_blind_trusts_exact_sources_only() -> None:
    # Oracle blind → wordlist guesses are untrusted, but exact GraphQL names still yield probes.
    fields = [{"name": "hidden_tableCollection"}]
    client = _RoutedClient(introspect_fields=fields, blind=True)
    disc = SupabaseDiscoverer(client)  # type: ignore[arg-type]
    prof = await disc.profile(
        "https://x.supabase.co/rest/v1/", graphql_url="https://x.supabase.co/graphql/v1"
    )
    urls = {p.url for p in prof.probes}
    assert urls == {"https://x.supabase.co/rest/v1/hidden_table"}  # only the exact GraphQL name, no wordlist
    assert prof.oracle_blind is True


def test_coverage_finding_reports_table_count() -> None:
    from dastcore.cli import _supabase_coverage_finding
    from dastcore.discovery.supabase import SupabaseProfile

    prof = SupabaseProfile(tables={"orders", "profiles"}, graphql_tables={"orders"}, introspection_enabled=True)
    finding = _supabase_coverage_finding("https://x.supabase.co/rest/v1/", prof)
    assert finding.severity == "info"
    assert finding.rule_id == "supabase-profile"
    assert "2 tabla" in finding.name
    assert "orders" in finding.evidence[0].data  # the tested tables are named in the evidence


def test_coverage_finding_when_no_tables_found() -> None:
    from dastcore.cli import _supabase_coverage_finding
    from dastcore.discovery.supabase import SupabaseProfile

    finding = _supabase_coverage_finding("https://x.supabase.co/rest/v1/", SupabaseProfile())
    assert finding.severity == "info"
    assert "no se descubri" in finding.name.lower()


# --- write-side RLS probe (Gap 1) -------------------------------------------------------------

class _WriteClient:
    """Fake client for the INSERT write-RLS probe: canned POST responses + records cleanup DELETEs."""

    def __init__(self, responses):
        self.responses = responses  # table -> (status, text)
        self.deleted: list = []

    def is_in_scope(self, url: str) -> bool:
        return True

    async def post(self, url: str, json=None, headers=None, timeout: float = 8.0, retries: int = 0):
        table = url.rstrip("/").rsplit("/", 1)[-1]
        status, text = self.responses.get(table, (400, '{"code":"PGRST204"}'))
        return SimpleNamespace(status_code=status, text=text)

    async def request(self, method: str, url: str, params=None, timeout: float = 6.0, retries: int = 0):
        self.deleted.append((method, url, params))
        return SimpleNamespace(status_code=204, text="")


async def test_probe_write_rls_classifies_and_cleans_up() -> None:
    responses = {
        "orders": (401, '{"code":"42501","message":"new row violates row-level security policy"}'),
        "public_notes": (201, '[{"id": 7, "title": "x"}]'),  # actually inserted → critical + cleanup
        "leads": (400, '{"code":"23502","message":"null value in column violates not-null constraint"}'),
        "quiet": (400, '{"code":"PGRST204","message":"Could not find the column"}'),  # inconclusive
    }
    client = _WriteClient(responses)
    findings = await probe_write_rls(
        client, "https://x.supabase.co/rest/v1/", {"orders", "public_notes", "leads", "quiet"}, identity="anon"
    )
    ids = {f.id for f in findings}
    assert "supabase-write-rls:public_notes:anon" in ids  # 201 created
    assert "supabase-write-rls:leads:anon" in ids  # 23502 → write authorized, data invalid
    assert not any("orders" in i for i in ids)  # 42501 → RLS blocked, secure
    assert not any("quiet" in i for i in ids)  # PGRST204 → inconclusive, no FP
    assert client.deleted, "the created row should have been cleaned up"
    created = next(f for f in findings if "public_notes" in f.id)
    authorized = next(f for f in findings if "leads" in f.id)
    assert created.severity == "critical"
    assert authorized.severity == "high"


def test_login_failed_finding_advises_unreliable_authz() -> None:
    from dastcore.cli import _login_failed_finding

    finding = _login_failed_finding("https://x.supabase.co/rest/v1/", ["authed"])
    assert finding.severity == "info"
    assert "authed" in finding.name
    assert finding.rule_id == "authz-login"


# --- cross-user BOLA (Gap 2) -------------------------------------------------------------------

class _BolaClient:
    """Fake client: `own_ids` = what this identity's collection returns; `leaks` = extra ids it can
    reach via a targeted id filter (i.e. a broken object-level policy)."""

    def __init__(self, own_ids, leaks=None):
        self.own_ids = own_ids  # table -> [id, ...]
        self.leaks = leaks or {}

    def is_in_scope(self, url: str) -> bool:
        return True

    async def get(self, url: str, params=None, timeout: float = 8.0, retries: int = 0):
        table = url.rstrip("/").rsplit("/", 1)[-1]
        params = params or {}
        if "id" in params and params["id"].startswith("in.("):
            wanted = params["id"][len("in.("):-1].split(",")
            reachable = set(self.own_ids.get(table, [])) | set(self.leaks.get(table, []))
            got = [i for i in wanted if i in reachable]
            return SimpleNamespace(status_code=200, text=json.dumps([{"id": i} for i in got]))
        return SimpleNamespace(status_code=200, text=json.dumps([{"id": i} for i in self.own_ids.get(table, [])]))


async def test_cross_user_bola_detects_id_leak() -> None:
    a = _BolaClient(own_ids={"notes": ["a1"]}, leaks={"notes": ["b1"]})  # A can reach B's row b1 by id → BOLA
    b = _BolaClient(own_ids={"notes": ["b1"]})
    findings = await probe_cross_user_bola(a, b, "https://x.supabase.co/rest/v1/", {"notes"}, name_a="A", name_b="B")
    assert len(findings) == 1
    assert findings[0].rule_id == "supabase-bola"
    assert findings[0].severity == "high"
    assert "b1" in findings[0].response.text


async def test_cross_user_bola_no_finding_when_isolated() -> None:
    a = _BolaClient(own_ids={"notes": ["a1"]})  # A cannot reach b1 → RLS correctly isolates
    b = _BolaClient(own_ids={"notes": ["b1"]})
    findings = await probe_cross_user_bola(a, b, "https://x.supabase.co/rest/v1/", {"notes"}, name_a="A", name_b="B")
    assert findings == []


async def test_cross_user_bola_skips_table_without_id_column() -> None:
    class _NoIdClient:
        def is_in_scope(self, url: str) -> bool:
            return True

        async def get(self, url: str, params=None, timeout: float = 8.0, retries: int = 0):
            return SimpleNamespace(status_code=400, text='{"code":"42703","message":"column notes.id does not exist"}')

    client = _NoIdClient()
    findings = await probe_cross_user_bola(
        client, client, "https://x.supabase.co/rest/v1/", {"notes"}, name_a="A", name_b="B"
    )
    assert findings == []  # no id column → id-based BOLA not applicable, no false positive
