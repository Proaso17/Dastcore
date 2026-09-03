"""Supabase-aware discovery: mine table names from a front-end bundle → per-table RLS probes."""

from __future__ import annotations

from types import SimpleNamespace

from dastcore.discovery.supabase import (
    SupabaseDiscoverer,
    mine_supabase_refs,
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
