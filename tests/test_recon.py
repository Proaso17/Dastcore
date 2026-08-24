"""Phase 10 recon — all offline via replay/fixtures. Validates parsing, the scope gate (out-of-scope
assets are never stored), profile/no-scan gating, graceful degrade, and store dedupe."""

from __future__ import annotations

from dastcore.bugbounty import Program
from dastcore.core.scope import ScopeChecker
from dastcore.recon import AssetStore, ReconOptions, run_recon
from dastcore.recon.adapters import CrtShAdapter, HttpxAdapter, NaabuAdapter, SubfinderAdapter
from dastcore.recon.models import Asset

_CRTSH = '[{"name_value":"api.acme.com\\nwww.acme.com\\n*.acme.com"},{"name_value":"evil.com"}]'
_SUBFINDER = "api.acme.com\ndev.acme.com\n\n"
_HTTPX = (
    '{"url":"https://api.acme.com","host":"api.acme.com","port":443,"status_code":200,"title":"API","tech":["nginx"],"a":["203.0.113.5"]}\n'
    '{"url":"https://evil.com","host":"evil.com","status_code":200}\n'  # out of scope
)


def _program() -> Program:
    return Program.model_validate(
        {"handle": "acme", "scope": {"domains": ["acme.com"], "wildcards": ["*.acme.com"]}, "seeds": ["acme.com"]}
    )


def _checker() -> ScopeChecker:
    return ScopeChecker(_program().to_scope_config())


# --- pure parsers -----------------------------------------------------------------------------


def test_crtsh_parses_and_normalizes_subdomains() -> None:
    hosts = {a.host for a in CrtShAdapter().parse(_CRTSH)}
    assert {"api.acme.com", "www.acme.com", "acme.com", "evil.com"} <= hosts  # scope filtering happens later
    assert "*.acme.com" not in hosts  # wildcard stripped


def test_subfinder_parses_lines() -> None:
    assert {a.host for a in SubfinderAdapter().parse(_SUBFINDER)} == {"api.acme.com", "dev.acme.com"}


def test_naabu_parses_plain_and_json_lines() -> None:
    raw = 'api.acme.com:8080\napi.acme.com:443\n{"host":"dev.acme.com","port":22}\n\nbroken\n'
    assets = NaabuAdapter().parse(raw)
    pairs = {(a.host, a.port) for a in assets}
    assert pairs == {("api.acme.com", 8080), ("api.acme.com", 443), ("dev.acme.com", 22)}
    assert all(a.source == "naabu" for a in assets)


def test_httpx_parses_live_hosts() -> None:
    assets = HttpxAdapter().parse(_HTTPX)
    api = next(a for a in assets if a.host == "api.acme.com")
    assert api.url == "https://api.acme.com" and api.status_code == 200 and api.tech == ["nginx"]
    assert api.ip == "203.0.113.5" and api.port == 443


# --- orchestrator: scope gate + profiles ------------------------------------------------------


def _opts(profile: str = "standard") -> ReconOptions:
    return ReconOptions(profile=profile, replay={"crtsh": _CRTSH, "httpx": _HTTPX})


async def test_recon_stores_only_in_scope_assets(tmp_path) -> None:
    store = AssetStore(tmp_path / "assets.db")
    stored = await run_recon(["acme.com"], _opts(), store, _checker(), adapters=[CrtShAdapter(), HttpxAdapter()])
    hosts = {a.host for a in store.all()}
    assert "api.acme.com" in hosts and "www.acme.com" in hosts
    assert "evil.com" not in hosts  # dropped by the scope gate, never stored
    assert any(a.url == "https://api.acme.com" for a in store.live())  # httpx result stored
    assert all(a.host != "evil.com" for a in stored)
    store.close()


async def test_passive_profile_skips_the_active_probe(tmp_path) -> None:
    store = AssetStore(tmp_path / "assets.db")
    await run_recon(["acme.com"], _opts("passive"), store, _checker(), adapters=[CrtShAdapter(), HttpxAdapter()])
    assert store.live() == []  # httpx (passive=False) not run in the passive profile
    assert {a.host for a in store.all()}  # but subdomain enumeration still populated the store
    store.close()


async def test_no_automated_scanning_blocks_active_probe(tmp_path) -> None:
    store = AssetStore(tmp_path / "assets.db")
    await run_recon(
        ["acme.com"], _opts(), store, _checker(), allow_active=False, adapters=[CrtShAdapter(), HttpxAdapter()]
    )
    assert store.live() == []  # program forbids automated scanning -> no active probing
    store.close()


async def test_missing_tool_degrades_gracefully() -> None:
    class _Ghost(SubfinderAdapter):
        binary = "definitely-not-installed-xyz"

    assert await _Ghost().collect(["acme.com"], ReconOptions()) == []  # no crash, just nothing


# --- store dedupe + first_seen/last_seen ------------------------------------------------------


def test_store_dedupes_and_tracks_timestamps(tmp_path) -> None:
    store = AssetStore(tmp_path / "assets.db")
    asset = Asset(host="api.acme.com", url="https://api.acme.com", source="httpx")
    assert store.upsert(asset, now=1000.0) is True  # new
    assert store.upsert(asset, now=2000.0) is False  # dedup -> update
    rows = store.all()
    assert len(rows) == 1
    ts = store._conn.execute("SELECT first_seen, last_seen FROM assets").fetchone()
    assert ts["first_seen"] == 1000.0 and ts["last_seen"] == 2000.0
    store.close()
