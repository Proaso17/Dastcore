"""Target coordinator: fetch each homepage once, collapse identical-content deployments into one
representative, and order survivors by promise. Deterministic; the fetch is injected (offline)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from dastcore.analysis.coordinator import content_fingerprint, coordinate, score_target
from dastcore.recon.models import Asset


def _fetch(mapping: dict[str, tuple[int, str]]) -> Callable[[str], Awaitable[tuple[int, str] | None]]:
    async def fetch(url: str) -> tuple[int, str] | None:
        return mapping.get(url)

    return fetch


async def test_identical_homepages_collapse_to_one_representative() -> None:
    assets = [
        Asset(host="a.t.com", url="https://a.t.com", tier=3),
        Asset(host="b.t.com", url="https://b.t.com", tier=3),
        Asset(host="api.t.com", url="https://api.t.com", tier=1),
    ]
    parked = "<html><head><title>Parked</title></head><body>coming soon — buy this domain</body></html>"
    app = "<html><head><title>Acme API</title></head><body>the real app, totally different markup</body></html>"
    result = await coordinate(
        assets,
        _fetch({"https://a.t.com": (200, parked), "https://b.t.com": (200, parked), "https://api.t.com": (200, app)}),
    )
    urls = [a.url for a in result.order]
    assert result.skipped == 1                       # a and b are the same parked page → one collapsed
    assert len(result.order) == 2 and "https://api.t.com" in urls
    assert result.order[0].url == "https://api.t.com"  # tier-1 app outranks the parked tier-3 pages
    # one of a/b represents the pair; the other is recorded as its duplicate
    rep = next(u for u in urls if u != "https://api.t.com")
    assert rep in result.duplicates and len(result.duplicates[rep]) == 1


async def test_unreachable_or_blank_assets_are_never_merged() -> None:
    assets = [Asset(host="x.t.com", url="https://x.t.com"), Asset(host="y.t.com", url="https://y.t.com")]
    result = await coordinate(assets, _fetch({}))  # both unreachable → fetch returns None
    assert result.skipped == 0 and len(result.order) == 2  # a failed/blank fetch must not swallow a host


async def test_auth_surface_and_tier_raise_promise_score() -> None:
    login = Asset(host="login.t.com", url="https://login.t.com", tier=1)
    plain = Asset(host="www.t.com", url="https://www.t.com", tier=3)
    s_login = score_target(login, 200, '<form action="/in"><input type="password" name="pwd"></form>')
    s_plain = score_target(plain, 200, "<p>hello world</p>")
    assert s_login > s_plain  # an auth form + tier 1 is a far more promising target than a plain page


def test_content_fingerprint_is_stable_and_discriminating() -> None:
    assert content_fingerprint("<p>same body</p>") == content_fingerprint("<p>same body</p>")
    assert content_fingerprint("<p>one app</p>") != content_fingerprint("<p>a very different app</p>")
