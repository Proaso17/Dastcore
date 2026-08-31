"""Attack-surface tiering: admin/API/internal hosts → Tier 1 (scan first), legacy stacks → Tier 2,
main app → Tier 3. A priority signal only — nothing is excluded by tier."""

from __future__ import annotations

from dastcore.recon.models import Asset
from dastcore.recon.tiering import assign_tiers, by_tier, classify_tier, tier_counts


def _asset(host: str, tech: list[str] | None = None) -> Asset:
    return Asset(host=host, url=f"http://{host}/", tech=tech or [])


def test_admin_api_internal_hosts_are_tier_1() -> None:
    for host in ("admin.acme.com", "api.acme.com", "staging.acme.com", "dev.acme.com",
                 "internal.acme.com", "sso.acme.com", "jenkins.acme.com"):
        assert classify_tier(_asset(host)) == 1, host


def test_whole_label_match_avoids_false_positives() -> None:
    # "development" / "apidocs" are single labels that must NOT match "dev" / "api".
    assert classify_tier(_asset("development-notes.acme.com")) == 3
    assert classify_tier(_asset("apidocs.acme.com")) == 3
    # but a real "api" label is Tier 1
    assert classify_tier(_asset("api.acme.com")) == 1


def test_legacy_tech_is_tier_2() -> None:
    assert classify_tier(_asset("shop.acme.com", tech=["PHP", "WordPress"])) == 2
    assert classify_tier(_asset("old.acme.com", tech=["Apache/2.2"])) == 2


def test_main_app_is_tier_3() -> None:
    assert classify_tier(_asset("www.acme.com", tech=["nginx", "React"])) == 3


def test_tier_1_beats_tier_2_when_both_match() -> None:
    # An admin host on a legacy stack is still Tier 1 (host priority wins).
    assert classify_tier(_asset("admin.acme.com", tech=["PHP"])) == 1


def test_by_tier_orders_high_priority_first_and_sets_tier() -> None:
    assets = [_asset("www.acme.com"), _asset("admin.acme.com"), _asset("old.acme.com", tech=["PHP"])]
    ordered = by_tier(assets)
    assert [a.host for a in ordered] == ["admin.acme.com", "old.acme.com", "www.acme.com"]
    assert [a.tier for a in ordered] == [1, 2, 3]  # tier set in place


def test_tier_counts() -> None:
    assets = [_asset("api.acme.com"), _asset("admin.acme.com"), _asset("shop.acme.com", tech=["php"]),
              _asset("www.acme.com")]
    assert tier_counts(assets) == {1: 2, 2: 1, 3: 1}


def test_assign_tiers_mutates_in_place() -> None:
    a = _asset("api.acme.com")
    assert a.tier == 3  # default before classification
    assign_tiers([a])
    assert a.tier == 1
