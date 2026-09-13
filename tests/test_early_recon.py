"""Early recon brain: a fingerprint at the start decides which recon techniques to turn on — but only the
ones the operator left at their default (auto_recon). Explicit flags always win; an empty auto_recon set
(web/hunt/tests, or a fully-pinned run) changes nothing."""

from __future__ import annotations

from dastcore.analysis.planner import TargetProfile, plan_recon
from dastcore.cli import _apply_early_recon

_ALL = frozenset({"engine", "use_js", "discover_content", "mine_params"})


def _apply(auto_recon, profile, **flags):
    recon = plan_recon(profile)
    base = {"engine": "http", "use_js": False, "discover_content": False, "mine_params": False, **flags}
    return _apply_early_recon(auto_recon, recon, profile, **base)


def test_spa_turns_on_headless_and_js() -> None:
    engine, use_js, _dc, _mp, upgrades = _apply(_ALL, TargetProfile(is_spa=True))
    assert engine == "both" and use_js is True
    assert any("headless" in u for u in upgrades)


def test_framework_and_api_turn_on_content_and_param_mining() -> None:
    engine, use_js, dc, mp, _ = _apply(_ALL, TargetProfile(frameworks=frozenset({"spring"}), api_kind="rest"))
    assert dc is True and mp is True          # stack paths to probe + an API → content discovery + Arjun
    assert engine == "http" and use_js is False  # no SPA signal → no headless / JS mining


def test_explicit_flags_are_never_overridden() -> None:
    # 'engine' not in auto_recon (the user pinned --engine http) → stays http even though it's a SPA.
    engine, *_ = _apply(frozenset({"use_js"}), TargetProfile(is_spa=True))
    assert engine == "http"


def test_already_enabled_is_left_alone() -> None:
    # engine already 'both' → no spurious change/upgrade entry.
    engine, _js, _dc, _mp, upgrades = _apply(_ALL, TargetProfile(is_spa=True), engine="both")
    assert engine == "both" and not any("headless" in u for u in upgrades)


def test_empty_auto_recon_is_a_no_op() -> None:
    engine, use_js, dc, mp, upgrades = _apply(frozenset(), TargetProfile(is_spa=True, api_kind="rest"))
    assert (engine, use_js, dc, mp) == ("http", False, False, False) and upgrades == []
