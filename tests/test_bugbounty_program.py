"""Phase 9: bug-bounty program layer + wildcard/CIDR scope. Out-of-scope always wins; a bare host/IP
can be scope-checked for recon; and 'no automated scanning' disables active scanning."""

from __future__ import annotations

from dastcore.bugbounty import Program, load_program
from dastcore.config import ScopeConfig
from dastcore.core.scope import ScopeChecker

# --- extended ScopeChecker: wildcard + CIDR + is_asset_in_scope ------------------------------


def _checker(allow: list[str], deny: list[str] | None = None) -> ScopeChecker:
    return ScopeChecker(ScopeConfig(allow_domains=allow, deny_domains=deny or [], allow_subdomains=True))


def test_wildcard_matches_subdomains_not_apex() -> None:
    c = _checker(["*.target.com"])
    assert c.is_asset_in_scope("api.target.com")
    assert c.is_asset_in_scope("a.b.target.com")
    assert not c.is_asset_in_scope("target.com")  # *.x is subdomains only
    assert not c.is_asset_in_scope("nottarget.com")


def test_exact_domain_matches_apex() -> None:
    c = _checker(["target.com"])
    assert c.is_asset_in_scope("target.com")
    assert c.is_asset_in_scope("api.target.com")  # allow_subdomains default


def test_cidr_matches_ip_in_range() -> None:
    c = _checker(["10.0.0.0/8"])
    assert c.is_asset_in_scope("10.1.2.3")
    assert not c.is_asset_in_scope("11.0.0.1")
    assert not c.is_asset_in_scope("api.target.com")  # not an IP -> not in the CIDR


def test_out_of_scope_wins_over_in_scope() -> None:
    c = _checker(["*.target.com"], deny=["secret.target.com"])
    assert c.is_asset_in_scope("api.target.com")
    assert not c.is_asset_in_scope("secret.target.com")  # deny wins


def test_deny_by_default() -> None:
    assert not _checker([]).is_asset_in_scope("anything.com")


def test_url_scope_honours_wildcards() -> None:
    c = _checker(["*.target.com"])
    assert c.is_in_scope("https://api.target.com/x")
    assert not c.is_in_scope("https://evil.com/x")


# --- Program model ---------------------------------------------------------------------------


def _program(**limits) -> Program:
    return Program.model_validate(
        {
            "platform": "hackerone",
            "handle": "acme",
            "scope": {"wildcards": ["*.acme.com"], "domains": ["acme.io"], "out_of_scope": ["blog.acme.com"]},
            "limits": limits,
            "seeds": ["acme.com"],
        }
    )


def test_program_maps_to_scope_config_with_precedence() -> None:
    checker = ScopeChecker(_program().to_scope_config())
    assert checker.is_asset_in_scope("api.acme.com")
    assert checker.is_asset_in_scope("acme.io")
    assert not checker.is_asset_in_scope("blog.acme.com")  # out_of_scope wins


def test_no_automated_scanning_disables_active() -> None:
    assert _program().allows_active_scanning() is True
    assert _program(no_automated_scanning=True).allows_active_scanning() is False


def test_to_scan_config_carries_authorization_and_rate() -> None:
    program = _program(requests_per_second=2.0, max_concurrency=3)
    cfg = program.to_scan_config("https://api.acme.com", authorized=True)
    assert cfg.i_have_authorization is True
    assert cfg.rate_limit.requests_per_second == 2.0 and cfg.rate_limit.max_concurrency == 3
    assert ScopeChecker(cfg.scope).is_in_scope("https://api.acme.com/")
    # a loaded program never bypasses the legal gate on its own
    assert program.to_scan_config("https://api.acme.com", authorized=False).i_have_authorization is False


def test_loader_round_trips_program_yaml(tmp_path) -> None:
    path = tmp_path / "program.yaml"
    path.write_text(
        "platform: bugcrowd\n"
        "handle: widgets\n"
        "scope:\n"
        "  wildcards: ['*.widgets.io']\n"
        "  cidrs: ['192.168.0.0/16']\n"
        "  out_of_scope: ['legacy.widgets.io']\n"
        "limits:\n"
        "  requests_per_second: 1.5\n"
        "  no_automated_scanning: true\n"
        "seeds: ['widgets.io']\n",
        encoding="utf-8",
    )
    program = load_program(path)
    assert program.platform == "bugcrowd" and program.handle == "widgets"
    assert program.allows_active_scanning() is False
    checker = ScopeChecker(program.to_scope_config())
    assert checker.is_asset_in_scope("app.widgets.io")
    assert checker.is_asset_in_scope("192.168.1.10")
    assert not checker.is_asset_in_scope("legacy.widgets.io")
