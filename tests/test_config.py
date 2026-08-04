from __future__ import annotations

from dastcore.config import ScanConfig, ScopeConfig


def test_scope_defaults_to_target_host_when_unset() -> None:
    config = ScanConfig(target="http://localhost:5000/")
    assert config.scope.allow_domains == ["localhost"]


def test_target_host_stays_in_scope_even_with_explicit_allow_domains() -> None:
    """Regression: --allow-domain must widen scope, never replace the target's own host."""
    config = ScanConfig(
        target="http://localhost:5000/",
        scope=ScopeConfig(allow_domains=["api.localhost"], deny_domains=["internal.localhost"]),
    )
    assert "localhost" in config.scope.allow_domains
    assert "api.localhost" in config.scope.allow_domains
    assert config.scope.deny_domains == ["internal.localhost"]


def test_target_host_not_duplicated_if_already_explicit() -> None:
    config = ScanConfig(
        target="http://localhost:5000/",
        scope=ScopeConfig(allow_domains=["localhost", "api.localhost"]),
    )
    assert config.scope.allow_domains.count("localhost") == 1
