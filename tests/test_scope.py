from __future__ import annotations

from dastcore.config import ScopeConfig
from dastcore.core.scope import ScopeChecker, is_in_scope


def test_allows_exact_domain() -> None:
    scope = ScopeConfig(allow_domains=["example.com"])
    assert is_in_scope("http://example.com/path", scope) is True


def test_denies_domain_not_in_allowlist() -> None:
    scope = ScopeConfig(allow_domains=["example.com"])
    assert is_in_scope("http://evil.com/path", scope) is False


def test_auth_endpoint_is_reachable_off_scope_but_not_the_rest_of_its_host() -> None:
    # The IdP (supabase) isn't in the attack scope, but the exact token endpoint must be reachable
    # for (re)login — while nothing else on that host is.
    scope = ScopeConfig(allow_domains=["example.com"], allow_subdomains=True)
    token_url = "https://proj.supabase.co/auth/v1/token?grant_type=password"
    checker = ScopeChecker(scope, auth_urls=[token_url])
    assert checker.is_in_scope(token_url) is True                                   # exact auth endpoint
    assert checker.is_in_scope("https://proj.supabase.co/auth/v1/token") is True    # same path, other query
    assert checker.is_in_scope("https://proj.supabase.co/rest/v1/users") is False   # rest of the IdP: not scanned
    assert checker.is_in_scope("https://api.example.com/") is True                  # real scope still works


def test_auth_endpoint_exemption_still_respects_deny() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], deny_domains=["idp.example.com"])
    url = "https://idp.example.com/token"
    assert ScopeChecker(scope, auth_urls=[url]).is_in_scope(url) is False  # deny wins over the exemption


def test_allows_subdomain_when_enabled() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], allow_subdomains=True)
    assert is_in_scope("http://api.example.com/path", scope) is True


def test_denies_subdomain_when_disabled() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], allow_subdomains=False)
    assert is_in_scope("http://api.example.com/path", scope) is False


def test_denies_sibling_domain_that_merely_ends_with_pattern() -> None:
    scope = ScopeConfig(allow_domains=["example.com"])
    assert is_in_scope("http://notexample.com/path", scope) is False


def test_deny_domain_overrides_allow() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], deny_domains=["internal.example.com"])
    assert is_in_scope("http://internal.example.com/admin", scope) is False
    assert is_in_scope("http://public.example.com/", scope) is True


def test_denies_disallowed_scheme() -> None:
    scope = ScopeConfig(allow_domains=["example.com"])
    assert is_in_scope("ftp://example.com/path", scope) is False
    assert is_in_scope("file:///etc/passwd", scope) is False


def test_allowed_ports_enforced() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], allowed_ports=[443])
    assert is_in_scope("https://example.com:443/", scope) is True
    assert is_in_scope("https://example.com:8443/", scope) is False


def test_default_port_used_when_no_port_specified() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], allowed_ports=[80])
    assert is_in_scope("http://example.com/", scope) is True


def test_no_allow_domains_means_nothing_in_scope() -> None:
    scope = ScopeConfig()
    assert is_in_scope("http://example.com/", scope) is False


def test_scope_checker_reusable_across_calls() -> None:
    checker = ScopeChecker(ScopeConfig(allow_domains=["example.com"]))
    assert checker.is_in_scope("http://example.com/a") is True
    assert checker.is_in_scope("http://example.com/b") is True
    assert checker.is_in_scope("http://other.com/") is False


def test_malformed_url_is_not_in_scope() -> None:
    scope = ScopeConfig(allow_domains=["example.com"])
    assert is_in_scope("not a url", scope) is False
    assert is_in_scope("http://", scope) is False


# --- path-level scope (bug-bounty route exclusions / prefix scoping) ----------------------------


def test_deny_paths_excludes_a_route_on_an_in_scope_host() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], deny_paths=["/admin/*", "/internal"])
    assert is_in_scope("http://example.com/public", scope) is True
    assert is_in_scope("http://example.com/admin/users", scope) is False  # glob excluded
    assert is_in_scope("http://example.com/internal", scope) is False  # prefix excluded
    assert is_in_scope("http://example.com/internal/x", scope) is False
    assert is_in_scope("http://example.com/internalize", scope) is True  # prefix is label-bounded


def test_deny_paths_glob_on_extension() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], deny_paths=["*.bak"])
    assert is_in_scope("http://example.com/db.bak", scope) is False
    assert is_in_scope("http://example.com/db.sql", scope) is True


def test_allow_paths_gates_to_a_prefix_only() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], allow_paths=["/api/*"])
    assert is_in_scope("http://example.com/api/v1/orders", scope) is True
    assert is_in_scope("http://example.com/", scope) is False  # not under the allowed prefix
    assert is_in_scope("http://example.com/app", scope) is False


def test_path_scope_does_not_affect_out_of_scope_hosts() -> None:
    scope = ScopeConfig(allow_domains=["example.com"], deny_paths=["/admin/*"])
    assert is_in_scope("http://evil.test/public", scope) is False  # host still decides first
