"""The dashboard program form must let you set a rate limit — the key control for honouring a
bug-bounty safe harbor's 'avoid harm' clause (e.g. scanning a bank gently). It has to reach the actual
per-request rate the hunt uses."""

from __future__ import annotations

from dastcore.web.app import _program_from_form


def test_form_rate_limit_reaches_the_scan_config() -> None:
    program = _program_from_form(
        "bancoplata", "hackerone", "*.bancoplata.mx", "history.bancoplata.mx",
        allow_active=True, rps=2.0, concurrency=2,
    )
    assert program.limits.requests_per_second == 2.0 and program.limits.max_concurrency == 2
    cfg = program.to_scan_config("https://beta.bancoplata.mx/", authorized=True)
    assert cfg.rate_limit.requests_per_second == 2.0 and cfg.rate_limit.max_concurrency == 2
    assert program.scope.wildcards == ["*.bancoplata.mx"] and program.scope.out_of_scope == ["history.bancoplata.mx"]


def test_form_defaults_and_active_toggle() -> None:
    # Unchecking "allow_active" -> recon/passive only; invalid rps falls back to the default.
    recon_only = _program_from_form("t", "self", "acme.com", "", allow_active=False, rps=0, concurrency=0)
    assert recon_only.allows_active_scanning() is False
    assert recon_only.limits.requests_per_second == 5.0 and recon_only.limits.max_concurrency == 5
