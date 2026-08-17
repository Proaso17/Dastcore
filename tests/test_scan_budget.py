"""A --max-requests / --time-budget cap is a soft stop: the scan must report whatever it gathered,
never crash with an unhandled BudgetExceededError (regression for the full-surface discovery timeout)."""

from __future__ import annotations

from dastcore.cli import _Budget, _run_scan
from dastcore.config import OutputConfig, RateLimitConfig, ScanConfig, ScopeConfig


async def test_run_scan_survives_budget_exhaustion(vuln_app_url: str) -> None:
    config = ScanConfig(
        target=vuln_app_url,  # type: ignore[arg-type]
        scope=ScopeConfig(allow_domains=["127.0.0.1"]),
        rate_limit=RateLimitConfig(requests_per_second=100, max_concurrency=10),
        output=OutputConfig(format="json"),
        i_have_authorization=True,
    )
    # a 5-request budget is spent almost immediately; the scan must return a list, not raise
    findings = await _run_scan(config, max_pages=50, engine="http", budget=_Budget(5, None))
    assert isinstance(findings, list)


async def test_run_scan_survives_budget_exhaustion_during_discovery(vuln_app_url: str) -> None:
    config = ScanConfig(
        target=vuln_app_url,  # type: ignore[arg-type]
        scope=ScopeConfig(allow_domains=["127.0.0.1"]),
        rate_limit=RateLimitConfig(requests_per_second=100, max_concurrency=10),
        output=OutputConfig(format="json"),
        i_have_authorization=True,
    )
    # content discovery would send hundreds of probes; the tiny budget stops it cleanly
    findings = await _run_scan(
        config, max_pages=50, engine="http", budget=_Budget(8, None), discover_content=True, discover_depth="light"
    )
    assert isinstance(findings, list)
