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


async def test_run_scan_survives_a_network_error_mid_scan(vuln_app_url: str, monkeypatch) -> None:
    import httpx

    import dastcore.cli as cli

    async def _boom(*_args, **_kwargs):
        raise httpx.ConnectError("network blip")

    # a flaky check partway through must not discard everything crawled/scanned before it
    monkeypatch.setattr(cli, "run_nosql_checks", _boom)
    config = ScanConfig(
        target=vuln_app_url,  # type: ignore[arg-type]
        scope=ScopeConfig(allow_domains=["127.0.0.1"]),
        rate_limit=RateLimitConfig(requests_per_second=100, max_concurrency=10),
        output=OutputConfig(format="json"),
        i_have_authorization=True,
    )
    findings = await _run_scan(config, max_pages=30, engine="http")
    assert isinstance(findings, list)  # partial report, not a crash


async def test_a_failing_check_is_isolated_not_fatal(vuln_app_url: str, monkeypatch) -> None:
    """A4: any single check raising an unexpected error is skipped (logged), the scan still finishes,
    and the report flags partial coverage — instead of the whole scan crashing."""
    import dastcore.cli as cli

    async def _boom(*_args, **_kwargs):
        raise ValueError("a detector bug")

    monkeypatch.setattr(cli, "run_nosql_checks", _boom)
    config = ScanConfig(
        target=vuln_app_url,  # type: ignore[arg-type]
        scope=ScopeConfig(allow_domains=["127.0.0.1"]),
        rate_limit=RateLimitConfig(requests_per_second=100, max_concurrency=10),
        output=OutputConfig(format="json"),
        i_have_authorization=True,
    )
    findings = await _run_scan(config, max_pages=30, engine="http")
    assert isinstance(findings, list)
    assert any(f.rule_id == "scan-coverage" for f in findings)  # partial coverage advisory present
    # the rest of the scan still ran: real vulns on the vuln app are still found
    assert any(f.severity in ("critical", "high", "medium") for f in findings)


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
