"""Manual seeds unified into the scan: a known path (or host) you provide is always probed and
scanned, even without the automatic sweep — and it's recursed like the rest."""

from __future__ import annotations

from dastcore.cli import _run_scan
from dastcore.config import OutputConfig, RateLimitConfig, ScanConfig, ScopeConfig


def _config(url: str) -> ScanConfig:
    return ScanConfig(
        target=url,  # type: ignore[arg-type]
        scope=ScopeConfig(allow_domains=["127.0.0.1"]),
        rate_limit=RateLimitConfig(requests_per_second=100, max_concurrency=10),
        output=OutputConfig(format="json"),
        i_have_authorization=True,
    )


async def test_manual_seed_path_reaches_an_unlinked_vuln_without_auto_discovery(vuln_app_url: str) -> None:
    # /backup is unlinked and auto content-discovery is OFF; only the manual seed path leads there.
    findings = await _run_scan(_config(vuln_app_url), max_pages=40, engine="http", seed_paths=["backup"])
    assert any(
        f.rule_id == "sqli-injection" and "/backup" in (f.request.url if f.request else "") for f in findings
    ), "the manually-seeded /backup path should have been scanned and its SQLi reported"


async def test_manual_seed_path_with_query_is_scanned_directly(vuln_app_url: str) -> None:
    # A seed carrying a query string becomes a DIRECT scannable request (its params are injection
    # points), so a known vulnerable URL is tested even when it's unlinked and dirbust can't parse it.
    findings = await _run_scan(_config(vuln_app_url), max_pages=1, engine="http", seed_paths=["backup?q=x"])
    assert any(
        f.rule_id == "sqli-injection" and "/backup" in (f.request.url if f.request else "") for f in findings
    ), "a query-string seed should be scanned directly and its SQLi reported"
