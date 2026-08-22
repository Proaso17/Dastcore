"""Historical URL mining (Wayback): passive attack-surface + parametrised endpoints as injection
points, scope-gated, fed into the scan. Offline — the archive source is injected/monkeypatched."""

from __future__ import annotations

from dastcore.cli import _run_scan
from dastcore.config import OutputConfig, RateLimitConfig, ScanConfig, ScopeConfig
from dastcore.discovery.historical import gather_historical_urls, prioritise, url_to_request


def test_url_to_request_parses_query_into_params() -> None:
    req = url_to_request("https://api.example.com/search?q=demo&page=2")
    assert req is not None
    assert req.url == "https://api.example.com/search"
    assert req.params == {"q": "demo", "page": "2"}


def test_url_to_request_rejects_non_http() -> None:
    assert url_to_request("ftp://example.com/x") is None
    assert url_to_request("not a url") is None


def test_prioritise_puts_parametrised_first_and_caps() -> None:
    plain = url_to_request("https://x.test/a")
    param = url_to_request("https://x.test/b?id=1")
    assert plain is not None and param is not None
    ordered = prioritise([plain, param], limit=10)
    assert ordered[0] is param  # injection-bearing URLs lead
    assert len(prioritise([plain, param, plain], limit=2)) == 2  # capped


async def test_gather_dedups_across_sources() -> None:
    async def source_a(_domain: str) -> list[str]:
        return ["https://x.test/a", "https://x.test/b"]

    async def source_b(_domain: str) -> list[str]:
        return ["https://x.test/b", "https://x.test/c"]  # b is a duplicate

    urls = await gather_historical_urls("x.test", sources=[source_a, source_b])
    assert urls == ["https://x.test/a", "https://x.test/b", "https://x.test/c"]


async def test_run_scan_scans_a_historical_parametrised_endpoint(vuln_app_url: str, monkeypatch) -> None:
    import dastcore.cli as cli

    # pretend the archive remembers an unlinked parametrised /backup?q= URL on the target
    async def fake_archive(_domain: str) -> list[str]:
        return [f"{vuln_app_url}/backup?q=seed", f"{vuln_app_url}/search?q=x"]

    monkeypatch.setattr(cli, "_looks_like_ip", lambda _host: False)  # let the 127.0.0.1 test target mine history
    monkeypatch.setattr(cli, "gather_historical_urls", fake_archive)

    config = ScanConfig(
        target=vuln_app_url,  # type: ignore[arg-type]
        scope=ScopeConfig(allow_domains=["127.0.0.1"]),
        rate_limit=RateLimitConfig(requests_per_second=100, max_concurrency=10),
        output=OutputConfig(format="json"),
        i_have_authorization=True,
    )
    findings = await _run_scan(config, max_pages=20, engine="http", use_historical=True)
    assert any(
        f.rule_id == "sqli-injection" and "/backup" in (f.request.url if f.request else "") for f in findings
    ), "the historical /backup?q= endpoint (with its param) should have been scanned and its SQLi found"
