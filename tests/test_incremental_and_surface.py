"""A1 (incremental finding persistence) + B5 (surface map) — improvements distilled from the
real-world getnyma scan: never lose findings to an interruption, and surface the whole map."""

from __future__ import annotations

from dastcore.cli import _run_scan
from dastcore.config import OutputConfig, RateLimitConfig, ScanConfig, ScopeConfig
from dastcore.report.incremental import FindingSink, load_jsonl


def test_finding_sink_appends_and_dedups(tmp_path, sample_finding) -> None:
    path = tmp_path / "partial.jsonl"
    with FindingSink(path) as sink:
        sink.write([sample_finding])
        sink.write([sample_finding])  # same id -> written only once
    back = load_jsonl(path)
    assert len(back) == 1
    assert back[0].id == sample_finding.id
    assert back[0].name == sample_finding.name


def test_load_jsonl_missing_file_is_empty(tmp_path) -> None:
    assert load_jsonl(tmp_path / "nope.jsonl") == []


async def test_run_scan_persists_findings_incrementally_and_maps_the_surface(vuln_app_url, tmp_path) -> None:
    log = tmp_path / "partial.jsonl"
    surface: dict = {}
    config = ScanConfig(
        target=vuln_app_url,  # type: ignore[arg-type]
        scope=ScopeConfig(allow_domains=["127.0.0.1"]),
        rate_limit=RateLimitConfig(requests_per_second=100, max_concurrency=10),
        output=OutputConfig(format="json"),
        i_have_authorization=True,
    )
    findings = await _run_scan(
        config,
        max_pages=40,
        engine="http",
        discover_content=True,
        discover_depth="light",
        findings_log=str(log),
        surface=surface,
    )

    # A1: findings were streamed to disk as they were found, matching the final set
    assert log.exists()
    persisted = load_jsonl(log)
    assert persisted, "expected findings streamed to the incremental log"
    assert {f.id for f in persisted} == {f.id for f in findings}

    # B5: the surface map captured the scanned host and the unlinked path content discovery found
    assert surface.get("roots")
    discovered_paths = [url for urls in surface.get("content", {}).values() for url in urls]
    assert any(url.rstrip("/").endswith("/backup") for url in discovered_paths)
