"""Organisational OSINT — bucket candidate generation, listability detection, and finding builders,
all offline via injected fetchers/probers."""

from __future__ import annotations

from dastcore.discovery.osint import (
    BucketHit,
    GithubHit,
    _is_listable,
    bucket_candidates,
    bucket_findings,
    bucket_urls,
    check_buckets,
    github_code_search,
    github_findings,
)


def test_bucket_candidates_permutes_labels() -> None:
    names = bucket_candidates(["acme", ""])
    assert "acme" in names and "acme-backup" in names and "acme-prod" in names
    assert len(names) == len(set(names))  # deduped


def test_bucket_urls_covers_three_providers() -> None:
    providers = {p for p, _ in bucket_urls("acme-backup")}
    assert providers == {"AWS S3", "Google Cloud Storage", "Azure Blob"}


def test_is_listable_only_for_world_readable_listings() -> None:
    assert _is_listable("AWS S3", 200, "<ListBucketResult><Contents>...</Contents></ListBucketResult>")
    assert not _is_listable("AWS S3", 403, "<Error><Code>AccessDenied</Code></Error>")
    assert not _is_listable("AWS S3", 200, "<Error>nope</Error>")
    assert _is_listable("Azure Blob", 200, "<EnumerationResults>...</EnumerationResults>")


async def test_check_buckets_reports_only_listable() -> None:
    listable_url = "https://acme-backup.s3.amazonaws.com/"

    async def prober(url: str):
        if url == listable_url:
            return 200, "<ListBucketResult><Contents/></ListBucketResult>"
        if "acme.s3" in url:
            return 403, "<Error><Code>AccessDenied</Code></Error>"  # exists but private -> not reported
        return None

    hits = await check_buckets(["acme"], prober=prober)
    assert [h.url for h in hits] == [listable_url]
    assert hits[0].listable is True


def test_bucket_findings_are_high_severity() -> None:
    findings = bucket_findings([BucketHit(provider="AWS S3", url="https://x.s3.amazonaws.com/", listable=True)])
    assert len(findings) == 1 and findings[0].severity == "high" and findings[0].rule_id == "osint-open-bucket"


async def test_github_search_needs_token_and_parses_items() -> None:
    # No token -> nothing, never touches the network.
    assert await github_code_search("acme.com", token="") == []

    async def fetch(_url: str, _headers: dict[str, str]):
        return {"items": [{"repository": {"full_name": "o/r"}, "path": "cfg.yml", "html_url": "https://gh/x"}]}

    hits = await github_code_search("acme.com", token="t", fetcher=fetch)
    assert hits == [GithubHit(repo="o/r", path="cfg.yml", url="https://gh/x")]
    findings = github_findings("acme.com", hits)
    assert len(findings) == 1 and findings[0].severity == "info" and findings[0].rule_id == "osint-public-code"
