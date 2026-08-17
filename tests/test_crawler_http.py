from __future__ import annotations

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.discovery.crawler_http import HttpCrawler


async def test_crawler_discovers_pages_links_and_forms_within_scope(vuln_app_url: str) -> None:
    # use_robots=False to isolate link/form discovery from robots/sitemap seeding.
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        discovered = await HttpCrawler(client, use_robots=False).crawl(f"{vuln_app_url}/")

    urls = [req.url for req in discovered]

    assert any(url.rstrip("/") == vuln_app_url.rstrip("/") for url in urls)

    # link (?q=demo) and form (q=) for /search dedup to a single discovered request
    search_requests = [req for req in discovered if req.url.endswith("/search")]
    assert len(search_requests) == 1
    assert "q" in search_requests[0].params

    greet_requests = [req for req in discovered if req.url.endswith("/greet")]
    assert len(greet_requests) == 1
    assert greet_requests[0].params.get("name") == "world"

    go_requests = [req for req in discovered if req.url.endswith("/go")]
    assert len(go_requests) == 1
    assert go_requests[0].params.get("url") == "/"

    file_requests = [req for req in discovered if req.url.endswith("/file")]
    assert len(file_requests) == 1
    assert file_requests[0].params.get("name") == "readme.txt"

    login_requests = [req for req in discovered if req.url.endswith("/login")]
    assert len(login_requests) == 1
    assert login_requests[0].method == "POST"
    assert set(login_requests[0].data or {}) == {"username", "password"}

    # the out-of-scope external link must never be followed
    assert not any("example.invalid" in url for url in urls)


async def test_crawler_seeds_from_robots_and_sitemap(vuln_app_url: str) -> None:
    """/secret-area is only referenced from robots.txt Disallow — reachable only via seeding."""
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        discovered = await HttpCrawler(client, use_robots=True).crawl(f"{vuln_app_url}/")
    urls = {req.url for req in discovered}
    assert any(u.endswith("/secret-area") for u in urls), urls


async def test_crawler_can_disable_robots_seeding(vuln_app_url: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        discovered = await HttpCrawler(client, use_robots=False).crawl(f"{vuln_app_url}/")
    urls = {req.url for req in discovered}
    assert not any(u.endswith("/secret-area") for u in urls)


async def test_crawler_dedups_by_request_shape_not_by_value(vuln_app_url: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        discovered = await HttpCrawler(client).crawl(f"{vuln_app_url}/")

    signatures = [req.signature() for req in discovered]
    assert len(signatures) == len(set(signatures))


async def test_crawler_respects_max_pages(vuln_app_url: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    async with HttpClient(scope) as client:
        discovered = await HttpCrawler(client, max_pages=1).crawl(f"{vuln_app_url}/")

    urls = [req.url for req in discovered]

    assert any(url.rstrip("/") == vuln_app_url.rstrip("/") for url in urls)
    # forms embedded on the one fetched page are recorded without needing a second fetch
    assert any(url.endswith("/search") for url in urls)
    assert any(url.endswith("/login") for url in urls)
    # but /greet, /go and /file are only linked, not embedded as forms — reaching
    # them needs a second page fetch, which max_pages=1 forbids
    assert not any(url.endswith("/greet") for url in urls)
    assert not any(url.endswith("/go") for url in urls)
    assert not any(url.endswith("/file") for url in urls)


async def test_crawler_skips_pages_that_error_and_keeps_going() -> None:
    """A transient network error on one page must not abort the crawl (multi-host resilience)."""
    import httpx as _httpx

    from dastcore.core.models import HttpResponse

    class _FlakyClient:
        def is_in_scope(self, url: str) -> bool:
            return True

        async def get(self, url: str) -> HttpResponse:
            if url.endswith("/bad"):
                raise _httpx.ConnectError("boom")
            body = '<a href="/bad">x</a><a href="/good">y</a>'
            return HttpResponse(method="GET", status_code=200, headers={"content-type": "text/html"}, text=body, url=url)

    discovered = await HttpCrawler(_FlakyClient(), use_robots=False).crawl("http://t.test/")  # type: ignore[arg-type]
    urls = {req.url for req in discovered}
    assert any(u.endswith("/good") for u in urls)  # reachable pages still crawled
    assert not any(u.endswith("/bad") for u in urls)  # the erroring page is skipped, no crash
