"""Discovery v2: robots.txt/sitemap parsing and JS sourcemap harvesting."""

from __future__ import annotations

import json
from types import SimpleNamespace

from dastcore.discovery.js_endpoints import extract_from_sourcemap, harvest_sourcemaps
from dastcore.discovery.recon_paths import ReconPathDiscoverer, parse_robots, parse_sitemap


class _FakeClient:
    """Serves canned bodies by URL suffix; everything in scope, no network."""

    def __init__(self, routes):
        self.routes = routes  # url-suffix -> (status, text)

    def is_in_scope(self, url: str) -> bool:
        return True

    async def get(self, url: str, timeout: float = 6.0, retries: int = 0):
        for suffix, (status, text) in self.routes.items():
            if url.endswith(suffix):
                return SimpleNamespace(status_code=status, text=text)
        return SimpleNamespace(status_code=404, text="")


def test_parse_robots_extracts_paths_and_sitemaps() -> None:
    body = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Allow: /public/\n"
        "Disallow: /*.json$\n"  # a glob pattern — must be skipped, it's not a real path
        "Disallow:\n"  # empty — ignored
        "Sitemap: https://x.test/sitemap.xml\n"
    )
    paths, sitemaps = parse_robots(body)
    assert paths == {"/admin/", "/public/"}
    assert sitemaps == {"https://x.test/sitemap.xml"}


def test_parse_sitemap_extracts_locs() -> None:
    xml = "<urlset><url><loc>https://x.test/a</loc></url><url><loc> https://x.test/b </loc></url></urlset>"
    assert parse_sitemap(xml) == {"https://x.test/a", "https://x.test/b"}


async def test_recon_discovers_robots_and_sitemap_paths() -> None:
    routes = {
        "/robots.txt": (
            200,
            "User-agent: *\nDisallow: /admin/\nDisallow: /exports/report.csv\nSitemap: https://x.test/sitemap.xml\n",
        ),
        "/sitemap.xml": (200, "<urlset><url><loc>https://x.test/hidden/page</loc></url></urlset>"),
    }
    reqs = await ReconPathDiscoverer(_FakeClient(routes)).discover("https://x.test")
    urls = {r.url for r in reqs}
    assert any(u.endswith("/admin/") for u in urls)
    assert any("exports/report.csv" in u for u in urls)
    assert any("hidden/page" in u for u in urls)


async def test_recon_follows_sitemap_index() -> None:
    routes = {
        "/robots.txt": (404, ""),
        "/sitemap.xml": (200, "<sitemapindex><sitemap><loc>https://x.test/sitemap-1.xml</loc></sitemap></sitemapindex>"),
        "/sitemap-1.xml": (200, "<urlset><url><loc>https://x.test/deep/route</loc></url></urlset>"),
    }
    reqs = await ReconPathDiscoverer(_FakeClient(routes)).discover("https://x.test")
    assert any("deep/route" in r.url for r in reqs)


def test_extract_from_sourcemap_mines_original_source() -> None:
    smap = json.dumps({"sourcesContent": ['fetch("/api/v1/secret"); const u = "/admin/users";']})
    endpoints = extract_from_sourcemap(smap)
    assert "/api/v1/secret" in endpoints


async def test_harvest_sourcemaps_builds_scoped_requests() -> None:
    smap = json.dumps({"sourcesContent": ['fetch("/api/hidden")']})
    client = _FakeClient({"/app.js.map": (200, smap)})
    reqs = await harvest_sourcemaps(client, "https://x.test/", ["https://x.test/app.js"])
    assert any("/api/hidden" in r.url for r in reqs)
