"""Web cache deception: an auth-gated page served via a .css path-confusion URL that a cache then
returns to an anonymous client is flagged; a non-cached or non-auth-gated page is not. Offline."""

from __future__ import annotations

from urllib.parse import urlsplit

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.cache_deception import run_cache_deception_checks

_AUTH = "<html>Welcome Miguel — balance 4321€ — account #99 " + "x" * 200 + "</html>"
_ANON = "<html>Please log in " + "y" * 200 + "</html>"


class _Cache:
    """Shared cache keyed by URL. A vulnerable CDN caches the authenticated .css response."""

    def __init__(self, *, vulnerable: bool) -> None:
        self.store: dict[str, str] = {}
        self.vulnerable = vulnerable


class _Client:
    """auth=True carries a session (sees _AUTH); anon sees _ANON — unless the cache serves an entry."""

    def __init__(self, cache: _Cache, *, authed: bool) -> None:
        self.cache = cache
        self.authed = authed

    async def get(self, url: str, *, timeout=None, retries=None, **_kw) -> HttpResponse:
        path = urlsplit(url).path
        is_trick = "/dc" in path and path.endswith((".css", ".js"))  # the path-confusion URL
        if is_trick and url in self.cache.store:  # a cache HIT serves whatever was stored
            return HttpResponse(status_code=200, text=self.cache.store[url], url=url)
        body = _AUTH if self.authed else _ANON  # app ignores the extra .css segment -> serves the page
        if is_trick and self.authed and self.cache.vulnerable:
            self.cache.store[url] = body  # authenticated response gets cached under the .css URL
        return HttpResponse(status_code=200, text=body, url=url)


def _reqs() -> list[HttpRequest]:
    return [HttpRequest(method="GET", url="https://app.test/account")]


async def test_flags_cache_deception_when_authed_page_is_served_anonymously() -> None:
    cache = _Cache(vulnerable=True)
    auth, anon = _Client(cache, authed=True), _Client(cache, authed=False)
    findings = await run_cache_deception_checks(auth, anon, _reqs())  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].rule_id == "web-cache-deception" and findings[0].severity == "high"


async def test_not_flagged_when_cache_does_not_store_it() -> None:
    cache = _Cache(vulnerable=False)  # nothing gets cached -> anon sees the login page
    auth, anon = _Client(cache, authed=True), _Client(cache, authed=False)
    assert await run_cache_deception_checks(auth, anon, _reqs()) == []  # type: ignore[arg-type]


async def test_not_flagged_when_page_is_not_auth_gated() -> None:
    class _Public:
        async def get(self, url, *, timeout=None, retries=None, **_kw):
            return HttpResponse(status_code=200, text="same public page for everyone " + "z" * 200, url=url)

    # auth and anon see identical content -> not an authenticated page -> nothing to leak
    assert await run_cache_deception_checks(_Public(), _Public(), _reqs()) == []  # type: ignore[arg-type]
