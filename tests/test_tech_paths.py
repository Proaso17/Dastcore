"""Tech-aware path discovery: fingerprint the stack, probe only its known paths, calibrated so a
catch-all can't invent endpoints, scope-gated. Offline — a fake client scripts every response."""

from __future__ import annotations

from urllib.parse import urlsplit

from dastcore.core.models import HttpResponse
from dastcore.discovery.tech_paths import detect_stacks, discover_tech_paths, paths_for_stacks


class _FakeClient:
    def __init__(self, routes: dict[str, HttpResponse], *, scope_ok=lambda _u: True) -> None:
        self.routes = routes
        self._scope_ok = scope_ok
        self.probed: list[str] = []

    def is_in_scope(self, url: str) -> bool:
        return self._scope_ok(url)

    async def get(self, url: str, *, timeout: float | None = None, retries: int | None = None, **_kw: object):
        parts = urlsplit(url)
        self.probed.append(parts.path)
        seg = parts.path.lstrip("/")
        if seg.startswith("dc") and "." not in seg and "/" not in seg:  # the random calibration baseline
            return HttpResponse(status_code=404, text="not found", url=url)
        key = parts.path + (f"?{parts.query}" if parts.query else "")
        return self.routes.get(key) or self.routes.get(parts.path) or HttpResponse(status_code=404, text="nf", url=url)


def _ok(body: str, status: int = 200) -> HttpResponse:
    return HttpResponse(status_code=status, text=body, url="http://t/")


def test_detect_stacks_by_body_cookie_and_server() -> None:
    assert "wordpress" in detect_stacks({}, set(), '<link href="/wp-content/x.css">')
    assert "spring" in detect_stacks({}, set(), "Whitelabel Error Page")
    assert "laravel" in detect_stacks({}, {"laravel_session"}, "")
    assert "tomcat" in detect_stacks({}, set(), "", server="Apache-Coyote/1.1")
    assert "nextjs" in detect_stacks({}, set(), '<script id="__NEXT_DATA__">{}</script>')
    assert detect_stacks({}, set(), "just a plain page") == set()


def test_paths_for_stacks_unions_and_dedups() -> None:
    paths = paths_for_stacks({"wordpress", "spring"})
    assert "wp-json/" in paths and "actuator" in paths
    assert len(paths) == len(set(paths))  # deduped


async def test_discovers_live_tech_paths_and_calibrates() -> None:
    routes = {
        "/": _ok('<html><link href="/wp-content/themes/x/style.css"></html>'),  # WordPress homepage
        "/wp-json/": _ok('{"name":"site","routes":{}}'),                        # live -> discovered
        "/wp-login.php": _ok("<form>log in</form>"),                            # live -> discovered
        # wp-admin/, xmlrpc.php, etc. fall through to 404 -> not discovered
    }
    client = _FakeClient(routes)
    reqs = await discover_tech_paths(client, "http://site.test/")  # type: ignore[arg-type]
    urls = {r.url for r in reqs}
    assert "http://site.test/wp-json/" in urls
    assert "http://site.test/wp-login.php" in urls
    assert "http://site.test/wp-admin/" not in urls  # 404 -> correctly not added


async def test_catch_all_does_not_invent_endpoints() -> None:
    # A WordPress-looking SPA that returns the SAME 200 body for every path must yield nothing.
    same = '<html><link href="/wp-content/app.js">the whole app is one page</link></html>'
    client = _FakeClient({}, )  # default route is 404...
    client.routes = {"__all__": _ok(same)}

    async def always_same(url: str, *, timeout=None, retries=None, **_kw):  # noqa: ANN001
        return _ok(same)

    client.get = always_same  # type: ignore[assignment,method-assign]
    reqs = await discover_tech_paths(client, "http://spa.test/")  # type: ignore[arg-type]
    assert reqs == []  # every path (incl. the random baseline) looks identical -> zero endpoints


async def test_scope_gates_tech_paths() -> None:
    routes = {
        "/": _ok('<meta name="generator" content="WordPress 6.4">'),
        "/wp-json/": _ok('{"routes":{}}'),
    }
    # scope rejects everything except the homepage and the calibration probe host — wp-json is blocked
    client = _FakeClient(routes, scope_ok=lambda u: "/wp-json" not in u)
    reqs = await discover_tech_paths(client, "http://site.test/")  # type: ignore[arg-type]
    assert all("/wp-json" not in r.url for r in reqs)
