"""probe_sensitive_files must calibrate against a catch-all host, so a SPA that serves its
index.html (with a 'password' field) for every path doesn't false-positive as an exposed config
backup — the real bug the getnyma n8n host exposed."""

from __future__ import annotations

from urllib.parse import urlsplit

from dastcore.core.models import HttpResponse
from dastcore.detectors.active_checks import probe_sensitive_files


class _CatchAll:
    """A SPA that answers 200 with the same login page (containing 'password') for every path."""

    def is_in_scope(self, url: str) -> bool:
        return True

    async def get(self, url: str, **_kwargs: object) -> HttpResponse:
        body = '<html><body><form><input name="password" type="password"></form></body></html>' * 40
        return HttpResponse(status_code=200, text=body, url=url)


class _RealLeak:
    """A normal server: 404 for unknown paths, but a genuinely exposed /.env."""

    def is_in_scope(self, url: str) -> bool:
        return True

    async def get(self, url: str, **_kwargs: object) -> HttpResponse:
        if urlsplit(url).path == "/.env":
            return HttpResponse(status_code=200, text="SECRET_KEY=abc123\nDB_PASSWORD=hunter2\n", url=url)
        return HttpResponse(status_code=404, text="Not Found", url=url)


async def test_catch_all_host_is_not_a_false_positive() -> None:
    findings = await probe_sensitive_files(_CatchAll(), "https://n8n.test/")  # type: ignore[arg-type]
    assert findings == []  # the 'password' match on the SPA index is not a config-backup leak


async def test_genuinely_exposed_file_is_still_reported() -> None:
    findings = await probe_sensitive_files(_RealLeak(), "https://real.test/")  # type: ignore[arg-type]
    assert any(f.name == "Exposed .env file" for f in findings)  # a real leak (404 baseline) still fires
