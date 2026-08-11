"""Source-map exposure (Module 14). Fires only when a served JS file references a map
that is actually reachable AND parses as a Source Map v3 — never on a stray comment,
an inline (data:) map, or a 404/non-map response."""

from __future__ import annotations

import json

import pytest

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.exposure import _is_source_map, check_source_map

_MAP = json.dumps({"version": 3, "sources": ["app.ts", "util.ts"], "mappings": "AAAA"})


def _js(url: str, body: str, ctype: str = "application/javascript") -> tuple[HttpRequest, HttpResponse]:
    req = HttpRequest(method="GET", url=url)
    resp = HttpResponse(status_code=200, headers={"Content-Type": ctype}, text=body, url=url)
    return req, resp


class _MapClient:
    """Serves a fixed body/status for the .map URL and records the fetch."""

    def __init__(self, body: str = _MAP, status: int = 200) -> None:
        self._body, self._status = body, status
        self.fetched: list[str] = []

    async def get(self, url: str) -> HttpResponse:
        self.fetched.append(url)
        return HttpResponse(status_code=self._status, text=self._body, url=url)


def test_is_source_map_accepts_v3_and_rejects_junk() -> None:
    assert _is_source_map(_MAP) is True
    assert _is_source_map('{"just": "json"}') is False
    assert _is_source_map("not json at all") is False


@pytest.mark.asyncio
async def test_reachable_source_map_is_reported() -> None:
    req, resp = _js("https://app.test/static/app.js", "console.log(1)\n//# sourceMappingURL=app.js.map")
    client = _MapClient()
    findings = await check_source_map(client, req, resp)
    assert client.fetched == ["https://app.test/static/app.js.map"]
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "source-map-exposure" and f.severity == "medium"
    assert "2 original source file" in f.evidence[0].data


@pytest.mark.asyncio
async def test_no_reference_no_finding() -> None:
    req, resp = _js("https://app.test/app.js", "console.log('no map here')")
    assert await check_source_map(_MapClient(), req, resp) == []


@pytest.mark.asyncio
async def test_inline_data_map_is_ignored() -> None:
    req, resp = _js("https://app.test/app.js", "x=1\n//# sourceMappingURL=data:application/json;base64,eyJ2IjozfQ==")
    client = _MapClient()
    assert await check_source_map(client, req, resp) == []
    assert client.fetched == []  # never fetched an inline map


@pytest.mark.asyncio
async def test_missing_map_is_not_reported() -> None:
    req, resp = _js("https://app.test/app.js", "x=1\n//# sourceMappingURL=app.js.map")
    assert await check_source_map(_MapClient(status=404), req, resp) == []


@pytest.mark.asyncio
async def test_map_url_that_is_not_a_source_map_is_not_reported() -> None:
    req, resp = _js("https://app.test/app.js", "x=1\n//# sourceMappingURL=app.js.map")
    assert await check_source_map(_MapClient(body='{"error":"not found"}'), req, resp) == []


@pytest.mark.asyncio
async def test_non_javascript_response_is_ignored() -> None:
    req = HttpRequest(method="GET", url="https://app.test/page")
    resp = HttpResponse(status_code=200, headers={"Content-Type": "text/html"}, text="//# sourceMappingURL=x.map")
    assert await check_source_map(_MapClient(), req, resp) == []


@pytest.mark.asyncio
async def test_scanner_reports_source_map_during_a_scan() -> None:
    # End-to-end wiring: the scanner's per-request active checks fetch and confirm the map.
    from dastcore.engine.scanner import Scanner

    class _ScannerClient:
        async def request(self, method, url, **kwargs) -> HttpResponse:
            return HttpResponse(
                status_code=200,
                headers={"Content-Type": "application/javascript"},
                text="console.log(1)\n//# sourceMappingURL=app.js.map",
                url=url,
            )

        async def get(self, url: str) -> HttpResponse:
            return HttpResponse(status_code=200, text=_MAP, url=url)

    scanner = Scanner(_ScannerClient(), rules=[], active_checks=True)
    findings = await scanner.scan_request(HttpRequest(method="GET", url="https://app.test/static/app.js"))
    assert any(f.rule_id == "source-map-exposure" for f in findings)
