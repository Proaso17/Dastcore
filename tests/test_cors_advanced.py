"""Advanced CORS: null-origin and prefix/suffix/substring allowlist bypasses (attacker-controllable
origins reflected). A restrictive endpoint that reflects only its real origin is not flagged. Offline."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.active_checks import check_cors_reflection

_ARB = "https://dastcore-cors-probe.evil"


class _CorsServer:
    """Reflects an Origin into ACAO iff ``accept(origin)`` is true; always sets Vary: Origin (CORS-aware)."""

    def __init__(self, accept, *, creds: bool = True) -> None:
        self._accept = accept
        self._creds = creds

    async def request(self, method: str, url: str, *, headers=None, **_kw) -> HttpResponse:
        origin = (headers or {}).get("Origin", "")
        h = {"Vary": "Origin"}
        if origin and self._accept(origin):
            h["Access-Control-Allow-Origin"] = origin
            if self._creds:
                h["Access-Control-Allow-Credentials"] = "true"
        return HttpResponse(status_code=200, headers=h, text="ok", url=url)


def _req() -> HttpRequest:
    return HttpRequest(method="GET", url="https://staging-panel.getnyma.com/api/data")


async def test_null_origin_trusted_is_flagged() -> None:
    server = _CorsServer(lambda o: o == "null")  # trusts null (not the arbitrary evil probe)
    findings = await check_cors_reflection(server, _req())  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].rule_id == "active-cors-origin-bypass" and findings[0].severity == "high"
    assert "null" in findings[0].evidence[0].data


async def test_suffix_bypass_is_flagged() -> None:
    # naive endsWith check: any origin ending in the registrable domain is accepted
    server = _CorsServer(lambda o: o.endswith("getnyma.com"), creds=False)
    findings = await check_cors_reflection(server, _req())  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].rule_id == "active-cors-origin-bypass"
    assert findings[0].severity == "medium"  # no credentials -> medium


async def test_arbitrary_reflection_keeps_original_rule() -> None:
    server = _CorsServer(lambda o: True)  # reflects anything (fully open)
    findings = await check_cors_reflection(server, _req())  # type: ignore[arg-type]
    assert len(findings) == 1 and findings[0].rule_id == "active-cors-reflected-origin"


async def test_strict_endpoint_not_flagged() -> None:
    # reflects only its own real origin -> not attacker-controllable -> nothing to report
    server = _CorsServer(lambda o: o == "https://staging-panel.getnyma.com")
    assert await check_cors_reflection(server, _req()) == []  # type: ignore[arg-type]


async def test_non_cors_endpoint_costs_nothing_extra() -> None:
    class _NoCors:
        async def request(self, method, url, *, headers=None, **_kw):
            return HttpResponse(status_code=200, text="ok", url=url)  # no CORS headers at all

    assert await check_cors_reflection(_NoCors(), _req()) == []  # type: ignore[arg-type]
