"""HTTP TRACE / Cross-Site Tracing (XST) active check."""

from __future__ import annotations

from dastcore.core.models import HttpResponse
from dastcore.detectors.active_checks import check_trace_method


class _TraceClient:
    """Echoes the request when TRACE is honoured (a vulnerable server)."""

    def __init__(self, *, echo: bool) -> None:
        self._echo = echo

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        if method == "TRACE" and self._echo:
            headers = kwargs.get("headers") or {}
            body = "TRACE / HTTP/1.1\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
            return HttpResponse(status_code=200, text=body, url=url)
        return HttpResponse(status_code=405, text="Method Not Allowed", url=url)


async def test_xst_detected_when_trace_is_echoed() -> None:
    findings = await check_trace_method(_TraceClient(echo=True), "http://target/")
    assert len(findings) == 1
    assert findings[0].rule_id == "active-trace-method"
    assert findings[0].family == "xst"
    assert findings[0].severity == "low"


async def test_no_finding_when_trace_is_disabled() -> None:
    assert await check_trace_method(_TraceClient(echo=False), "http://target/") == []
