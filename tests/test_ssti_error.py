"""Error-based blind SSTI: a polyglot that triggers a reproducible template-engine error (absent for a
benign value) is flagged; a server that errors generically, or not at all, is not. Offline fake server."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.ssti_error import _POLYGLOT, run_ssti_error_checks


class _Server:
    """`mode`: 'jinja' errors with a Jinja2 signature on the polyglot; 'generic' returns a plain 500 on
    any odd input; 'safe' echoes everything with no error."""

    def __init__(self, mode: str) -> None:
        self.mode = mode

    async def request(self, method: str, url: str, *, params=None, json=None, data=None, **_kw) -> HttpResponse:
        value = ""
        for src in (params, json, data):
            if src:
                value = str(next(iter(src.values())))
                break
        if self.mode == "jinja" and _POLYGLOT in value:
            return HttpResponse(status_code=500, text="jinja2.exceptions.TemplateSyntaxError: unexpected char", url=url)
        if self.mode == "generic":
            # a plain 500 with no engine-specific signature (must NOT be flagged)
            return HttpResponse(status_code=500, text="Internal Server Error", url=url)
        return HttpResponse(status_code=200, text=f"you said {value}", url=url)


def _reqs() -> list[HttpRequest]:
    return [HttpRequest(method="GET", url="http://t.test/greet", params={"name": "x"})]


async def test_flags_error_based_ssti() -> None:
    findings = await run_ssti_error_checks(_Server("jinja"), _reqs())  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].rule_id == "ssti-error-based" and findings[0].severity == "high"
    assert "jinja2" in findings[0].evidence[0].data.lower()


async def test_generic_500_is_not_flagged() -> None:
    # a generic error with no template-engine signature is never SSTI -> zero-FP
    assert await run_ssti_error_checks(_Server("generic"), _reqs()) == []  # type: ignore[arg-type]


async def test_safe_endpoint_is_not_flagged() -> None:
    assert await run_ssti_error_checks(_Server("safe"), _reqs()) == []  # type: ignore[arg-type]
