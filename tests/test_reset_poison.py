"""Password reset poisoning (A07): a reset endpoint that reflects an injected host header (builds the
reset link from it) is flagged; one that ignores it, or a non-reset path, is not. Offline fake server."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.reset_poison import run_reset_poisoning_checks


class _ResetServer:
    """`trusts` = the host header the app builds the reset link from (reflected). None = safe."""

    def __init__(self, trusts: str | None) -> None:
        self.trusts = trusts

    async def request(self, method: str, url: str, *, headers=None, **_kw) -> HttpResponse:
        headers = headers or {}
        if self.trusts and self.trusts in headers:
            host = headers[self.trusts].removeprefix("host=")
            return HttpResponse(status_code=200, text=f'{{"message":"reset link sent: https://{host}/reset?token=abc"}}', url=url)
        return HttpResponse(status_code=200, text='{"message":"if the account exists, a reset link was sent"}', url=url)


def _reset(path: str = "/api/auth/forgot-password") -> HttpRequest:
    return HttpRequest(method="POST", url=f"http://t.test{path}", json_body={"email": "a@t.test"})


async def test_flags_xforwardedhost_poisoning() -> None:
    findings = await run_reset_poisoning_checks(_ResetServer("X-Forwarded-Host"), [_reset()])  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].rule_id == "password-reset-poisoning"
    assert findings[0].injection_point.name == "X-Forwarded-Host"


async def test_flags_forwarded_header_poisoning() -> None:
    findings = await run_reset_poisoning_checks(_ResetServer("Forwarded"), [_reset("/password/reset")])  # type: ignore[arg-type]
    assert len(findings) == 1 and findings[0].injection_point.name == "Forwarded"


async def test_safe_reset_endpoint_is_not_flagged() -> None:
    findings = await run_reset_poisoning_checks(_ResetServer(None), [_reset()])  # type: ignore[arg-type]
    assert findings == []


async def test_non_reset_path_is_ignored() -> None:
    req = HttpRequest(method="POST", url="http://t.test/api/orders", json_body={"item": "1"})
    findings = await run_reset_poisoning_checks(_ResetServer("X-Forwarded-Host"), [req])  # type: ignore[arg-type]
    assert findings == []
