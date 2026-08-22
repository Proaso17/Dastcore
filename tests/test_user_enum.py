"""User/account enumeration (A07): flags an auth endpoint that answers differently for accounts that
exist vs not, calibrated so a stable or noisy endpoint yields nothing. Offline — a fake auth server."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.user_enum import run_user_enumeration_checks


class _AuthServer:
    """Scriptable login: 'invalid password' for known accounts, 'user not found' otherwise.
    ``mode='stable'`` returns one message for everyone; ``mode='noisy'`` varies every response."""

    def __init__(self, existing: set[str], *, mode: str = "leaky") -> None:
        self.existing = existing
        self.mode = mode
        self._n = 0

    async def request(self, method: str, url: str, *, json=None, data=None, **_kw) -> HttpResponse:
        body = json or data or {}
        ident = str(body.get("username") or body.get("email") or "")
        if self.mode == "stable":
            return HttpResponse(status_code=401, text="invalid credentials", url=url)
        if self.mode == "noisy":
            self._n += 1
            return HttpResponse(status_code=401, text="error " + "x" * (self._n * 40), url=url)
        if ident in self.existing:
            return HttpResponse(status_code=401, text="invalid password for this account", url=url)
        return HttpResponse(status_code=404, text="that user does not exist", url=url)


def _login(path: str = "/login") -> HttpRequest:
    return HttpRequest(method="POST", url=f"http://t.test{path}", json_body={"username": "x", "password": "y"})


async def test_flags_a_leaky_login() -> None:
    findings = await run_user_enumeration_checks(_AuthServer({"admin"}), [_login()])  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].rule_id == "user-enumeration"
    assert findings[0].owasp == "WSTG-IDNT-04"


async def test_stable_endpoint_is_not_flagged() -> None:
    findings = await run_user_enumeration_checks(_AuthServer({"admin"}, mode="stable"), [_login()])  # type: ignore[arg-type]
    assert findings == []


async def test_noisy_endpoint_is_not_flagged() -> None:
    # randoms disagree among themselves -> we can't attribute a diff to the identity -> bail (zero-FP)
    findings = await run_user_enumeration_checks(_AuthServer({"admin"}, mode="noisy"), [_login()])  # type: ignore[arg-type]
    assert findings == []


async def test_non_auth_paths_are_ignored() -> None:
    req = HttpRequest(method="POST", url="http://t.test/api/orders", json_body={"item": "1"})
    findings = await run_user_enumeration_checks(_AuthServer({"admin"}), [req])  # type: ignore[arg-type]
    assert findings == []


async def test_email_field_uses_email_identities() -> None:
    reset = HttpRequest(method="POST", url="http://t.test/password/reset", json_body={"email": "a@t.test"})
    # server 'exists' set keyed by the email the detector will try (admin@t.test)
    findings = await run_user_enumeration_checks(_AuthServer({"admin@t.test"}), [reset])  # type: ignore[arg-type]
    assert len(findings) == 1 and findings[0].injection_point.name == "email"
