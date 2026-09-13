"""Phase 7: authorization detectors (BOLA/IDOR, BFLA, missing authentication).

Uses three identities backed by static session cookies against the local target:
alice & bob (role user) and admin (role admin).
"""

from __future__ import annotations

from contextlib import AsyncExitStack

from dastcore.config import AuthConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.core.session import SessionManager
from dastcore.detectors.authz import Identity, run_authz_checks

_SCOPE = ScopeConfig(allow_domains=["127.0.0.1"])

_COOKIES = {
    "alice": {"session_user_id": "1", "session_role": "user"},
    "bob": {"session_user_id": "2", "session_role": "user"},
    "admin": {"session_user_id": "99", "session_role": "admin"},
}
_ROLES = {"alice": "user", "bob": "user", "admin": "admin"}


async def _identities(stack: AsyncExitStack, names: list[str]) -> list[Identity]:
    identities = []
    for name in names:
        session = SessionManager(AuthConfig(type="cookie", cookies=_COOKIES[name]))
        client = await stack.enter_async_context(HttpClient(_SCOPE, session=session))
        identities.append(Identity(name=name, role=_ROLES[name], client=client))
    return identities


async def test_bola_detected_when_users_share_objects(vuln_app_url: str) -> None:
    probes = [
        HttpRequest(method="GET", url=f"{vuln_app_url}/api/orders/101"),
        HttpRequest(method="GET", url=f"{vuln_app_url}/api/orders/102"),
    ]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice", "bob"])
        findings = await run_authz_checks(identities, probes)

    bola = [f for f in findings if f.rule_id == "authz-bola"]
    assert len(bola) == 2  # both orders are readable by both users
    assert bola[0].severity == "high"
    assert "alice" in bola[0].evidence[0].data and "bob" in bola[0].evidence[0].data
    # proof of impact: the actual cross-account object, redacted, is attached
    assert bola[0].impact is not None
    assert "otra cuenta" in bola[0].impact and "owner_id" in bola[0].impact


def test_bola_impact_redacts_pii() -> None:
    from dastcore.core.models import HttpResponse
    from dastcore.detectors.authz import _bola_impact, _redact

    assert "jane@example.com" not in _redact('{"email":"jane@example.com","ssn":"123456789"}')
    assert "123456789" not in _redact('{"ssn":"123456789"}')  # long digit runs masked
    impact = _bola_impact(HttpResponse(status_code=200, text='{"owner_id":7,"email":"bob@corp.com"}'), "owner_id")
    assert "otra cuenta" in impact and "owner_id" in impact and "bob@corp.com" not in impact


async def test_bfla_detected_when_user_hits_admin_function(vuln_app_url: str) -> None:
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/admin/stats")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice", "admin"])
        findings = await run_authz_checks(identities, probes)

    bfla = [f for f in findings if f.rule_id == "authz-bfla"]
    assert len(bfla) == 1
    assert "alice" in bfla[0].evidence[0].data


async def test_no_bfla_on_properly_secured_admin_endpoint(vuln_app_url: str) -> None:
    """/admin/delete enforces the admin role, so a normal user gets 403 -> no BFLA."""
    probes = [HttpRequest(method="POST", url=f"{vuln_app_url}/admin/delete")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice", "admin"])
        findings = await run_authz_checks(identities, probes)

    assert not any(f.rule_id == "authz-bfla" for f in findings)


async def test_missing_authentication_on_sensitive_endpoint(vuln_app_url: str) -> None:
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/api/internal/config")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice"])
        unauth = await stack.enter_async_context(HttpClient(_SCOPE))
        findings = await run_authz_checks(identities, probes, unauth_client=unauth)

    missing = [f for f in findings if f.rule_id == "authz-missing-auth"]
    assert len(missing) == 1
    assert missing[0].cwe == "CWE-306"


async def test_no_missing_auth_on_protected_object_endpoint(vuln_app_url: str) -> None:
    """/api/orders/101 requires a session cookie, so unauth gets 401 -> not flagged."""
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/api/orders/101")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice"])
        unauth = await stack.enter_async_context(HttpClient(_SCOPE))
        findings = await run_authz_checks(identities, probes, unauth_client=unauth)

    assert not any(f.rule_id == "authz-missing-auth" for f in findings)


async def test_unauthenticated_sensitive_endpoint_is_not_double_reported_as_bfla(vuln_app_url: str) -> None:
    """/api/internal/config needs no auth: report missing-auth, not also BFLA (low noise)."""
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/api/internal/config")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice"])
        unauth = await stack.enter_async_context(HttpClient(_SCOPE))
        findings = await run_authz_checks(identities, probes, unauth_client=unauth)

    rule_ids = [f.rule_id for f in findings]
    assert "authz-missing-auth" in rule_ids
    assert "authz-bfla" not in rule_ids


async def test_no_bola_when_only_one_identity_has_access(vuln_app_url: str) -> None:
    """A single identity cannot demonstrate cross-account access."""
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/api/orders/101")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice"])
        findings = await run_authz_checks(identities, probes)

    assert not any(f.rule_id == "authz-bola" for f in findings)


async def test_no_bola_on_shared_public_object(vuln_app_url: str) -> None:
    """A public product is identical for every user but has no ownership markers -> not BOLA."""
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/api/products/1")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice", "bob"])
        findings = await run_authz_checks(identities, probes)

    assert not any(f.rule_id == "authz-bola" for f in findings)


def test_ownership_marker_distinguishes_owned_from_public() -> None:
    from dastcore.detectors.authz import _ownership_marker

    assert _ownership_marker('{"id":1,"owner_id":7,"item":"Laptop"}') == "owner_id"
    assert _ownership_marker('{"name":"jane","email":"jane@example.com"}') is not None
    assert _ownership_marker('{"id":1,"name":"Laptop","price":999.99}') is None  # public product


async def test_bola_via_owner_signature_across_session_chrome(vuln_app_url: str) -> None:
    """/api/invoices/501 wraps the owned record in a per-session CSRF token, so alice's and bob's
    bodies differ. The identical-body path can't see it; matching the owned record (owner_id/email)
    across sessions plus the unauth-401 privacy proof confirms the cross-account read."""
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/api/invoices/501")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice", "bob"])
        unauth = await stack.enter_async_context(HttpClient(_SCOPE))
        findings = await run_authz_checks(identities, probes, unauth_client=unauth)

    bola = [f for f in findings if f.rule_id == "authz-bola"]
    assert len(bola) == 1
    assert bola[0].severity == "high"
    assert "alice" in bola[0].evidence[0].data and "bob" in bola[0].evidence[0].data
    # confirmed via the owner-signature/privacy-proof path, not identical bodies
    assert "access-controlled" in bola[0].evidence[0].data
    assert bola[0].impact is not None


async def test_no_bola_on_public_object_even_when_access_controlled(vuln_app_url: str) -> None:
    """/api/products/1 requires a session (unauth 401 = access-controlled) but carries no owner
    signature. The privacy proof alone must not fire BOLA on a genuinely public catalog object."""
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/api/products/1")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice", "bob"])
        unauth = await stack.enter_async_context(HttpClient(_SCOPE))
        findings = await run_authz_checks(identities, probes, unauth_client=unauth)

    assert not any(f.rule_id == "authz-bola" for f in findings)


def test_owner_record_signature_requires_a_real_identifier() -> None:
    from dastcore.detectors.authz import _owner_record_signature

    assert _owner_record_signature('{"csrf":"ab","invoice":{"owner_id": 1}}') == "owner_id=1"
    uuid = "7f3a1b2c-0000-1111-2222-333344445555"
    assert _owner_record_signature(f'{{"user_id":"{uuid}"}}') == f"user_id={uuid}"
    assert _owner_record_signature('{"account":"free","tier":"public"}') is None  # label, not an id
    assert _owner_record_signature('{"contact":"jane@example.com"}') == "email=jane@example.com"
