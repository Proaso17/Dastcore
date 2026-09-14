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
from dastcore.detectors.authz import Identity, run_authz_checks, run_bola_enumeration_checks

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


async def test_bfla_detected_on_privileged_action_verb(vuln_app_url: str) -> None:
    """A privileged action named by its verb (/api/users/<id>/promote), not under /admin, reached by
    a normal user -> BFLA. Exercises the privileged-action recognizer beyond the /admin path."""
    probes = [HttpRequest(method="POST", url=f"{vuln_app_url}/api/users/5/promote")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice", "admin"])
        unauth = await stack.enter_async_context(HttpClient(_SCOPE))
        findings = await run_authz_checks(identities, probes, unauth_client=unauth)

    bfla = [f for f in findings if f.rule_id == "authz-bfla"]
    assert len(bfla) == 1
    assert "alice" in bfla[0].evidence[0].data


async def test_no_bfla_on_ordinary_user_write(vuln_app_url: str) -> None:
    """DELETE /api/cart/<id> is a normal user action (no privileged name/verb), so a user succeeding
    must not be flagged — guards against over-broad verb matching."""
    probes = [HttpRequest(method="DELETE", url=f"{vuln_app_url}/api/cart/9")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice", "admin"])
        unauth = await stack.enter_async_context(HttpClient(_SCOPE))
        findings = await run_authz_checks(identities, probes, unauth_client=unauth)

    assert not any(f.rule_id == "authz-bfla" for f in findings)


async def test_bfla_differential_privilege_inversion(vuln_app_url: str) -> None:
    """/api/legacy/export forbids admins (403) but serves normal users (200). A junior doing what a
    senior cannot is BFLA by monotonicity — no path/name heuristic involved."""
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/api/legacy/export")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice", "admin"])
        unauth = await stack.enter_async_context(HttpClient(_SCOPE))
        findings = await run_authz_checks(identities, probes, unauth_client=unauth)

    bfla = [f for f in findings if f.rule_id == "authz-bfla"]
    assert len(bfla) == 1
    assert "inversion" in bfla[0].evidence[0].data.lower()
    assert bfla[0].evidence[0].type == "differential"


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


# --- Active IDOR by id enumeration --------------------------------------------------------------


async def test_idor_enumeration_detects_cross_owner_pii_leak(vuln_app_url: str) -> None:
    """alice's single session walks /api/invoices/<id> and reads invoices of *two* owners, each with
    an email (strong PII), on an endpoint that denies unauthenticated access -> confirmed IDOR."""
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/api/invoices/501")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice"])
        unauth = await stack.enter_async_context(HttpClient(_SCOPE))
        findings = await run_bola_enumeration_checks(identities, probes, unauth_client=unauth)

    enum = [f for f in findings if f.rule_id == "authz-idor-enum"]
    assert len(enum) == 1
    assert enum[0].severity == "high" and enum[0].cwe == "CWE-639"
    assert "alice" in enum[0].evidence[0].data
    assert enum[0].impact is not None


async def test_no_idor_enum_on_members_forum_without_pii(vuln_app_url: str) -> None:
    """/api/posts/<id> is a members-only forum: any user may read any post, and posts carry an author
    user_id but no per-user PII. The strong-PII gate must keep enumeration from firing."""
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/api/posts/601")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice"])
        unauth = await stack.enter_async_context(HttpClient(_SCOPE))
        findings = await run_bola_enumeration_checks(identities, probes, unauth_client=unauth)

    assert not any(f.rule_id == "authz-idor-enum" for f in findings)


async def test_no_idor_enum_on_public_catalog(vuln_app_url: str) -> None:
    """/api/products/<id> has no owner/PII markers, so enumeration finds nothing to leak."""
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/api/products/1")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice"])
        unauth = await stack.enter_async_context(HttpClient(_SCOPE))
        findings = await run_bola_enumeration_checks(identities, probes, unauth_client=unauth)

    assert not any(f.rule_id == "authz-idor-enum" for f in findings)


async def test_no_idor_enum_without_privacy_oracle(vuln_app_url: str) -> None:
    """Without an unauth client we can't prove the endpoint is access-controlled -> never fires."""
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/api/invoices/501")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["alice"])
        findings = await run_bola_enumeration_checks(identities, probes)

    assert findings == []


async def test_idor_enum_skips_privileged_identity(vuln_app_url: str) -> None:
    """An admin legitimately reads many owners' records, so enumeration must not flag an admin session."""
    probes = [HttpRequest(method="GET", url=f"{vuln_app_url}/api/invoices/501")]
    async with AsyncExitStack() as stack:
        identities = await _identities(stack, ["admin"])
        unauth = await stack.enter_async_context(HttpClient(_SCOPE))
        findings = await run_bola_enumeration_checks(identities, probes, unauth_client=unauth)

    assert not any(f.rule_id == "authz-idor-enum" for f in findings)


def test_enumerable_points_and_id_mutation() -> None:
    from dastcore.detectors.authz import _enumerable_points, _with_id

    req = HttpRequest(method="GET", url="https://x.test/api/2/orders/101")
    points = _enumerable_points(req)
    # both "2" (index 2) and "101" (index 4) are integers; the last is the object id
    assert ("path", 2, 2) in points
    assert points[-1] == ("path", 4, 101)
    mutated = _with_id(req, points[-1], 102)
    assert mutated.url == "https://x.test/api/2/orders/102"

    req_param = HttpRequest(method="GET", url="https://x.test/api/order", params={"order_id": "7"})
    pts = _enumerable_points(req_param)
    assert pts[-1] == ("param", "order_id", 7)
    assert _with_id(req_param, pts[-1], 8).params["order_id"] == "8"

    # a long digit run (epoch/code/phone) is not an enumerable object id
    assert _enumerable_points(HttpRequest(method="GET", url="https://x.test/t/1700000000000")) == []
