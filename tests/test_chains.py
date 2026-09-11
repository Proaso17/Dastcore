"""Attack-path chaining: independent confirmed findings combine into exploit chains, and a chain
never forms unless all its legs are present (and never from suppressed findings)."""

from __future__ import annotations

from dastcore.analysis import correlate_chains
from dastcore.core.models import Finding, HttpRequest, HttpResponse, InjectionPoint


def _finding(
    rule_id: str, family: str = "", severity: str = "high", *, path: str = "/", suppressed: bool = False
) -> Finding:
    req = HttpRequest(method="GET", url=f"http://t{path}", params={"x": "1"})
    point = InjectionPoint(location="query", name="x", base_value="1", request_template=req)
    return Finding(
        id=f"{rule_id}:{path}",
        rule_id=rule_id,
        name=rule_id,
        severity=severity,  # type: ignore[arg-type]
        cwe="CWE-0",
        owasp="x",
        injection_point=point,
        request=req,
        response=HttpResponse(status_code=200),
        remediation="x",
        family=family,
        suppressed=suppressed,
    )


def test_open_redirect_plus_oauth_forms_account_takeover() -> None:
    chains = correlate_chains([_finding("open-redirect"), _finding("oauth-redirect-uri-validation")])
    assert len(chains) == 1
    chain = chains[0]
    assert chain.id == "account-takeover-oauth" and chain.severity == "critical"
    assert {leg.rule_id for leg in chain.legs} == {"open-redirect", "oauth-redirect-uri-validation"}


def test_xss_plus_insecure_cookie_forms_session_hijack() -> None:
    chains = correlate_chains([_finding("xss-reflected", family="xss"), _finding("passive-insecure-cookie")])
    ids = {c.id for c in chains}
    assert "session-hijack-xss-cookie" in ids
    hijack = next(c for c in chains if c.id == "session-hijack-xss-cookie")
    assert any(leg.role.startswith("Ejecución de JavaScript") for leg in hijack.legs)


def test_single_leg_present_forms_no_chain() -> None:
    # Open redirect alone is not account takeover — the OAuth leg is missing.
    assert correlate_chains([_finding("open-redirect")]) == []


def test_user_enum_plus_idor_forms_pii_harvest() -> None:
    chains = correlate_chains([_finding("user-enumeration"), _finding("authz-bola", family="authz")])
    harvest = next(c for c in chains if c.id == "idor-pii-harvest")
    assert harvest.severity == "critical"
    assert {leg.rule_id for leg in harvest.legs} == {"user-enumeration", "authz-bola"}


def test_reset_poisoning_plus_enum_forms_mass_ato() -> None:
    chains = correlate_chains([_finding("password-reset-poisoning"), _finding("user-enumeration")])
    assert any(c.id == "account-takeover-reset-enum" and c.severity == "critical" for c in chains)


def test_user_enum_alone_forms_no_pii_harvest_chain() -> None:
    # Enumeration on its own is not the harvest chain — the IDOR/BOLA leg must also be present.
    assert not any(c.id == "idor-pii-harvest" for c in correlate_chains([_finding("user-enumeration")]))


def test_authz_plus_forgeable_token_forms_privilege_escalation() -> None:
    chains = correlate_chains([_finding("authz-bola", severity="high"), _finding("jwt-alg-none", severity="high")])
    assert any(c.id == "privilege-escalation-authz-token" and c.severity == "critical" for c in chains)


def test_suppressed_finding_cannot_complete_a_chain() -> None:
    # The OAuth leg is triaged away → the chain must not form.
    findings = [_finding("open-redirect"), _finding("oauth-redirect-uri-validation", suppressed=True)]
    assert correlate_chains(findings) == []


def test_chains_are_sorted_most_severe_first() -> None:
    findings = [
        _finding("path-traversal-lfi", family="lfi"),
        _finding("secret-exposure"),  # -> lfi-to-secrets (high)
        _finding("open-redirect"),
        _finding("oauth-redirect-uri-validation"),  # -> account-takeover (critical)
    ]
    chains = correlate_chains(findings)
    assert [c.severity for c in chains] == sorted(
        [c.severity for c in chains], key=lambda s: {"critical": 4, "high": 3}.get(s, 0), reverse=True
    )
    assert chains[0].severity == "critical"
