"""Passive secret-exposure detector."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.secrets import check_exposed_secrets

_REQ = HttpRequest(method="GET", url="http://t/api/build-info")


def _resp(text: str) -> HttpResponse:
    return HttpResponse(status_code=200, text=text, url="http://t/api/build-info")


def test_detects_aws_key() -> None:
    findings = check_exposed_secrets(_REQ, _resp('{"aws_key":"AKIAIOSFODNN7EXAMPLE"}'))
    assert len(findings) == 1
    assert findings[0].rule_id == "secret-exposure"
    assert "AWS access key id" in findings[0].name
    assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].evidence[0].data  # masked, not re-leaked


def test_detects_private_key_as_critical() -> None:
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    findings = check_exposed_secrets(_REQ, _resp(body))
    assert findings and findings[0].severity == "critical"


def test_detects_stripe_and_github_tokens() -> None:
    # Built by concatenation so no full secret literal lives in the source (they're fake,
    # but real-looking values trip commit secret scanners). They match the patterns at runtime.
    stripe = "sk_" + "live_" + "0123456789abcdefABCD"
    github = "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
    body = f"stripe={stripe} token={github}"
    labels = {f.name for f in check_exposed_secrets(_REQ, _resp(body))}
    assert any("Stripe" in name for name in labels)
    assert any("GitHub" in name for name in labels)


def test_clean_response_has_no_secrets() -> None:
    assert check_exposed_secrets(_REQ, _resp('{"version":"1.2.3","status":"ok"}')) == []
