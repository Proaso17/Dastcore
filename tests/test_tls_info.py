"""TLS enrichment — parse a real (generated) certificate and turn its facts into zero-FP findings.
All offline: a self-signed cert is generated in-process and fed through the pure parser + an injected
prober, so no TLS server is needed."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from dastcore.discovery.tls_info import CertInfo, certificate_findings, parse_certificate, run_tls_checks

cryptography = pytest.importorskip("cryptography")


def _make_cert(*, not_before: datetime, not_after: datetime, issuer_cn: str = "acme.com") -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "acme.com")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("acme.com"), x509.DNSName("www.acme.com")]), False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


_NOW = datetime(2026, 8, 24, tzinfo=UTC)


def test_parse_certificate_extracts_identity_validity_and_sans() -> None:
    der = _make_cert(not_before=_NOW - timedelta(days=10), not_after=_NOW + timedelta(days=300))
    info = parse_certificate(der, "acme.com", 443, tls_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384")
    assert "acme.com" in info.subject and info.self_signed is True  # subject == issuer
    assert set(info.sans) == {"acme.com", "www.acme.com"}
    assert info.tls_version == "TLSv1.3" and not info.expired(now=_NOW)


def test_expired_cert_is_flagged() -> None:
    der = _make_cert(not_before=_NOW - timedelta(days=800), not_after=_NOW - timedelta(days=1))
    info = parse_certificate(der, "old.acme.com", 443)
    findings = certificate_findings(info, now=_NOW)
    ids = {f.rule_id for f in findings}
    assert "tls-cert-expired" in ids and "tls-cert-self-signed" in ids


def test_expiring_soon_cert_is_flagged_but_not_expired() -> None:
    info = CertInfo(host="soon.acme.com", not_after=_NOW + timedelta(days=5), issuer="CN=R3", subject="CN=soon.acme.com")
    findings = certificate_findings(info, now=_NOW)
    ids = {f.rule_id for f in findings}
    assert "tls-cert-expiring" in ids and "tls-cert-expired" not in ids and "tls-cert-self-signed" not in ids


def test_healthy_ca_signed_cert_yields_no_findings() -> None:
    info = CertInfo(host="ok.acme.com", not_after=_NOW + timedelta(days=300), issuer="CN=R3", subject="CN=ok.acme.com")
    assert certificate_findings(info, now=_NOW) == []


async def test_run_tls_checks_uses_injected_prober_for_https_only() -> None:
    info = CertInfo(
        host="acme.com", not_after=_NOW - timedelta(days=1), issuer="CN=acme.com", subject="CN=acme.com",
        self_signed=True,
    )

    async def prober(_host: str, _port: int) -> CertInfo:
        return info

    https = await run_tls_checks("https://acme.com/", prober=prober, now=_NOW)
    assert {f.rule_id for f in https} == {"tls-cert-expired", "tls-cert-self-signed"}
    # A plain-HTTP target is never TLS-probed.
    assert await run_tls_checks("http://acme.com/", prober=prober, now=_NOW) == []
