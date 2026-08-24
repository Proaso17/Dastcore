"""TLS certificate enrichment — read the live certificate and flag the facts that are findings.

``passive_sources.cert_sans`` already reads a cert's SANs for subdomain discovery; this reads the rest
of the same certificate — issuer, validity window, self-signed status, negotiated protocol/cipher — and
turns the *facts* into findings: an **expired** certificate, a **self-signed** certificate on a public
host, or one **expiring within a few weeks**. These are objective properties of the certificate the
server itself presents, so they are zero-FP by construction (no guessing, no probe payloads).

The certificate parsing is pure (``parse_certificate`` over DER bytes) and unit-testable with a
generated cert; the network handshake is a separate, injectable step. Needs ``cryptography`` (already an
optional/dev dependency); without it the module fail-opens to no findings.

CWE-295 (Improper Certificate Validation) / CWE-298 (Improper Validation of Certificate Expiration).
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# A prober fetches (host, port) -> its certificate info, or None if TLS couldn't be read. Injectable.
CertProber = Callable[[str, int], Awaitable["CertInfo | None"]]

_EXPIRY_WARN_DAYS = 21


@dataclass
class CertInfo:
    """The parsed live certificate for a host: identity, validity window, and negotiated connection."""

    host: str
    port: int = 443
    subject: str = ""
    issuer: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    self_signed: bool = False
    sans: list[str] = field(default_factory=list)
    tls_version: str = ""
    cipher: str = ""

    def expired(self, *, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return self.not_after is not None and self.not_after < now

    def days_to_expiry(self, *, now: datetime | None = None) -> int | None:
        if self.not_after is None:
            return None
        now = now or datetime.now(UTC)
        return (self.not_after - now).days


def parse_certificate(der: bytes, host: str, port: int = 443, *, tls_version: str = "", cipher: str = "") -> CertInfo:
    """Parse a DER certificate into a ``CertInfo``. Pure — no network. Empty ``CertInfo`` on parse error."""
    info = CertInfo(host=host, port=port, tls_version=tls_version, cipher=cipher)
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID
    except ImportError:
        return info
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001 — unparseable cert: return what we have
        return info

    info.subject = cert.subject.rfc4514_string()
    info.issuer = cert.issuer.rfc4514_string()
    info.self_signed = cert.subject == cert.issuer
    try:  # ``not_valid_*_utc`` is the tz-aware accessor (cryptography >= 42); fall back if older.
        info.not_before = cert.not_valid_before_utc
        info.not_after = cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover - only on very old cryptography
        info.not_before = cert.not_valid_before.replace(tzinfo=UTC)
        info.not_after = cert.not_valid_after.replace(tzinfo=UTC)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        info.sans = list(san.value.get_values_for_type(x509.DNSName))
    except Exception:  # noqa: BLE001 — no SAN extension
        pass
    return info


def _probe_tls_sync(host: str, port: int, *, timeout: float) -> CertInfo | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we read the cert; we don't trust-chain it (self-signed must be seen)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                version = tls.version() or ""
                cipher_tuple = tls.cipher()
    except Exception:  # noqa: BLE001 — no TLS here / handshake failed: nothing to report
        return None
    if not der:
        return None
    cipher = cipher_tuple[0] if cipher_tuple else ""
    return parse_certificate(der, host, port, tls_version=version, cipher=cipher)


async def probe_tls(host: str, port: int = 443, *, timeout: float = 8.0) -> CertInfo | None:
    """Handshake with ``host:port`` and return its certificate info (or None if it doesn't speak TLS)."""
    return await asyncio.to_thread(_probe_tls_sync, host.strip().lower().rstrip("."), port, timeout=timeout)


def _point(request: HttpRequest) -> InjectionPoint:
    return InjectionPoint(location="header", name="Host", base_value="", request_template=request)


def _finding(host: str, port: int, rule: str, name: str, severity: str, cwe: str, detail: str, fix: str) -> Finding:
    origin = f"https://{host}/" if port == 443 else f"https://{host}:{port}/"
    request = HttpRequest(method="GET", url=origin)
    return Finding(
        id=f"{rule}:{host}:{port}",
        rule_id=rule,
        name=name,
        severity=severity,
        cwe=cwe,
        owasp="WSTG-CRYP-01",
        family="tls",
        injection_point=_point(request),
        evidence=[Evidence(type="response_match", data=detail, confidence="high")],
        request=request,
        response=HttpResponse(status_code=0, url=origin, text=detail),
        remediation=fix,
    )


def certificate_findings(info: CertInfo, *, now: datetime | None = None) -> list[Finding]:
    """The findings implied by a certificate's facts: expired, self-signed, or expiring soon. Zero-FP."""
    findings: list[Finding] = []
    host, port = info.host, info.port
    if info.expired(now=now):
        findings.append(
            _finding(
                host, port, "tls-cert-expired", "Expired TLS certificate", "medium", "CWE-298",
                f"{host}:{port} presents a certificate that expired on {info.not_after} "
                f"(issuer: {info.issuer or 'unknown'}).",
                "Renueva el certificado TLS y automatiza su renovación (p. ej. ACME/Let's Encrypt) "
                "para que no vuelva a caducar.",
            )
        )
    if info.self_signed:
        findings.append(
            _finding(
                host, port, "tls-cert-self-signed", "Self-signed TLS certificate", "low", "CWE-295",
                f"{host}:{port} presents a self-signed certificate (subject == issuer: {info.subject}). "
                "Clients cannot validate it against a trusted CA, so it trains users to click through "
                "certificate warnings and enables MITM.",
                "Sustituye el certificado autofirmado por uno emitido por una CA de confianza.",
            )
        )
    days = info.days_to_expiry(now=now)
    if not info.expired(now=now) and days is not None and 0 <= days <= _EXPIRY_WARN_DAYS:
        findings.append(
            _finding(
                host, port, "tls-cert-expiring", "TLS certificate expiring soon", "info", "CWE-298",
                f"{host}:{port}'s certificate expires in {days} day(s) (on {info.not_after}).",
                "Renueva el certificado antes de que caduque y automatiza la renovación.",
            )
        )
    return findings


async def run_tls_checks(
    client_target: str, *, prober: CertProber | None = None, now: datetime | None = None
) -> list[Finding]:
    """Read the target's TLS certificate and report expired / self-signed / expiring-soon facts.

    Only runs for ``https`` targets. ``prober`` is injectable so the check is testable without a live
    TLS server; by default it performs a real handshake.
    """
    parts = urlsplit(client_target)
    if parts.scheme != "https" or not parts.hostname:
        return []
    port = parts.port or 443
    probe = prober or probe_tls
    info = await probe(parts.hostname, port)
    if info is None:
        return []
    return certificate_findings(info, now=now)
