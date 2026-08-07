"""Passive secret-exposure detector.

Scans a response body for high-signal credential formats that should never appear
in an HTTP response — cloud API keys, provider tokens, private keys. The patterns
are deliberately specific (a fixed prefix + a fixed shape) so a normal page doesn't
match; generic-looking blobs (bare base64, JWTs that are often a user's own token)
are left out to keep false positives near zero. The matched value is masked in the
evidence so the report doesn't re-leak it.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# (label, pattern, severity) — each prefix makes the match unambiguous.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "high"),
    ("Stripe secret key", re.compile(r"sk_live_[0-9a-zA-Z]{16,}"), "high"),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"), "high"),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"), "high"),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical"),
]


def _mask(value: str) -> str:
    return f"{value[:6]}…{value[-2:]}" if len(value) > 10 else f"{value[:3]}…"


def _point(request: HttpRequest) -> InjectionPoint:
    return InjectionPoint(location="header", name="-", base_value="", request_template=request)


def check_exposed_secrets(request: HttpRequest, response: HttpResponse) -> list[Finding]:
    """Report any high-signal secret found in the response body (one per type)."""
    findings: list[Finding] = []
    path = urlsplit(request.url).path or "/"
    for label, pattern, severity in _SECRET_PATTERNS:
        match = pattern.search(response.text)
        if match is None:
            continue
        findings.append(
            Finding(
                id=f"secret-exposure:{label}:{request.method}:{path}",
                rule_id="secret-exposure",
                name=f"Exposed secret in response: {label}",
                severity=severity,  # type: ignore[arg-type]
                cwe="CWE-312",
                owasp="WSTG-CONF-06",
                family="secret",
                injection_point=_point(request),
                evidence=[
                    Evidence(
                        type="response_match",
                        data=f"{label} found in response body: {_mask(match.group(0))}",
                        confidence="high",
                    )
                ],
                request=request,
                response=response,
                remediation=(
                    "Nunca devuelvas secretos en una respuesta HTTP. Rota la credencial filtrada "
                    "de inmediato y elimínala del código/config que la sirvió."
                ),
            )
        )
    return findings
