"""Passive detector: serialized objects exposed to the client.

When an app hands a serialized object to the client (in a body, hidden field or
cookie), it almost always deserializes it back on the next request — a classic
insecure-deserialization sink (Java `readObject`, PHP `unserialize`, Python
`pickle.loads`). The signatures below are the magic prefixes of each format, so a
normal page doesn't match and plain base64 (a decoy) is left alone.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# (label, pattern) — each is the unambiguous magic header of a serialization format.
_SERIALIZED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Java serialized stream: 0xAC 0xED 0x00 0x05 -> base64 "rO0AB…"
    ("Java serialized object", re.compile(r"rO0AB[A-Za-z0-9+/=]{10,}")),
    # PHP serialize() of an object: O:<len>:"Class":<n>:{ …
    ("PHP serialized object", re.compile(r'O:\d+:"[A-Za-z0-9_\\]+":\d+:\{')),
    # Python pickle protocol 4 magic 0x80 0x04 0x95 -> base64 "gASV…"
    ("Python pickle (base64)", re.compile(r"gASV[A-Za-z0-9+/=]{10,}")),
]


def _point(request: HttpRequest) -> InjectionPoint:
    return InjectionPoint(location="header", name="-", base_value="", request_template=request)


def check_serialized_exposure(request: HttpRequest, response: HttpResponse) -> list[Finding]:
    """Report a serialized object handed to the client (one finding per format)."""
    findings: list[Finding] = []
    path = urlsplit(request.url).path or "/"
    for label, pattern in _SERIALIZED_PATTERNS:
        match = pattern.search(response.text)
        if match is None:
            continue
        snippet = match.group(0)
        findings.append(
            Finding(
                id=f"serialized-object-exposure:{label}:{request.method}:{path}",
                rule_id="serialized-object-exposure",
                name=f"Serialized object exposed to client: {label}",
                severity="medium",
                cwe="CWE-502",
                owasp="A08:2021-Software and Data Integrity Failures",
                family="deserialization",
                injection_point=_point(request),
                evidence=[
                    Evidence(
                        type="response_match",
                        data=f"{label} in response: {snippet[:40]}…",
                        confidence="high",
                    )
                ],
                request=request,
                response=response,
                remediation=(
                    "Do not send serialized objects to the client or accept them back. If you must, "
                    "sign them (HMAC) and verify before deserializing, prefer a data-only format "
                    "(JSON) over native serialization, and use allow-lists on the deserializer."
                ),
            )
        )
    return findings
