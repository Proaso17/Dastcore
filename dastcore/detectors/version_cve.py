"""Known-vulnerable component detection (SCA-lite): fingerprint product + version and
match it against a bundled, offline advisory database (dastcore/vulndb/advisories.yaml).

This is version-banner based, so findings are reported at *medium* confidence — a banner
can be spoofed and distros back-port fixes without bumping the version string. It answers
"you appear to be running a version with a known CVE; verify your patch level", not "this
is a confirmed exploit". Add an advisory = add a YAML entry; no code change needed.
"""

from __future__ import annotations

import operator
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_ADVISORIES_PATH = Path(__file__).resolve().parent.parent / "vulndb" / "advisories.yaml"

# product -> regex capturing the version, applied to the header haystack (Server + X-Powered-By).
_HEADER_EXTRACTORS: list[tuple[str, re.Pattern[str], str]] = [
    ("apache", re.compile(r"Apache/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE), "Server header"),
    ("nginx", re.compile(r"nginx/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE), "Server header"),
    ("openssl", re.compile(r"OpenSSL/(\d+\.\d+\.\d+[a-z]?)", re.IGNORECASE), "Server header"),
    ("php", re.compile(r"PHP/(\d+\.\d+\.\d+)", re.IGNORECASE), "X-Powered-By header"),
]

# product -> regexes applied to the HTML body (generator meta, client-side library assets).
_BODY_EXTRACTORS: list[tuple[str, re.Pattern[str], str]] = [
    ("wordpress", re.compile(r"""content=["']WordPress\s+(\d+\.\d+(?:\.\d+)?)""", re.IGNORECASE), "generator meta"),
    ("jquery", re.compile(r"jquery[.\-/](\d+\.\d+\.\d+)(?:\.min)?\.js", re.IGNORECASE), "script asset"),
    ("jquery", re.compile(r"jQuery(?:\s+JavaScript\s+Library)?\s+v?(\d+\.\d+\.\d+)", re.IGNORECASE), "inline banner"),
    ("bootstrap", re.compile(r"bootstrap[.\-/](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)", re.IGNORECASE), "asset"),
    ("bootstrap", re.compile(r"Bootstrap\s+v(\d+\.\d+\.\d+)", re.IGNORECASE), "inline banner"),
]

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?([a-z])?")
_OPS = {"<=": operator.le, ">=": operator.ge, "==": operator.eq, "=": operator.eq, "<": operator.lt, ">": operator.gt}


@dataclass(frozen=True)
class SoftwareComponent:
    product: str
    version: str
    source: str


def _version_key(version: str) -> tuple[int, int, int, int] | None:
    """A comparable tuple for a dotted version with an optional letter suffix (OpenSSL 1.0.1f)."""
    match = _VERSION_RE.match(version.strip())
    if not match:
        return None
    major, minor, patch = (int(match.group(i) or 0) for i in (1, 2, 3))
    letter = match.group(4)
    return (major, minor, patch, (ord(letter) - 96) if letter else 0)


def satisfies(version: str, spec: str) -> bool:
    """True if `version` meets every comma-separated constraint in `spec` (AND)."""
    current = _version_key(version)
    if current is None:
        return False
    for clause in spec.split(","):
        clause = clause.strip()
        for op_str in ("<=", ">=", "==", "<", ">", "="):
            if clause.startswith(op_str):
                target = _version_key(clause[len(op_str) :])
                if target is None or not _OPS[op_str](current, target):
                    return False
                break
        else:
            return False  # malformed constraint never matches
    return True


@lru_cache(maxsize=1)
def load_advisories() -> list[dict]:
    data = yaml.safe_load(_ADVISORIES_PATH.read_text(encoding="utf-8")) or {}
    return data.get("advisories", [])


def extract_components(response: HttpResponse) -> list[SoftwareComponent]:
    """Fingerprint product + version from a response's headers and HTML body."""
    haystack = " ".join(f"{name}: {value}" for name, value in response.headers.items())
    found: dict[tuple[str, str], SoftwareComponent] = {}
    for product, pattern, source in _HEADER_EXTRACTORS:
        m = pattern.search(haystack)
        if m:
            found.setdefault((product, m.group(1)), SoftwareComponent(product, m.group(1), source))
    for product, pattern, source in _BODY_EXTRACTORS:
        m = pattern.search(response.text)
        if m:
            found.setdefault((product, m.group(1)), SoftwareComponent(product, m.group(1), source))
    return list(found.values())


def _point(request: HttpRequest) -> InjectionPoint:
    return InjectionPoint(location="header", name="-", base_value="", request_template=request)


def check_known_vulnerable_versions(request: HttpRequest, response: HttpResponse) -> list[Finding]:
    """Match fingerprinted components against the advisory DB; one finding per matched CVE."""
    host = urlsplit(request.url).netloc
    findings: list[Finding] = []
    emitted: set[str] = set()
    for component in extract_components(response):
        for advisory in load_advisories():
            if advisory["product"] != component.product:
                continue
            if not satisfies(component.version, advisory["affected"]):
                continue
            cve = advisory["cve"]
            key = f"{component.product}:{component.version}:{cve}"
            if key in emitted:
                continue
            emitted.add(key)
            fixed = advisory.get("fixed", "the latest release")
            reference = f"https://nvd.nist.gov/vuln/detail/{cve}"
            findings.append(
                Finding(
                    id=f"vulnerable-component:{host}:{component.product}:{cve}",
                    rule_id="known-vulnerable-version",
                    name=f"Known-vulnerable component: {component.product} {component.version} ({cve})",
                    severity=advisory["severity"],
                    cwe=advisory["cwe"],
                    owasp="A06:2021-Vulnerable and Outdated Components",
                    family="vulnerable_component",
                    injection_point=_point(request),
                    evidence=[
                        Evidence(
                            type="response_match",
                            # medium: version-banner based, not an exploited confirmation
                            data=(
                                f"{advisory['title']} — {component.product} {component.version} "
                                f"(affected {advisory['affected']}, seen in {component.source}); CVSS {advisory.get('cvss', 'n/a')}"
                            ),
                            confidence="medium",
                        )
                    ],
                    request=request,
                    response=response,
                    remediation=(
                        f"Upgrade {component.product} to {fixed} or later. This version matches {cve} "
                        f"({advisory['title']}). Verify your actual patch level — a back-ported fix may not "
                        f"change the version banner. Reference: {reference}"
                    ),
                )
            )
    return findings
