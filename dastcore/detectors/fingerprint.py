"""Technology fingerprinting and WAF / blocking-layer detection.

Two pieces of scan context that make the rest of the results easier to read and act on:

- **Fingerprint** — what the target is built with (server, framework, language),
  read passively from response headers and cookie names. Informational, and useful
  for choosing follow-up payloads by hand.
- **WAF detection** — whether a web application firewall or CDN blocking layer sits
  in front. It matters because a *blocked* request is not the same as a *safe* one:
  behind a WAF, "no finding" can mean "filtered", so the report should say a WAF is
  present rather than let the reader assume full coverage.

Both are reported as `info` findings; neither is a vulnerability on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# Cookie name (lowercased) -> technology it implies.
_COOKIE_TECH: dict[str, str] = {
    "phpsessid": "PHP",
    "jsessionid": "Java (JSP/Servlet)",
    "asp.net_sessionid": "ASP.NET",
    ".aspxauth": "ASP.NET",
    "laravel_session": "Laravel (PHP)",
    "ci_session": "CodeIgniter (PHP)",
    "csrftoken": "Django (Python)",
    "connect.sid": "Express (Node.js)",
    "_rails_session": "Ruby on Rails",
    "wordpress_logged_in": "WordPress",
}

# (header lowercased, required value substring or None, technology or None=use raw value).
_HEADER_TECH: list[tuple[str, str | None, str | None]] = [
    ("x-powered-by", None, None),
    ("x-aspnet-version", None, "ASP.NET"),
    ("x-aspnetmvc-version", None, "ASP.NET MVC"),
    ("x-drupal-cache", None, "Drupal"),
    ("x-generator", "drupal", "Drupal"),
    ("x-generator", "wordpress", "WordPress"),
]

# (header lowercased, required value substring or None, WAF/blocking-layer name).
_WAF_SIGNATURES: list[tuple[str, str | None, str]] = [
    ("cf-ray", None, "Cloudflare"),
    ("server", "cloudflare", "Cloudflare"),
    ("x-sucuri-id", None, "Sucuri"),
    ("x-sucuri-cache", None, "Sucuri"),
    ("x-iinfo", None, "Imperva Incapsula"),
    ("x-cdn", "incapsula", "Imperva Incapsula"),
    ("server", "akamaighost", "Akamai"),
    ("server", "barracuda", "Barracuda"),
    ("x-powered-by-plesk", None, "Plesk"),
    ("x-waf-event-info", None, "generic WAF"),
    ("x-denied-reason", None, "generic WAF"),
]

# Body/status signals that a request was actively blocked (for the WAF probe).
_BLOCK_STATUSES = {403, 406, 429, 501, 503}
_BLOCK_BODY = re.compile(
    r"(access denied|request blocked|web application firewall|attention required|"
    r"you (?:have been|are) blocked|mod_security|not acceptable|request rejected|"
    r"blocked by|security policy|incapsula|cloudflare|malicious)",
    re.IGNORECASE,
)

# A single deliberately-suspicious probe value that most WAFs flag but a plain app ignores.
_WAF_PROBE = "' OR 1=1-- <script>alert(1)</script> ../../etc/passwd"


@dataclass
class TechProfile:
    server: str | None = None
    powered_by: str | None = None
    technologies: list[str] = field(default_factory=list)
    waf: str | None = None


def _lower_headers(response: HttpResponse) -> dict[str, str]:
    headers = {name.lower(): value for name, value in response.headers.items()}
    return headers


def _cookie_names(response: HttpResponse) -> set[str]:
    names = {name.lower() for name in response.cookies}
    for part in _lower_headers(response).get("set-cookie", "").split(","):
        name = part.split("=", 1)[0].strip().lower()
        if name:
            names.add(name)
    return names


def build_profile(response: HttpResponse) -> TechProfile:
    """Extract a technology profile from a single response's headers and cookies."""
    headers = _lower_headers(response)
    techs: list[str] = []

    server = response.headers.get("Server") or headers.get("server")
    powered_by = response.headers.get("X-Powered-By") or headers.get("x-powered-by")
    if server:
        techs.append(server)

    for header, needle, tech in _HEADER_TECH:
        value = headers.get(header)
        if value is None:
            continue
        if needle is not None and needle not in value.lower():
            continue
        techs.append(tech or value)

    for name in _cookie_names(response):
        tech = _COOKIE_TECH.get(name)
        if tech:
            techs.append(tech)

    waf: str | None = None
    for header, needle, name in _WAF_SIGNATURES:
        value = headers.get(header)
        if value is not None and (needle is None or needle in value.lower()):
            waf = name
            break

    # Dedupe preserving order.
    deduped = list(dict.fromkeys(techs))
    return TechProfile(server=server, powered_by=powered_by, technologies=deduped, waf=waf)


def looks_blocked(response: HttpResponse) -> str | None:
    """A short reason if this response looks like an active block, else None."""
    if response.status_code in _BLOCK_STATUSES:
        return f"status {response.status_code}"
    match = _BLOCK_BODY.search(response.text)
    return f"body signature {match.group(0)!r}" if match else None


def _point(request: HttpRequest) -> InjectionPoint:
    return InjectionPoint(location="header", name="-", base_value="", request_template=request)


async def fingerprint_and_waf(client: HttpClient, target: str) -> list[Finding]:
    """Fingerprint the target and detect a WAF/blocking layer. Returns info findings."""
    parts = urlsplit(target)
    origin = f"{parts.scheme}://{parts.netloc}/"
    try:
        base = await client.get(origin)
    except (OutOfScopeError, BudgetExceededError):
        return []

    profile = build_profile(base)
    findings: list[Finding] = []
    base_request = HttpRequest(method="GET", url=origin)

    # Known-vulnerable component versions (SCA-lite) from the fingerprinted software.
    from dastcore.detectors.version_cve import check_known_vulnerable_versions

    findings.extend(check_known_vulnerable_versions(base_request, base))

    if profile.server or profile.powered_by or profile.technologies:
        detail = ", ".join(profile.technologies) or profile.server or profile.powered_by or "unknown"
        findings.append(
            Finding(
                id=f"tech-fingerprint:{parts.netloc}",
                rule_id="tech-fingerprint",
                name="Technology fingerprint",
                severity="info",
                cwe="CWE-200",
                owasp="WSTG-INFO-02",
                injection_point=_point(base_request),
                evidence=[Evidence(type="response_match", data=f"detected: {detail}"[:200], confidence="high")],
                request=base_request,
                response=base,
                remediation=(
                    "Minimiza las cabeceras que revelan producto/versión (Server, X-Powered-By) "
                    "para reducir la superficie de reconocimiento del atacante."
                ),
            )
        )

    # WAF: from headers (passive) or by actively probing with a suspicious value.
    waf = profile.waf
    waf_reason = f"header signature ({waf})" if waf else None
    if waf is None and looks_blocked(base) is None:
        probe_url = f"{origin}?{urlencode({'dastcore_probe': _WAF_PROBE})}"
        try:
            probe = await client.get(probe_url)
        except (OutOfScopeError, BudgetExceededError):
            probe = None
        reason = looks_blocked(probe) if probe is not None else None
        if reason:
            waf = build_profile(probe).waf or "unidentified WAF / blocking layer"  # type: ignore[union-attr]
            waf_reason = f"suspicious request blocked ({reason})"

    if waf:
        findings.append(
            Finding(
                id=f"waf-detected:{parts.netloc}",
                rule_id="waf-detected",
                name=f"WAF / blocking layer detected: {waf}",
                severity="info",
                cwe="CWE-693",
                owasp="WSTG-INFO-02",
                injection_point=_point(base_request),
                evidence=[Evidence(type="differential", data=(waf_reason or "detected")[:200], confidence="high")],
                request=base_request,
                response=base,
                remediation=(
                    "Un WAF/capa de bloqueo está delante del objetivo: los resultados pueden estar "
                    "filtrados (un request bloqueado no equivale a 'no vulnerable'). Para una cobertura "
                    "completa, escanea desde una IP en allowlist o directamente contra el origen."
                ),
            )
        )
    return findings
