"""Passive detectors.

Operate on a single already-fetched response — no extra requests, no
mutation. Covers missing security headers, insecure cookie flags, permissive
CORS, and verbose error / stack-trace disclosure.
"""

from __future__ import annotations

import re

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.detectors.cleartext import check_cleartext_credentials
from dastcore.detectors.deserialization import check_serialized_exposure
from dastcore.detectors.secrets import check_exposed_secrets

_ERROR_DISCLOSURE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"Warning:\s+[\w\\]+\(\):",  # PHP warnings
    r"at [\w.$]+\([\w.]+:\d+\)",  # Java-style stack frame
    r"System\.\w+Exception",
    r"ORA-\d{5}",
]


def _passive_point(request: HttpRequest, name: str) -> InjectionPoint:
    """Passive findings aren't tied to a mutated parameter; anchor to the request itself."""
    return InjectionPoint(location="header", name=name, base_value="", request_template=request)


def check_missing_security_headers(request: HttpRequest, response: HttpResponse) -> list[Finding]:
    headers = {name.lower(): value for name, value in response.headers.items()}
    findings: list[Finding] = []

    if "x-content-type-options" not in headers:
        findings.append(
            Finding(
                id="passive-missing-x-content-type-options",
                rule_id="passive-missing-x-content-type-options",
                name="Missing X-Content-Type-Options header",
                severity="low",
                cwe="CWE-693",
                owasp="A05:2021-Security Misconfiguration",
                injection_point=_passive_point(request, "X-Content-Type-Options"),
                evidence=[Evidence(type="status", data="No X-Content-Type-Options header present", confidence="high")],
                request=request,
                response=response,
                remediation="Set 'X-Content-Type-Options: nosniff' on all responses.",
            )
        )

    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        findings.append(
            Finding(
                id="passive-missing-x-frame-options",
                rule_id="passive-missing-x-frame-options",
                name="Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)",
                severity="medium",
                cwe="CWE-1021",
                owasp="WSTG-CLNT-09",
                injection_point=_passive_point(request, "X-Frame-Options"),
                evidence=[
                    Evidence(
                        type="status",
                        data="No X-Frame-Options and no CSP frame-ancestors directive",
                        confidence="high",
                    )
                ],
                request=request,
                response=response,
                remediation="Set 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
            )
        )

    if request.url.startswith("https://") and "strict-transport-security" not in headers:
        findings.append(
            Finding(
                id="passive-missing-hsts",
                rule_id="passive-missing-hsts",
                name="Missing Strict-Transport-Security header",
                severity="medium",
                cwe="CWE-319",
                owasp="WSTG-CONF-07",
                injection_point=_passive_point(request, "Strict-Transport-Security"),
                evidence=[
                    Evidence(
                        type="status", data="HTTPS response has no Strict-Transport-Security header", confidence="high"
                    )
                ],
                request=request,
                response=response,
                remediation="Set 'Strict-Transport-Security: max-age=63072000; includeSubDomains'.",
            )
        )

    return findings


def check_insecure_cookies(request: HttpRequest, response: HttpResponse) -> list[Finding]:
    set_cookie = response.headers.get("set-cookie")
    if not set_cookie:
        return []

    directives = {part.strip().lower() for part in set_cookie.split(";")[1:]}
    missing = []
    if "httponly" not in directives:
        missing.append("HttpOnly")
    if request.url.startswith("https://") and "secure" not in directives:
        missing.append("Secure")
    if not any(directive.startswith("samesite") for directive in directives):
        missing.append("SameSite")

    if not missing:
        return []

    cookie_name = set_cookie.split("=", 1)[0].strip()
    return [
        Finding(
            id=f"passive-insecure-cookie:{cookie_name}",
            rule_id="passive-insecure-cookie",
            name=f"Cookie '{cookie_name}' missing security attributes: {', '.join(missing)}",
            severity="medium",
            cwe="CWE-614",
            owasp="WSTG-SESS-02",
            injection_point=_passive_point(request, cookie_name),
            evidence=[Evidence(type="status", data=set_cookie, confidence="high")],
            request=request,
            response=response,
            remediation="Set the missing cookie attributes: HttpOnly always, Secure over HTTPS, and an explicit SameSite policy.",
        )
    ]


def check_cors_misconfiguration(request: HttpRequest, response: HttpResponse) -> list[Finding]:
    headers = {name.lower(): value for name, value in response.headers.items()}
    allow_origin = headers.get("access-control-allow-origin")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower()

    if allow_origin == "*" and allow_credentials == "true":
        return [
            Finding(
                id="passive-cors-wildcard-with-credentials",
                rule_id="passive-cors-wildcard-with-credentials",
                name="CORS misconfiguration: wildcard origin with credentials allowed",
                severity="high",
                cwe="CWE-942",
                owasp="WSTG-CLNT-07",
                injection_point=_passive_point(request, "Access-Control-Allow-Origin"),
                evidence=[
                    Evidence(
                        type="status",
                        data="Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true",
                        confidence="high",
                    )
                ],
                request=request,
                response=response,
                remediation=(
                    "Never combine a wildcard Access-Control-Allow-Origin with allow-credentials; "
                    "reflect a validated allowlist of origins instead."
                ),
            )
        ]
    return []


def check_error_disclosure(request: HttpRequest, response: HttpResponse) -> list[Finding]:
    for pattern in _ERROR_DISCLOSURE_PATTERNS:
        match = re.search(pattern, response.text)
        if match:
            return [
                Finding(
                    id="passive-error-disclosure",
                    rule_id="passive-error-disclosure",
                    name="Verbose error / stack trace disclosed in response",
                    severity="medium",
                    cwe="CWE-209",
                    owasp="WSTG-ERRH-01",
                    injection_point=_passive_point(request, "(body)"),
                    evidence=[Evidence(type="response_match", data=match.group(0)[:200], confidence="high")],
                    request=request,
                    response=response,
                    remediation="Disable debug/verbose error output in production; return generic error pages instead.",
                )
            ]
    return []


_DIR_LISTING_PATTERNS = [
    r"<title>Index of /",
    r"<h1>Index of /",
    r"Directory listing for /",
]


def check_technology_disclosure(request: HttpRequest, response: HttpResponse) -> list[Finding]:
    """Server / X-Powered-By headers leak the stack and version, easing targeted attacks."""
    headers = {name.lower(): value for name, value in response.headers.items()}
    findings: list[Finding] = []
    for header_name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        value = headers.get(header_name)
        # A bare product name is low signal; a version number is what actually helps an attacker.
        if value and re.search(r"\d+\.\d+", value):
            findings.append(
                Finding(
                    id=f"passive-tech-disclosure:{header_name}",
                    rule_id="passive-tech-disclosure",
                    name=f"Technology/version disclosure via '{header_name}' header",
                    severity="low",
                    cwe="CWE-200",
                    owasp="WSTG-INFO-08",
                    injection_point=_passive_point(request, header_name),
                    evidence=[Evidence(type="status", data=f"{header_name}: {value}", confidence="high")],
                    request=request,
                    response=response,
                    remediation="Suppress or genericize version-revealing response headers (Server, X-Powered-By, etc.).",
                )
            )
    return findings


def check_missing_csp(request: HttpRequest, response: HttpResponse) -> list[Finding]:
    """A missing Content-Security-Policy removes a key defense-in-depth layer against XSS."""
    headers = {name.lower() for name in response.headers}
    content_type = response.headers.get("content-type", "").lower()
    if "content-security-policy" in headers or "html" not in content_type:
        return []
    return [
        Finding(
            id="passive-missing-csp",
            rule_id="passive-missing-csp",
            name="Missing Content-Security-Policy header",
            severity="low",
            cwe="CWE-693",
            owasp="WSTG-CONF-12",
            injection_point=_passive_point(request, "Content-Security-Policy"),
            evidence=[
                Evidence(type="status", data="HTML response has no Content-Security-Policy header", confidence="high")
            ],
            request=request,
            response=response,
            remediation="Define a restrictive Content-Security-Policy (e.g. default-src 'self') as defense in depth against XSS.",
        )
    ]


def check_directory_listing(request: HttpRequest, response: HttpResponse) -> list[Finding]:
    """An enabled directory listing exposes file structure and unintended files."""
    if response.status_code != 200:
        return []
    for pattern in _DIR_LISTING_PATTERNS:
        if re.search(pattern, response.text, re.IGNORECASE):
            return [
                Finding(
                    id="passive-directory-listing",
                    rule_id="passive-directory-listing",
                    name="Directory listing enabled",
                    severity="medium",
                    cwe="CWE-548",
                    owasp="WSTG-CONF-04",
                    injection_point=_passive_point(request, "(body)"),
                    evidence=[Evidence(type="response_match", data=pattern, confidence="high")],
                    request=request,
                    response=response,
                    remediation="Disable automatic directory indexing on the web server.",
                )
            ]
    return []


def run_passive_checks(request: HttpRequest, response: HttpResponse) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_missing_security_headers(request, response))
    findings.extend(check_insecure_cookies(request, response))
    findings.extend(check_cors_misconfiguration(request, response))
    findings.extend(check_error_disclosure(request, response))
    findings.extend(check_technology_disclosure(request, response))
    findings.extend(check_missing_csp(request, response))
    findings.extend(check_directory_listing(request, response))
    findings.extend(check_exposed_secrets(request, response))
    findings.extend(check_serialized_exposure(request, response))
    findings.extend(check_cleartext_credentials(request, response))
    return findings
