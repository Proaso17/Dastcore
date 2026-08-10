"""Passive detector: credentials submitted over cleartext HTTP.

Flags a login form (a `password` field) whose `action` posts to an absolute
`http://` URL — the credentials would travel unencrypted. The signal is deliberately
narrow (an explicit cleartext absolute action, not merely "served over HTTP") so a
localhost/dev target with relative actions isn't flagged; that keeps false positives
near zero while catching the real mixed-content credential leak.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_FORM = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
_ACTION = re.compile(r"""action\s*=\s*["']?\s*(http://[^"'\s>]+)""", re.IGNORECASE)
_PASSWORD_FIELD = re.compile(r"""<input\b[^>]*\btype\s*=\s*["']?password""", re.IGNORECASE)


def _point(request: HttpRequest) -> InjectionPoint:
    return InjectionPoint(location="header", name="-", base_value="", request_template=request)


def check_cleartext_credentials(request: HttpRequest, response: HttpResponse) -> list[Finding]:
    """Report a password form that posts to an absolute cleartext (http://) URL."""
    path = urlsplit(request.url).path or "/"
    for form in _FORM.finditer(response.text):
        block = form.group(0)
        action = _ACTION.search(block)
        if action is None or not _PASSWORD_FIELD.search(block):
            continue
        return [
            Finding(
                id=f"cleartext-credentials:{request.method}:{path}",
                rule_id="cleartext-credentials",
                name="Credentials submitted over cleartext HTTP",
                severity="medium",
                cwe="CWE-319",
                owasp="WSTG-ATHN-01",
                family="cleartext",
                injection_point=_point(request),
                evidence=[
                    Evidence(
                        type="response_match",
                        data=f"password form posts to cleartext URL: {action.group(1)[:120]}",
                        confidence="high",
                    )
                ],
                request=request,
                response=response,
                remediation=(
                    "Serve login pages over HTTPS and post credentials only to an https:// endpoint. "
                    "Enable HSTS and redirect all HTTP traffic to HTTPS so credentials never travel in "
                    "cleartext."
                ),
            )
        ]
    return []
