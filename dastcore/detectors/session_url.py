"""Passive detector: session identifier carried in the URL (CWE-598).

A session token in a query string leaks into browser history, proxies, Referer headers
and server logs. This flags a discovered URL whose query has a session-like parameter
name with a long, token-shaped value — a narrow signal so a short id or a search term
named `token=hi` isn't flagged.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# Parameter names that carry a session/authentication token (not generic ids).
_SESSION_PARAMS = {
    "sessionid",
    "session_id",
    "sessiontoken",
    "session",
    "sessid",
    "sid",
    "jsessionid",
    "phpsessid",
    "aspsessionid",
    "asp.net_sessionid",
    "access_token",
    "auth_token",
    "authtoken",
}
# A real token: long and made of token characters (not a word or a small integer).
_TOKEN_VALUE = re.compile(r"^[A-Za-z0-9._~+/\-]{16,}$")


def _point(request: HttpRequest, name: str) -> InjectionPoint:
    return InjectionPoint(location="query", name=name, base_value="", request_template=request)


def check_session_token_in_url(request: HttpRequest, response: HttpResponse) -> list[Finding]:
    """Report a session/auth token passed in the request URL's query string."""
    query = urlsplit(request.url).query
    for name, value in parse_qsl(query):
        if name.lower() in _SESSION_PARAMS and _TOKEN_VALUE.match(value):
            path = urlsplit(request.url).path or "/"
            return [
                Finding(
                    id=f"session-token-in-url:{request.method}:{path}:{name}",
                    rule_id="session-token-in-url",
                    name="Session token exposed in URL",
                    severity="medium",
                    cwe="CWE-598",
                    owasp="WSTG-SESS-04",
                    family="session_exposure",
                    injection_point=_point(request, name),
                    evidence=[
                        Evidence(
                            type="response_match",
                            data=f"session parameter {name!r} carries a token in the query string",
                            confidence="high",
                        )
                    ],
                    request=request,
                    response=response,
                    remediation=(
                        "Never put session or auth tokens in the URL. Keep the session in a Secure, HttpOnly "
                        "cookie (or an Authorization header), and pass tokens in the request body/header, so "
                        "they don't leak via history, logs, proxies or the Referer header."
                    ),
                )
            ]
    return []
