"""Active detector: OAuth2/OIDC lax ``redirect_uri`` validation.

An authorization endpoint must only redirect the authorization code/token to a ``redirect_uri``
pre-registered for that ``client_id``. If it accepts an attacker-controlled ``redirect_uri``, the
attacker harvests victims' codes/tokens — a full account takeover primitive.

This finds discovered OAuth authorization requests (they carry a ``client_id``), replays each
with a **foreign** ``redirect_uri``, and — since the scanner doesn't follow redirects — reads the
``Location`` straight off the response. The oracle is unambiguous and false-positive-free: the
finding fires only when the server issues a redirect whose host is the foreign origin we supplied.
A server that validates ``redirect_uri`` rejects it (error, or a redirect to its own origin) and
is never flagged.

CWE-601 (URL Redirection to Untrusted Site) / OWASP A07:2021 (Auth failures).
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_FOREIGN_HOST = "dcattacker.test"
_FOREIGN_REDIRECT = f"https://{_FOREIGN_HOST}/callback"
_AUTHORIZE_PATH = ("authorize", "authorization", "connect/authorize", "oauth2/auth")


def _is_authorize_request(request: HttpRequest) -> bool:
    """A request that looks like an OAuth2/OIDC authorization request (carries a client_id)."""
    params = request.params
    if "client_id" not in params:
        return False
    path = urlsplit(request.url).path.lower()
    return any(marker in path for marker in _AUTHORIZE_PATH) or "response_type" in params


def _point(request: HttpRequest) -> InjectionPoint:
    return InjectionPoint(location="query", name="redirect_uri", base_value="", request_template=request)


async def _get(client: HttpClient, request: HttpRequest) -> HttpResponse | None:
    try:
        return await client.request("GET", request.url, params=request.params, headers=request.headers or None)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _redirect_host(response: HttpResponse) -> str | None:
    if response.status_code not in (301, 302, 303, 307, 308):
        return None
    location = response.headers.get("location") or response.headers.get("Location")
    return urlsplit(location).netloc.lower() if location else None


async def check_oauth_redirect(client: HttpClient, request: HttpRequest) -> list[Finding]:
    """Replay an authorization request with a foreign redirect_uri; flag if it's honoured."""
    if not _is_authorize_request(request):
        return []
    forged = request.model_copy(
        update={
            "method": "GET",
            "params": {
                **request.params,
                "redirect_uri": _FOREIGN_REDIRECT,
                "response_type": request.params.get("response_type", "code"),
            },
        }
    )
    response = await _get(client, forged)
    if response is None or _redirect_host(response) != _FOREIGN_HOST:
        return []  # not redirected to the attacker origin → redirect_uri is validated

    path = urlsplit(request.url).path or "/"
    location = response.headers.get("location") or response.headers.get("Location") or ""
    leaked = "code" in parse_qs(urlsplit(location).query) or "code=" in urlsplit(location).fragment
    return [
        Finding(
            id=f"oauth-open-redirect:{path}",
            rule_id="oauth-redirect-uri-validation",
            name="OAuth2/OIDC lax redirect_uri validation",
            severity="high",
            cwe="CWE-601",
            owasp="A07:2021",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
            family="oauth",
            injection_point=_point(request),
            evidence=[
                Evidence(
                    type="differential",
                    data=(
                        f"the authorization endpoint {path} redirected to an attacker-controlled redirect_uri "
                        f"({_FOREIGN_REDIRECT}"
                        + (" carrying the authorization code" if leaked else "")
                        + ") — redirect_uri is not validated against the client's registered URIs, so an attacker "
                        "can steal victims' codes/tokens"
                    )[:200],
                    confidence="high",
                )
            ],
            request=forged,
            response=response,
            remediation=(
                "Valida `redirect_uri` contra una allowlist exacta (comparación completa, sin comodines ni "
                "subcadenas) de las URIs registradas para ese `client_id`. Rechaza cualquier `redirect_uri` no "
                "registrada antes de emitir el código/token."
            ),
        )
    ]


async def run_oauth_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Run the redirect_uri check over each discovered OAuth authorization request, deduped."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for request in requests:
        path = urlsplit(request.url).path or "/"
        if path in seen or not _is_authorize_request(request):
            continue
        seen.add(path)
        findings.extend(await check_oauth_redirect(client, request))
    return findings
