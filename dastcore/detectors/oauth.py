"""Active + passive OAuth2/OIDC checks.

The authorization endpoint is the account-takeover surface of a modern app. This covers the
highest-value OAuth flaws, each confirmed so it stays false-positive-free:

* **Lax ``redirect_uri`` validation** (active) — replay the authorization request with an
  attacker-controlled ``redirect_uri`` and its common validator-bypass shapes (fully foreign,
  ``registered@attacker`` userinfo confusion, ``registered.attacker`` subdomain, ``attacker/registered``
  path embed). The finding fires only when the server issues a redirect whose **host is one we
  control** — a validator that rejects it is never flagged. Stealing the code/token from there is a
  full ATO primitive.
* **Missing ``state``** (passive) — an authorization request with no (or empty) ``state`` has no
  CSRF token, so the client's callback can't bind the response to the user's session (login CSRF /
  forced account linking).
* **Missing PKCE** (passive) — an authorization-code request with no ``code_challenge`` is open to
  authorization-code interception; PKCE is required for public clients and recommended for all.

CWE-601 / CWE-352 / CWE-287, OWASP A07:2021.
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


def _redirect_hostname(response: HttpResponse) -> str | None:
    """The *hostname* (not netloc) of a redirect Location — so `registered@attacker` resolves to the
    attacker host, catching userinfo-confusion bypasses that a netloc check would miss."""
    if response.status_code not in (301, 302, 303, 307, 308):
        return None
    location = response.headers.get("location") or response.headers.get("Location")
    return (urlsplit(location).hostname or "").lower() if location else None


def _is_attacker_host(host: str | None) -> bool:
    return bool(host) and (host == _FOREIGN_HOST or host.endswith("." + _FOREIGN_HOST))  # type: ignore[union-attr]


def _redirect_variants(registered: str) -> list[tuple[str, str]]:
    """(bypass-class label, redirect_uri) shapes that all resolve to a host we control if honoured."""
    reg_host = urlsplit(registered).hostname or "app.test"
    return [
        ("redirect_uri foráneo", _FOREIGN_REDIRECT),
        ("confusión de userinfo (@)", f"https://{reg_host}@{_FOREIGN_HOST}/callback"),
        ("subdominio del atacante", f"https://{reg_host}.{_FOREIGN_HOST}/callback"),
        ("host registrado en el path", f"https://{_FOREIGN_HOST}/{reg_host}/callback"),
    ]


async def check_oauth_redirect(client: HttpClient, request: HttpRequest) -> list[Finding]:
    """Replay the authorization request with attacker-controlled redirect_uri shapes; flag the first honoured."""
    if not _is_authorize_request(request):
        return []
    registered = request.params.get("redirect_uri", "")
    for label, redirect_uri in _redirect_variants(registered):
        forged = request.model_copy(
            update={
                "method": "GET",
                "params": {
                    **request.params,
                    "redirect_uri": redirect_uri,
                    "response_type": request.params.get("response_type", "code"),
                },
            }
        )
        response = await _get(client, forged)
        if response is None or not _is_attacker_host(_redirect_hostname(response)):
            continue  # this shape was rejected/validated → try the next

        path = urlsplit(request.url).path or "/"
        location = response.headers.get("location") or response.headers.get("Location") or ""
        parts = urlsplit(location)
        leaked = "code" in parse_qs(parts.query) or "code=" in parts.fragment or "token" in parts.fragment
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
                            f"el endpoint de autorización {path} redirigió a un redirect_uri controlado por el "
                            f"atacante mediante «{label}» ({redirect_uri}"
                            + (" — llevando el código/token de autorización" if leaked else "")
                            + "): redirect_uri no se valida contra las URIs registradas del client_id, así que un "
                            "atacante roba los códigos/tokens de las víctimas (account takeover)"
                        )[:220],
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
    return []


def check_oauth_state(request: HttpRequest) -> Finding | None:
    """Passive: an authorization request with no/empty `state` has no CSRF binding (login CSRF)."""
    if not _is_authorize_request(request) or "response_type" not in request.params:
        return None
    if request.params.get("state", "").strip():
        return None  # a state parameter is present
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"oauth-missing-state:{path}",
        rule_id="oauth-missing-state",
        name="OAuth2/OIDC sin parámetro state (CSRF de login)",
        severity="medium",
        cwe="CWE-352",
        owasp="A07:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        family="oauth",
        injection_point=InjectionPoint(location="query", name="state", base_value="", request_template=request),
        evidence=[
            Evidence(
                type="status",
                data=(
                    f"la petición de autorización {path} no incluye `state`: sin token anti-CSRF el callback no "
                    "puede ligar la respuesta a la sesión del usuario, permitiendo CSRF de login / vinculación "
                    "forzada de cuenta del atacante"
                )[:220],
                confidence="high",
            )
        ],
        request=request,
        response=HttpResponse(status_code=0, text=""),
        remediation=(
            "Envía un `state` aleatorio e impredecible en cada petición de autorización y valídalo en el callback "
            "contra el valor guardado en la sesión del usuario antes de canjear el código."
        ),
    )


def check_oauth_pkce(request: HttpRequest) -> Finding | None:
    """Passive: an authorization-code request with no `code_challenge` (PKCE) is interception-prone."""
    if not _is_authorize_request(request):
        return None
    if "code" not in request.params.get("response_type", "").lower():
        return None  # PKCE applies to the authorization-code flow
    if request.params.get("code_challenge", "").strip():
        return None  # PKCE in use
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"oauth-missing-pkce:{path}",
        rule_id="oauth-missing-pkce",
        name="OAuth2/OIDC sin PKCE (code_challenge)",
        severity="low",
        cwe="CWE-287",
        owasp="A07:2021",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        family="oauth",
        injection_point=InjectionPoint(location="query", name="code_challenge", base_value="", request_template=request),
        evidence=[
            Evidence(
                type="status",
                data=(
                    f"la petición de autorización {path} usa flujo de código sin `code_challenge` (PKCE): un "
                    "atacante que intercepte el código de autorización puede canjearlo. PKCE es obligatorio para "
                    "clientes públicos y recomendado para todos"
                )[:220],
                confidence="high",
            )
        ],
        request=request,
        response=HttpResponse(status_code=0, text=""),
        remediation=(
            "Usa PKCE: envía `code_challenge`/`code_challenge_method=S256` en la autorización y exige el "
            "`code_verifier` correcto al canjear el código en el token endpoint."
        ),
    )


async def run_oauth_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Run redirect_uri (active) + missing-state/PKCE (passive) over each OAuth authorization request, deduped."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for request in requests:
        path = urlsplit(request.url).path or "/"
        if path in seen or not _is_authorize_request(request):
            continue
        seen.add(path)
        findings.extend(await check_oauth_redirect(client, request))
        for passive in (check_oauth_state(request), check_oauth_pkce(request)):
            if passive is not None:
                findings.append(passive)
    return findings
