"""Access-control bypass via trusted request headers. CWE-290 / CWE-807 / CWE-284, OWASP A01:2021.

Some apps make access decisions on headers an attacker fully controls:

- **IP-allowlist spoofing** — an endpoint restricted to internal callers trusts ``X-Forwarded-For`` /
  ``X-Real-IP`` / ``X-Custom-IP-Authorization``; sending ``127.0.0.1`` flips a 403 into a 200.
- **URL-override routing** — a front proxy blocks ``/admin`` but the backend routes on
  ``X-Original-URL`` / ``X-Rewrite-URL``; requesting an allowed path with that header reaches the
  blocked one.

Both are confirmed by a **differential**: an endpoint that denies us (401/403) returns success once a
spoofed header is added, and the success body differs from the denial. The URL-override check adds a
catch-all guard (a bogus override path must not produce the same page) so a header that merely changes
the response generically can't masquerade as a per-path bypass. Read-only (GET/HEAD only), so it never
changes state; a finding only ever forms from a real deny→allow flip.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.validation.baseline import similarity_ratio

_IP_HEADERS = ["X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Originating-IP", "X-Custom-IP-Authorization"]
_URL_HEADERS = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL"]
_LOCALHOST = "127.0.0.1"
_DENIED = {401, 403}
_MAX_CANDIDATES = 60
_DIFF = 0.95  # bodies below this similarity are "different"


async def _send(client: HttpClient, request: HttpRequest) -> HttpResponse | None:
    try:
        return await client.request(
            request.method,
            request.url,
            params=request.params or None,
            headers=request.headers or None,
            cookies=request.cookies or None,
            data=request.data,
            json=request.json_body,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _success(status: int) -> bool:
    return 200 <= status < 300


def _differs(a: HttpResponse, b: HttpResponse) -> bool:
    return similarity_ratio(a.text, b.text) < _DIFF


def _with_headers(request: HttpRequest, extra: dict[str, str]) -> HttpRequest:
    return request.model_copy(update={"headers": {**request.headers, **extra}})


def _finding(
    rule_id: str, name: str, cwe: str, request: HttpRequest, response: HttpResponse, header: str, detail: str
) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"{rule_id}:{request.method}:{path}:{header}",
        rule_id=rule_id,
        name=name,
        severity="high",
        cwe=cwe,
        owasp="A01:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        family="authz",
        injection_point=InjectionPoint(location="header", name=header, base_value="", request_template=request),
        evidence=[Evidence(type="differential", data=detail[:200], confidence="high")],
        request=request,
        response=response,
        remediation=(
            "No tomes decisiones de acceso a partir de cabeceras que el cliente controla (X-Forwarded-For, "
            "X-Original-URL, etc.). Determina la IP de origen y la ruta en el borde de confianza y aplica "
            "autenticación/autorización en el servidor para cada petición; ignora estas cabeceras salvo que "
            "provengan de un proxy en el que confíes explícitamente."
        ),
    )


async def _check_ip_spoof(client: HttpClient, request: HttpRequest, baseline: HttpResponse) -> Finding | None:
    """A denied endpoint that flips to success once we spoof a trusted client IP."""
    spoof = _with_headers(request, dict.fromkeys(_IP_HEADERS, _LOCALHOST))
    resp = await _send(client, spoof)
    if resp is None or not _success(resp.status_code) or not _differs(resp, baseline):
        return None
    confirm = await _send(client, spoof)  # reproducible
    if confirm is None or not _success(confirm.status_code):
        return None
    return _finding(
        "access-bypass-trusted-header-ip",
        "Bypass de control de acceso vía cabecera de IP de confianza",
        "CWE-290",
        spoof,
        resp,
        _IP_HEADERS[0],
        f"la petición denegada (HTTP {baseline.status_code}) devolvió HTTP {resp.status_code} al enviar "
        f"{', '.join(_IP_HEADERS)}: {_LOCALHOST} — el control de acceso confía en una cabecera de IP falsificable",
    )


async def _check_url_override(
    client: HttpClient, request: HttpRequest, baseline: HttpResponse, root_resp: HttpResponse, junk_resp: HttpResponse
) -> Finding | None:
    """A path blocked at the proxy that the backend still serves when routed via X-Original-URL."""
    path = urlsplit(request.url).path or "/"
    root = urlsplit(request.url)._replace(path="/", query="", fragment="").geturl()
    for header in _URL_HEADERS:
        override = HttpRequest(method="GET", url=root, headers={header: path})
        resp = await _send(client, override)
        if resp is None or not _success(resp.status_code):
            continue
        # The header must have a *path-specific* effect: differ from plain root, differ from the denial,
        # and differ from the bogus-override reference (else it just changes the page generically).
        if _differs(resp, root_resp) and _differs(resp, baseline) and _differs(resp, junk_resp):
            confirm = await _send(client, override)
            if confirm is not None and _success(confirm.status_code):
                return _finding(
                    "access-bypass-trusted-header-url",
                    "Bypass de control de acceso vía reescritura de URL en cabecera",
                    "CWE-284",
                    override,
                    resp,
                    header,
                    f"'{path}' está bloqueado directamente (HTTP {baseline.status_code}) pero el backend lo sirve al "
                    f"enrutar con {header}: {path} desde una ruta permitida — la decisión de ruta confía en la cabecera",
                )
    return None


async def run_access_bypass_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Find endpoints whose access control can be bypassed with a spoofed trusted header."""
    findings: list[Finding] = []
    seen: set[str] = set()
    root_probed: dict[str, tuple[HttpResponse, HttpResponse] | None] = {}

    for request in requests:
        if request.method not in ("GET", "HEAD"):
            continue  # read-only: never re-issue state-changing verbs
        sig = request.signature()
        if sig in seen:
            continue
        seen.add(sig)
        if len(seen) > _MAX_CANDIDATES:
            break

        baseline = await _send(client, request)
        if baseline is None or baseline.status_code not in _DENIED:
            continue  # only endpoints that actually deny us are worth trying to bypass

        ip_hit = await _check_ip_spoof(client, request, baseline)
        if ip_hit is not None:
            findings.append(ip_hit)

        # URL-override needs an allowed base (site root) + a bogus-override reference, fetched once per host.
        host = urlsplit(request.url).netloc
        if host not in root_probed:
            root = urlsplit(request.url)._replace(path="/", query="", fragment="").geturl()
            root_resp = await _send(client, HttpRequest(method="GET", url=root))
            junk_header = {_URL_HEADERS[0]: f"/dc-none-{secrets.token_hex(4)}"}
            junk_resp = await _send(client, HttpRequest(method="GET", url=root, headers=junk_header))
            root_probed[host] = (
                (root_resp, junk_resp)
                if root_resp is not None and _success(root_resp.status_code) and junk_resp is not None
                else None
            )
        probed = root_probed[host]
        if probed is not None:
            url_hit = await _check_url_override(client, request, baseline, probed[0], probed[1])
            if url_hit is not None:
                findings.append(url_hit)

    return findings
