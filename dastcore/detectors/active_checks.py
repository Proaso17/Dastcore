"""Active checks that don't fit the generic per-parameter rule engine.

These craft specific requests (a forged Origin, probes for well-known sensitive
paths, a GraphQL introspection query) rather than fuzzing an injection point, so
they live here instead of as YAML rules.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin, urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.discovery.graphql import introspect

_CORS_PROBE_ORIGIN = "https://dastcore-cors-probe.evil"
_XST_PROBE = "dastcore-xst-probe"

# path -> (finding name, signature the body must match to confirm, severity)
_SENSITIVE_FILES: list[tuple[str, str, str, str]] = [
    (".env", "Exposed .env file", r"(?im)^[A-Z0-9_]+\s*=", "high"),
    (".git/config", "Exposed .git repository", r"\[core\]|repositoryformatversion", "high"),
    (".git/HEAD", "Exposed .git repository", r"ref:\s*refs/", "high"),
    ("id_rsa", "Exposed private key", r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY", "critical"),
    (".htpasswd", "Exposed .htpasswd", r":\$(?:apr1|2y|1)\$", "high"),
    ("config.php.bak", "Exposed PHP config backup", r"<\?php|\$db|password", "high"),
    (".DS_Store", "Exposed .DS_Store", r"Bud1|\x00\x00\x00", "low"),
    # API schemas: reachable but a recon surface (info) — signature keeps it unambiguous.
    ("swagger.json", "Exposed OpenAPI/Swagger schema", r'"swagger"\s*:|"openapi"\s*:', "info"),
    ("openapi.json", "Exposed OpenAPI/Swagger schema", r'"openapi"\s*:|"swagger"\s*:', "info"),
    # Spring Boot Actuator: /env leaks config + property sources (often with secrets).
    ("actuator/env", "Exposed Spring Actuator /env", r'"propertySources"\s*:|"activeProfiles"\s*:', "high"),
    ("actuator", "Exposed Spring Actuator index", r'"_links"\s*:.*"(?:env|health|beans)"', "medium"),
    # Apache/Nginx server status pages.
    ("server-status", "Exposed server-status page", r"Apache Server Status|Server Version:|Total Accesses", "medium"),
    # Common editor/backup leftovers of a config file.
    (".env.bak", "Exposed .env backup", r"(?im)^[A-Z0-9_]+\s*=", "high"),
]


def _point(request: HttpRequest, location: str, name: str) -> InjectionPoint:
    return InjectionPoint(location=location, name=name, base_value="", request_template=request)  # type: ignore[arg-type]


_CORS_ATTACK_SUFFIX = "dcattacker.example"  # an attacker-registrable domain used to prove a bypass


async def _cors_probe(client: HttpClient, request: HttpRequest, origin: str) -> tuple[str, str, bool] | None:
    """Send ``request`` with ``Origin: origin``; return (ACAO, ACAC-lowercased, cors_aware) or None.

    ``cors_aware`` means the endpoint does dynamic per-origin handling (any ``Access-Control-*`` header,
    or ``Vary: Origin``) — the signal that a *restrictive* endpoint (which won't reflect our evil probe)
    is still worth testing for an allowlist bypass, without a second request.
    """
    try:
        response = await client.request(
            request.method, request.url, params=request.params,
            headers={**request.headers, "Origin": origin},
            data=request.data, json=request.json_body,
        )
    except (OutOfScopeError, BudgetExceededError):
        return None
    headers = {name.lower(): value for name, value in response.headers.items()}
    aware = any(h.startswith("access-control-") for h in headers) or "origin" in headers.get("vary", "").lower()
    return headers.get("access-control-allow-origin", ""), headers.get("access-control-allow-credentials", "").lower(), aware


def _cors_bypass_origins(request: HttpRequest) -> list[tuple[str, str]]:
    """(origin, why) pairs that are attacker-controllable yet trick common naive Origin checks."""
    host = (urlsplit(request.url).hostname or "").lower()
    reg = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    return [
        ("null", "null origin trusted (exploitable from a sandboxed iframe)"),
        (f"https://{host}.{_CORS_ATTACK_SUFFIX}", "target host as a prefix (naive startsWith/regex)"),
        (f"https://{reg}.{_CORS_ATTACK_SUFFIX}", "target domain as a subdomain of an attacker domain (substring match)"),
        (f"https://dcattacker-{reg}", "attacker domain ending in the target (naive endsWith)"),
    ]


def _cors_finding(
    request: HttpRequest, rule_id: str, name: str, origin: str, with_creds: bool, why: str
) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"{rule_id}:{request.method}:{path}",
        rule_id=rule_id,
        name=name,
        severity="high" if with_creds else "medium",  # credentials => a real cross-account read
        cwe="CWE-942",
        owasp="WSTG-CLNT-07",
        family="cors",
        injection_point=_point(request, "header", "Origin"),
        evidence=[Evidence(
            type="reflected",
            data=(f"Origin {origin} was reflected in Access-Control-Allow-Origin"
                  + (" with Access-Control-Allow-Credentials: true" if with_creds else " (no credentials)")
                  + f" — {why}")[:240],
            confidence="high",
        )],
        request=request.model_copy(update={"headers": {**request.headers, "Origin": origin}}),
        response=HttpResponse(status_code=200, url=request.url),
        remediation=(
            "Valida el Origin contra un allowlist **exacto** de orígenes de confianza (comparación de "
            "igualdad, no prefijo/sufijo/substring/regex). Nunca reflejes un Origin arbitrario ni `null`, "
            "y nunca combines reflexión de Origin con Access-Control-Allow-Credentials: true."
        ),
    )


async def check_cors_reflection(client: HttpClient, request: HttpRequest) -> list[Finding]:
    """Flag CORS misconfigurations: an arbitrary/`null`/attacker-controllable Origin reflected in ACAO
    (highest impact with credentials). Bypass probes only run on CORS-aware endpoints, so a non-CORS
    endpoint still costs a single probe."""
    arb = await _cors_probe(client, request, _CORS_PROBE_ORIGIN)
    if arb is None:
        return []
    acao, acac, aware = arb
    with_creds = acac == "true"

    # 1) Arbitrary origin reflected → the fully-open case (unchanged rule id, highest signal).
    if acao == _CORS_PROBE_ORIGIN:
        return [_cors_finding(
            request, "active-cors-reflected-origin",
            "CORS misconfiguration: arbitrary origin reflected"
            + (" with credentials" if with_creds else ""),
            _CORS_PROBE_ORIGIN, with_creds, "any origin is reflected (fully open)",
        )]

    # Not doing dynamic per-origin CORS → nothing to bypass; keep cost at one probe for the common case.
    if not aware:
        return []

    # 2) CORS-aware endpoint → try null + prefix/suffix/substring bypasses (all attacker-controllable).
    for origin, why in _cors_bypass_origins(request):
        probed = await _cors_probe(client, request, origin)
        if probed is None:
            continue
        got_acao, got_acac, _ = probed
        if got_acao == origin:
            return [_cors_finding(
                request, "active-cors-origin-bypass",
                "CORS misconfiguration: attacker-controllable origin accepted (allowlist bypass)",
                origin, got_acac == "true", why,
            )]
    return []


async def probe_sensitive_files(client: HttpClient, target: str) -> list[Finding]:
    """Probe well-known sensitive paths at the target origin; confirm by content signature.

    Calibrates against a **catch-all** first: a host that serves 200 for a random path (a SPA that
    returns its ``index.html`` for every route) would otherwise false-positive on any sensitive path —
    e.g. an n8n login page contains the word "password", which matched the config-backup signature. A
    hit is only reported when the response genuinely differs from that random-path baseline.
    """
    parts = urlsplit(target)
    origin = f"{parts.scheme}://{parts.netloc}/"
    try:
        baseline = await client.get(urljoin(origin, "dc" + secrets.token_hex(12) + ".notreal"))
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return []
    catch_all = baseline.status_code == 200
    baseline_len = len(baseline.text or "")

    findings: list[Finding] = []
    for path, name, signature, severity in _SENSITIVE_FILES:
        url = urljoin(origin, path)
        try:
            response = await client.get(url)
        except (OutOfScopeError, BudgetExceededError):
            break
        if response.status_code != 200 or not re.search(signature, response.text):
            continue
        if catch_all:
            # The host answers 200 for garbage too. Skip if this response is the same generic page as
            # the random path (≈ same size), or if the signature already appears in that generic page —
            # either way the match proves nothing about the file existing.
            length = len(response.text or "")
            if abs(length - baseline_len) <= max(64, int(0.03 * max(length, baseline_len, 1))):
                continue
            if re.search(signature, baseline.text or ""):
                continue
        request = HttpRequest(method="GET", url=url)
        findings.append(
                Finding(
                    id=f"active-sensitive-file:{path}",
                    rule_id="active-sensitive-file",
                    name=name,
                    severity=severity,  # type: ignore[arg-type]
                    cwe="CWE-538",
                    owasp="WSTG-CONF-04",
                    injection_point=_point(request, "path", path),
                    evidence=[
                        Evidence(
                            type="response_match", data=f"{path} served (200) with matching content", confidence="high"
                        )
                    ],
                    request=request,
                    response=response,
                    remediation="Elimina o bloquea el acceso a este fichero desde el servidor web; no lo despliegues.",
                )
            )
    return findings


async def check_trace_method(client: HttpClient, target: str) -> list[Finding]:
    """Flag a server that honours HTTP TRACE and echoes the request (Cross-Site Tracing).

    Confirmed by the echo: a unique probe header sent on the TRACE request coming back in
    the response body means TRACE is enabled, which XST can abuse to read otherwise
    HttpOnly headers/cookies. No echo, no finding."""
    parts = urlsplit(target)
    origin = f"{parts.scheme}://{parts.netloc}/"
    try:
        response = await client.request("TRACE", origin, headers={"X-Dastcore-XST": _XST_PROBE})
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return []
    if response.status_code != 200 or _XST_PROBE not in response.text:
        return []
    request = HttpRequest(method="TRACE", url=origin, headers={"X-Dastcore-XST": _XST_PROBE})
    return [
        Finding(
            id=f"active-trace-method:{parts.netloc}",
            rule_id="active-trace-method",
            name="HTTP TRACE method enabled (Cross-Site Tracing)",
            severity="low",
            cwe="CWE-16",
            owasp="WSTG-CONF-06",
            family="xst",
            injection_point=_point(request, "header", "X-Dastcore-XST"),
            evidence=[
                Evidence(type="response_match", data="TRACE echoed the request (XST possible)", confidence="high")
            ],
            request=request,
            response=response,
            remediation="Deshabilita el método TRACE (y TRACK) en el servidor/proxy; no es necesario en producción.",
        )
    ]


_DANGEROUS_METHODS = ("PUT", "DELETE", "PATCH", "CONNECT", "TRACK")


async def check_dangerous_methods(client: HttpClient, target: str) -> list[Finding]:
    """Flag write/dangerous HTTP methods advertised in the OPTIONS `Allow` header.

    A safe, read-only probe (a single OPTIONS): if the server advertises PUT/DELETE/PATCH
    (or CONNECT/TRACK), those state-changing methods are reachable and worth reviewing for
    missing authorization. Reported low — it confirms exposure, not exploitability."""
    parts = urlsplit(target)
    origin = f"{parts.scheme}://{parts.netloc}/"
    try:
        response = await client.request("OPTIONS", origin)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return []
    allow = next((value for name, value in response.headers.items() if name.lower() == "allow"), "")
    advertised = [m for m in _DANGEROUS_METHODS if re.search(rf"\b{m}\b", allow, re.IGNORECASE)]
    if not advertised:
        return []
    request = HttpRequest(method="OPTIONS", url=origin)
    return [
        Finding(
            id=f"active-dangerous-methods:{parts.netloc}",
            rule_id="active-dangerous-methods",
            name=f"Dangerous HTTP methods enabled: {', '.join(advertised)}",
            severity="low",
            cwe="CWE-749",
            owasp="WSTG-CONF-06",
            family="http_methods",
            injection_point=_point(request, "header", "Allow"),
            evidence=[
                Evidence(type="response_match", data=f"OPTIONS Allow advertises: {allow.strip()}", confidence="high")
            ],
            request=request,
            response=response,
            remediation=(
                "Disable HTTP methods the application does not use (PUT/DELETE/PATCH/CONNECT/TRACK) at "
                "the server or proxy, and enforce authorization on any write method you do expose."
            ),
        )
    ]


async def check_graphql_introspection(client: HttpClient, endpoint_url: str) -> list[Finding]:
    """Flag a GraphQL endpoint that has introspection enabled (info disclosure)."""
    schema = await introspect(client, endpoint_url)
    if schema is None:
        return []
    request = HttpRequest(method="POST", url=endpoint_url, json_body={"query": "{__schema{types{name}}}"})
    response = HttpResponse(status_code=200, url=endpoint_url)
    return [
        Finding(
            id="active-graphql-introspection",
            rule_id="active-graphql-introspection",
            name="GraphQL introspection enabled",
            severity="low",
            cwe="CWE-200",
            owasp="WSTG-APIT-01",
            injection_point=_point(request, "body", "query"),
            evidence=[Evidence(type="status", data="introspection query returned the full schema", confidence="high")],
            request=request,
            response=response,
            remediation="Deshabilita la introspección de GraphQL en producción para no exponer el esquema completo.",
        )
    ]
