"""Active checks that don't fit the generic per-parameter rule engine.

These craft specific requests (a forged Origin, probes for well-known sensitive
paths, a GraphQL introspection query) rather than fuzzing an injection point, so
they live here instead of as YAML rules.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.discovery.graphql import introspect

_CORS_PROBE_ORIGIN = "https://dastcore-cors-probe.evil"

# path -> (finding name, signature the body must match to confirm, severity)
_SENSITIVE_FILES: list[tuple[str, str, str, str]] = [
    (".env", "Exposed .env file", r"(?im)^[A-Z0-9_]+\s*=", "high"),
    (".git/config", "Exposed .git repository", r"\[core\]|repositoryformatversion", "high"),
    (".git/HEAD", "Exposed .git repository", r"ref:\s*refs/", "high"),
    ("id_rsa", "Exposed private key", r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY", "critical"),
    (".htpasswd", "Exposed .htpasswd", r":\$(?:apr1|2y|1)\$", "high"),
    ("config.php.bak", "Exposed PHP config backup", r"<\?php|\$db|password", "high"),
    (".DS_Store", "Exposed .DS_Store", r"Bud1|\x00\x00\x00", "low"),
]


def _point(request: HttpRequest, location: str, name: str) -> InjectionPoint:
    return InjectionPoint(location=location, name=name, base_value="", request_template=request)  # type: ignore[arg-type]


async def check_cors_reflection(client: HttpClient, request: HttpRequest) -> list[Finding]:
    """Send a forged Origin and flag a server that reflects it *with* credentials."""
    try:
        response = await client.request(
            request.method,
            request.url,
            params=request.params,
            headers={**request.headers, "Origin": _CORS_PROBE_ORIGIN},
            data=request.data,
            json=request.json_body,
        )
    except (OutOfScopeError, BudgetExceededError):
        return []

    headers = {name.lower(): value for name, value in response.headers.items()}
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == _CORS_PROBE_ORIGIN and acac == "true":
        path = urlsplit(request.url).path or "/"
        return [
            Finding(
                id=f"active-cors-reflected-origin:{request.method}:{path}",
                rule_id="active-cors-reflected-origin",
                name="CORS misconfiguration: arbitrary origin reflected with credentials",
                severity="high",
                cwe="CWE-942",
                owasp="WSTG-CLNT-07",
                family="cors",
                injection_point=_point(request, "header", "Origin"),
                evidence=[
                    Evidence(
                        type="reflected",
                        data=f"reflected Origin {_CORS_PROBE_ORIGIN} with Access-Control-Allow-Credentials: true",
                        confidence="high",
                    )
                ],
                request=request,
                response=response,
                remediation=(
                    "Nunca reflejes un Origin arbitrario con allow-credentials. Valida el Origin "
                    "contra un allowlist estricto de orígenes de confianza."
                ),
            )
        ]
    return []


async def probe_sensitive_files(client: HttpClient, target: str) -> list[Finding]:
    """Probe well-known sensitive paths at the target origin; confirm by content signature."""
    parts = urlsplit(target)
    origin = f"{parts.scheme}://{parts.netloc}/"
    findings: list[Finding] = []
    for path, name, signature, severity in _SENSITIVE_FILES:
        url = urljoin(origin, path)
        try:
            response = await client.get(url)
        except (OutOfScopeError, BudgetExceededError):
            break
        if response.status_code == 200 and re.search(signature, response.text):
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
