"""Active detector: hardcoded secrets in JavaScript bundles.

Front-end build pipelines routinely bake API keys and tokens straight into the shipped JS —
they're "in the browser anyway", so a cloud key or a server-side token ends up in a bundle any
visitor can download. The passive secret detector only sees responses the scan already made;
this one explicitly enumerates the ``.js`` assets discovered during the crawl, fetches each
once, and runs the same high-signal secret patterns over its contents.

False-positive-safe by construction: it reuses the deliberately specific credential formats
(fixed prefix + fixed shape — AWS `AKIA…`, Stripe `sk_live_…`, GitHub `ghp_…`, private keys),
so ordinary minified code doesn't match. The matched value is masked in the evidence.

CWE-615 (Information Exposure Through Comments/Code) / OWASP WSTG-CONF-06.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.detectors.secrets import find_secrets, mask_secret


def _is_js(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(".js") or path.endswith(".mjs")


def _point(request: HttpRequest) -> InjectionPoint:
    return InjectionPoint(location="body", name="-", base_value="", request_template=request)


async def _fetch(client: HttpClient, url: str) -> HttpResponse | None:
    try:
        return await client.request("GET", url)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


async def run_js_secret_scan(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Fetch each unique discovered ``.js`` asset and report high-signal secrets baked into it."""
    findings: list[Finding] = []
    seen_urls: set[str] = set()
    seen_findings: set[str] = set()
    for request in requests:
        url = request.url
        if not _is_js(url) or url in seen_urls:
            continue
        seen_urls.add(url)
        response = await _fetch(client, url)
        if response is None or response.status_code >= 400:
            continue
        js_request = HttpRequest(method="GET", url=url)
        path = urlsplit(url).path or "/"
        for label, value, severity in find_secrets(response.text):
            key = f"{path}:{label}"
            if key in seen_findings:
                continue
            seen_findings.add(key)
            findings.append(
                Finding(
                    id=f"js-secret-exposure:{label}:{path}",
                    rule_id="js-secret-exposure",
                    name=f"Hardcoded secret in JS bundle: {label}",
                    severity=severity,  # type: ignore[arg-type]
                    cwe="CWE-615",
                    owasp="WSTG-CONF-06",
                    family="secret",
                    injection_point=_point(js_request),
                    evidence=[
                        Evidence(
                            type="response_match",
                            data=f"{label} baked into {path}: {mask_secret(value)}",
                            confidence="high",
                        )
                    ],
                    request=js_request,
                    response=response,
                    remediation=(
                        "No incrustes secretos en el bundle del frontend: cualquier visitante lo descarga. "
                        "Mueve la credencial al backend (proxy la llamada), usa claves públicas/restringidas por "
                        "referrer donde aplique, y rota de inmediato la credencial filtrada."
                    ),
                )
            )
    return findings
