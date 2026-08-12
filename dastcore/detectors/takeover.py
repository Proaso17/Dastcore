"""Passive detector: subdomain takeover (dangling DNS to an unclaimed service).

When a DNS record still points at a third-party service (GitHub Pages, S3, Heroku, Fastly…)
but the underlying resource was deleted, anyone can re-create it under that name and serve
content from the victim's subdomain. The tell is the provider's own "this isn't claimed" page.

This fetches the root of each in-scope host discovered during the scan and matches the body
against a curated set of **high-specificity provider fingerprints** — distinctive strings that
only appear on an unclaimed resource, so a live site or a generic 404 never matches. No
fingerprint, no finding.

CWE-284 (Improper Access Control) / OWASP WSTG-CONF-10 (Test for Subdomain Takeover).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# (service, fingerprint) — each string is unique to that provider's unclaimed-resource page.
_FINGERPRINTS: list[tuple[str, re.Pattern[str]]] = [
    ("GitHub Pages", re.compile(r"There isn't a GitHub Pages site here\.")),
    ("AWS S3", re.compile(r"<Code>NoSuchBucket</Code>|The specified bucket does not exist")),
    ("Heroku", re.compile(r"herokucdn\.com/error-pages/no-such-app\.html|No such app")),
    ("Fastly", re.compile(r"Fastly error: unknown domain")),
    ("Shopify", re.compile(r"Sorry, this shop is currently unavailable")),
    ("Bitbucket", re.compile(r"Repository not found — Bitbucket")),
    ("Ghost", re.compile(r"The thing you were looking for is no longer here")),
    ("Surge.sh", re.compile(r"project not found", re.IGNORECASE)),
    ("Pantheon", re.compile(r"The gods are wise, but do not know of the site which you seek")),
    ("Tumblr", re.compile(r"Whatever you were looking for doesn't currently exist at this address")),
    ("Zendesk", re.compile(r"Help Center Closed")),
    ("Readme.io", re.compile(r"Project doesnt exist\.\.\. yet!")),
]


def _hosts(target: str, requests: list[HttpRequest]) -> list[str]:
    """Unique ``scheme://netloc`` origins seen in the scan (target first), order-stable."""
    origins: list[str] = []
    for url in [target, *(r.url for r in requests)]:
        parts = urlsplit(url)
        if parts.scheme and parts.netloc:
            origin = f"{parts.scheme}://{parts.netloc}"
            if origin not in origins:
                origins.append(origin)
    return origins


def _point(request: HttpRequest) -> InjectionPoint:
    return InjectionPoint(location="header", name="Host", base_value="", request_template=request)


async def _fetch_root(client: HttpClient, origin: str) -> HttpResponse | None:
    try:
        return await client.request("GET", origin + "/")
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


async def run_subdomain_takeover_check(client: HttpClient, target: str, requests: list[HttpRequest]) -> list[Finding]:
    """Fingerprint each in-scope host's root for an unclaimed-service takeover page."""
    findings: list[Finding] = []
    for origin in _hosts(target, requests):
        response = await _fetch_root(client, origin)
        if response is None:
            continue
        for service, pattern in _FINGERPRINTS:
            if not pattern.search(response.text):
                continue
            host = urlsplit(origin).netloc
            request = HttpRequest(method="GET", url=origin + "/")
            findings.append(
                Finding(
                    id=f"subdomain-takeover:{host}:{service}",
                    rule_id="subdomain-takeover",
                    name=f"Possible subdomain takeover ({service})",
                    severity="high",
                    cwe="CWE-284",
                    owasp="WSTG-CONF-10",
                    cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N",
                    family="takeover",
                    injection_point=_point(request),
                    evidence=[
                        Evidence(
                            type="response_match",
                            data=(
                                f"{host} serves the unclaimed-resource page of {service} — the DNS record points "
                                "at a third-party service whose resource no longer exists, so an attacker can "
                                "claim it and serve content from this host"
                            ),
                            confidence="high",
                        )
                    ],
                    request=request,
                    response=response,
                    remediation=(
                        "Elimina el registro DNS colgante (CNAME/ALIAS) que apunta al servicio de terceros, o "
                        "reclama el recurso en ese proveedor. Audita periódicamente los DNS en busca de destinos "
                        "no reclamados."
                    ),
                )
            )
            break  # one takeover finding per host is enough
    return findings
