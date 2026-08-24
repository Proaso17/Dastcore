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
from dastcore.discovery.dns_records import RecordSet

# CNAME target patterns -> the takeover-able service they belong to. A CNAME to one of these whose own
# target does NOT resolve (dangling) is a high-confidence takeover, independent of the body fingerprint.
_CNAME_SERVICES: list[tuple[str, re.Pattern[str]]] = [
    ("GitHub Pages", re.compile(r"\.github\.io$", re.IGNORECASE)),
    ("AWS S3", re.compile(r"\.s3[.-][a-z0-9-]*\.amazonaws\.com$|\.s3\.amazonaws\.com$", re.IGNORECASE)),
    ("AWS CloudFront", re.compile(r"\.cloudfront\.net$", re.IGNORECASE)),
    ("Heroku", re.compile(r"\.heroku(?:app|dns|ssl)\.com$", re.IGNORECASE)),
    ("Azure", re.compile(r"\.(?:azurewebsites|cloudapp|trafficmanager|blob\.core\.windows)\.net$", re.IGNORECASE)),
    ("Fastly", re.compile(r"\.fastly\.net$", re.IGNORECASE)),
    ("Shopify", re.compile(r"\.myshopify\.com$", re.IGNORECASE)),
    ("Pantheon", re.compile(r"\.pantheonsite\.io$", re.IGNORECASE)),
    ("Ghost", re.compile(r"\.ghost\.io$", re.IGNORECASE)),
    ("Surge.sh", re.compile(r"\.surge\.sh$", re.IGNORECASE)),
    ("Zendesk", re.compile(r"\.zendesk\.com$", re.IGNORECASE)),
    ("Readme.io", re.compile(r"\.readme\.io$", re.IGNORECASE)),
    ("Netlify", re.compile(r"\.netlify\.(?:app|com)$", re.IGNORECASE)),
]

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


def _cname_service(cname: str) -> str | None:
    """The takeover-able service a CNAME target belongs to (GitHub Pages, S3…), or None."""
    target = cname.strip().lower().rstrip(".")
    for service, pattern in _CNAME_SERVICES:
        if pattern.search(target):
            return service
    return None


def _finding(host: str, origin: str, service: str, evidence: str, response: HttpResponse | None) -> Finding:
    request = HttpRequest(method="GET", url=origin + "/")
    # The dangling-CNAME path has no HTTP response (the proof is the DNS record itself); record a
    # synthetic response carrying the DNS evidence so the finding still serialises.
    response = response or HttpResponse(status_code=0, url=origin + "/", text=evidence)
    return Finding(
        id=f"subdomain-takeover:{host}:{service}",
        rule_id="subdomain-takeover",
        name=f"Possible subdomain takeover ({service})",
        severity="high",
        cwe="CWE-284",
        owasp="WSTG-CONF-10",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N",
        family="takeover",
        injection_point=_point(request),
        evidence=[Evidence(type="response_match", data=evidence, confidence="high")],
        request=request,
        response=response,
        remediation=(
            "Elimina el registro DNS colgante (CNAME/ALIAS) que apunta al servicio de terceros, o "
            "reclama el recurso en ese proveedor. Audita periódicamente los DNS en busca de destinos "
            "no reclamados."
        ),
    )


async def run_subdomain_takeover_check(
    client: HttpClient,
    target: str,
    requests: list[HttpRequest],
    *,
    dns_records: dict[str, RecordSet] | None = None,
) -> list[Finding]:
    """Fingerprint each in-scope host's root for an unclaimed-service takeover page.

    Two independent signals, either of which flags a host (once):

    - **Body fingerprint** — the host's root serves a provider's own "this isn't claimed" page. When
      DNS records are available, the host's dangling ``CNAME`` target is added to the evidence.
    - **Dangling CNAME** — the host ``CNAME``s to a takeover-able provider (``*.github.io``,
      ``*.s3.amazonaws.com``…) but that target no longer resolves. Requires ``dns_records`` and is a
      high-confidence takeover on its own, even when the provider serves no distinctive body.
    """
    findings: list[Finding] = []
    flagged: set[str] = set()
    records = dns_records or {}

    for origin in _hosts(target, requests):
        host = urlsplit(origin).netloc.split(":", 1)[0].lower()
        response = await _fetch_root(client, origin)
        if response is None:
            continue
        matched = next((svc for svc, pat in _FINGERPRINTS if pat.search(response.text)), None)
        if matched is None:
            continue
        cname = (records.get(host).cname[0] if records.get(host) and records[host].cname else "")
        detail = (
            f"{host} serves the unclaimed-resource page of {matched} — the DNS record points at a "
            "third-party service whose resource no longer exists, so an attacker can claim it and serve "
            "content from this host"
        )
        if cname:
            detail += f" (dangling CNAME -> {cname})"
        findings.append(_finding(host, origin, matched, detail, response))
        flagged.add(host)

    # Dangling-CNAME path: a CNAME to a takeover-able provider whose target no longer resolves. This
    # catches takeovers the body fingerprint misses (some providers serve a bare 404), using only DNS.
    for host, record_set in records.items():
        if host in flagged or not record_set.cname:
            continue
        cname = record_set.cname[0]
        service = _cname_service(cname)
        # Dangling = the host CNAMEs somewhere, but nothing ultimately resolves (no A/AAAA at the end).
        if service is None or record_set.a or record_set.aaaa:
            continue
        origin = f"https://{host}"
        detail = (
            f"{host} has a dangling CNAME to {cname} ({service}) that no longer resolves to any address "
            "— an attacker can register that resource on the provider and serve content from this host"
        )
        findings.append(_finding(host, origin, service, detail, None))
        flagged.add(host)

    return findings
