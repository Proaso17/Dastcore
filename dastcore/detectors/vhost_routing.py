"""Host-header routing to an internal/alternate virtual host. CWE-284 / OWASP A01:2021.

An edge (CDN, reverse proxy, load balancer) usually routes to a backend by the ``Host`` header. If it
routes to an internal-only vhost when asked for it — while the connection still goes to the same public
IP — an attacker reaches an app that was never meant to be public (an admin console, a staging build,
the origin's default vhost) just by changing the ``Host`` header.

False-positive-free differential with a bogus-host guard:

1. baseline = the target with its legitimate ``Host`` (the public app);
2. for an internal-sounding host name (``admin``, ``internal``, ``localhost`` …) the response must be
   ``2xx`` and **differ from the baseline** (a distinct app, not the public one);
3. it must also **differ from a random bogus host** — so an edge that serves one generic default (or
   error) for *any* unknown host can't trip it; only a name that routes somewhere specific does.

The hit is reproduced. The connection only ever targets the in-scope host; just the ``Host`` header
changes.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.validation.baseline import similarity_ratio

_DIFF = 0.9  # responses below this similarity are "different"
_MAX_ROOTS = 5

# Internal/privileged host names that should not be reachable from the public edge.
_GENERIC_INTERNAL = (
    "localhost",
    "internal",
    "intranet",
    "admin",
    "staging",
    "backend",
    "management",
    "console",
    "api-internal",
)


async def _get(client: HttpClient, url: str, headers: dict[str, str] | None) -> HttpResponse | None:
    try:
        return await client.request("GET", url, headers=headers or None)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _registrable(host: str) -> str:
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _candidates(root_url: str) -> list[str]:
    host = urlsplit(root_url).hostname or ""
    reg = _registrable(host)
    cands = list(_GENERIC_INTERNAL)
    if reg and "." in reg:
        cands += [f"admin.{reg}", f"internal.{reg}", f"staging.{reg}"]
    return cands


def _reached_distinct(resp: HttpResponse | None, baseline: HttpResponse, bogus: HttpResponse | None) -> bool:
    if resp is None or not (200 <= resp.status_code < 300):
        return False
    if similarity_ratio(resp.text, baseline.text) >= _DIFF:
        return False  # same as the public app -> not a distinct vhost
    if bogus is not None and similarity_ratio(resp.text, bogus.text) >= _DIFF:
        return False  # same as the generic default-for-any-host -> not specific routing
    return True


def _finding(root_url: str, host: str, response: HttpResponse) -> Finding:
    request = HttpRequest(method="GET", url=root_url, headers={"Host": host})
    return Finding(
        id=f"vhost-routing:{urlsplit(root_url).netloc}:{host}",
        rule_id="vhost-routing",
        name="Enrutado por Host a un vhost interno/alternativo",
        severity="medium",
        cwe="CWE-284",
        owasp="A01:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        family="access_bypass",
        injection_point=InjectionPoint(location="header", name="Host", base_value=host, request_template=request),
        evidence=[
            Evidence(
                type="differential",
                data=(
                    f"con 'Host: {host}' el borde enruta a una app 2xx distinta de la pública y distinta de un "
                    f"host inexistente de control → se alcanza un vhost interno/alternativo cambiando solo la "
                    "cabecera Host (la conexión sigue yendo al host público autorizado)"
                )[:220],
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "No enrutes a vhosts internos desde el edge público: usa una allowlist de Host esperados y "
            "responde 404/421 (Misdirected Request) a Hosts desconocidos. No confíes en `Host`/"
            "`X-Forwarded-Host` para decidir a qué backend/app servir."
        ),
    )


async def check_vhost_routing(client: HttpClient, root_url: str) -> Finding | None:
    """Probe one root for a Host name that routes to a distinct internal vhost."""
    baseline = await _get(client, root_url, None)
    if baseline is None or baseline.status_code >= 500:
        return None
    bogus = await _get(client, root_url, {"Host": "dcvhost" + secrets.token_hex(4) + ".invalid"})
    for host in _candidates(root_url):
        resp = await _get(client, root_url, {"Host": host})
        if not _reached_distinct(resp, baseline, bogus):
            continue
        repro = await _get(client, root_url, {"Host": host})
        if not _reached_distinct(repro, baseline, bogus):
            continue
        return _finding(root_url, host, resp)  # type: ignore[arg-type]
    return None


async def run_vhost_routing_checks(client: HttpClient, roots: list[str]) -> list[Finding]:
    """Test each scanned root for Host-header routing to an internal/alternate vhost."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for root in roots:
        netloc = urlsplit(root).netloc
        if netloc in seen:
            continue
        seen.add(netloc)
        if len(seen) > _MAX_ROOTS:
            break
        found = await check_vhost_routing(client, root)
        if found is not None:
            findings.append(found)
    return findings
