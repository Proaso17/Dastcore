"""Virtual-host discovery — the apps a server hosts by ``Host`` header, not by DNS.

One IP often serves many sites, selected by the request's ``Host`` header. Some of those virtual hosts
are never published in DNS (internal tools, staging panels, a legacy site), so subdomain enumeration —
which only finds names that resolve — never sees them. This fuzzes the ``Host`` header against a known
live endpoint: send the same request with ``Host: candidate`` and keep the candidates that return a
*distinct* page from the server's default (calibrated against a random, certainly-nonexistent vhost, so
a catch-all that answers everything identically can't manufacture hits — the same zero-FP discipline as
content discovery).

**Scope stays absolute in two ways:** the URL requested is the in-scope target (so every request goes
through the scope-enforced :class:`HttpClient`), and each candidate ``Host`` value must itself pass
``is_asset_in_scope`` before it is ever sent — we only look for the *organisation's own* virtual hosts,
never someone else's. Discovered vhosts become scan roots (requested at the target URL with their Host).
"""

from __future__ import annotations

import asyncio
import secrets

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.discovery.subdomains import DiscoveredHost


def _same_page(a: HttpResponse, b: HttpResponse) -> bool:
    """Two responses that look like the same default page — same status and near-identical size."""
    if a.status_code != b.status_code:
        return False
    la, lb = len(a.text or ""), len(b.text or "")
    return abs(la - lb) <= max(64, int(0.03 * max(la, lb, 1)))


class VhostDiscoverer:
    """Fuzz the ``Host`` header at a live in-scope URL to find virtual hosts not published in DNS."""

    def __init__(
        self,
        client: HttpClient,
        *,
        candidates: list[str],
        concurrency: int = 20,
        timeout: float = 6.0,
    ) -> None:
        self._client = client
        # Only in-scope candidate hostnames are ever sent as a Host header (never a third-party name).
        self._candidates = [
            c for c in dict.fromkeys(h.strip().lower().lstrip("*.").rstrip(".") for h in candidates) if c
        ]
        self._concurrency = max(1, concurrency)
        self._timeout = timeout

    async def _fetch(self, base_url: str, host_header: str) -> HttpResponse | None:
        try:
            return await self._client.get(
                base_url, headers={"Host": host_header}, timeout=self._timeout, retries=0
            )
        except (OutOfScopeError, BudgetExceededError):
            return None
        except Exception:  # noqa: BLE001 — a dead vhost probe must not abort the sweep
            return None

    async def discover(self, base_url: str) -> list[DiscoveredHost]:
        """Return the in-scope virtual hosts the target serves that differ from its default page."""
        if not self._client.is_in_scope(base_url) or not self._candidates:
            return []

        # Baseline: a random, certainly-nonexistent vhost. Whatever the server returns for it is its
        # "default"/catch-all answer; a real vhost must differ from this.
        baseline = await self._fetch(base_url, f"dc{secrets.token_hex(10)}.example")
        if baseline is None:
            return []

        semaphore = asyncio.Semaphore(self._concurrency)

        async def _check(candidate: str) -> DiscoveredHost | None:
            if not self._client.is_asset_in_scope(candidate):  # scope-gate the Host value itself
                return None
            async with semaphore:
                resp = await self._fetch(base_url, candidate)
            if resp is None or _same_page(resp, baseline):
                return None
            return DiscoveredHost(host=candidate, url=base_url, status_code=resp.status_code, source="vhost")

        results = await asyncio.gather(*(_check(c) for c in self._candidates))
        found = {h.host: h for h in results if h is not None}
        return sorted(found.values(), key=lambda h: h.host)


def vhost_findings(base_url: str, found: list[DiscoveredHost]) -> list[Finding]:
    """One info finding per virtual host discovered by Host-header fuzzing (a lead to investigate)."""
    findings: list[Finding] = []
    for host in found:
        request = HttpRequest(method="GET", url=base_url, headers={"Host": host.host})
        point = InjectionPoint(location="header", name="Host", base_value=host.host, request_template=request)
        detail = (
            f"{base_url} serves a distinct virtual host for Host: {host.host} (status {host.status_code}) that "
            "is not published in DNS — an unlinked internal/staging site reachable only by its Host header."
        )
        findings.append(
            Finding(
                id=f"vhost:{host.host}",
                rule_id="virtual-host",
                name="Undisclosed virtual host",
                severity="info",
                cwe="CWE-200",
                owasp="WSTG-CONF-01",
                family="osint",
                injection_point=point,
                evidence=[Evidence(type="response_match", data=detail, confidence="high")],
                request=request,
                response=HttpResponse(status_code=host.status_code, url=base_url, text=detail),
                remediation=(
                    "Confirma que este virtual host deba estar accesible. Si es interno/staging, restríngelo "
                    "(red/allowlist/autenticación) en lugar de dejarlo servible por cabecera Host."
                ),
            )
        )
    return findings
