"""Passive subdomain sources — find a domain's hosts from public datasets without touching the target.

Brute force only finds hosts whose name you guessed; passive sources (certificate-transparency logs,
passive-DNS datasets, URL archives, the live TLS certificate's SANs) surface the *real* hostnames an
organisation has used — the single biggest coverage win in recon, and it generalises to any website.

Each source is **best-effort and fail-open**: a source that is down, rate-limited, or missing its API
key returns nothing and never breaks discovery. **Free** sources need no configuration; a few
**premium** sources activate only when their API key is present in the environment. Everything returned
here is still scope-gated and DNS/HTTP-validated by the caller before a single request hits the target,
so a passive hit that doesn't resolve or answer is simply dropped (zero false hosts).

Env vars for the optional premium sources:
  SECURITYTRAILS_API_KEY · VIRUSTOTAL_API_KEY (or VT_API_KEY) · SHODAN_API_KEY
"""

from __future__ import annotations

import asyncio
import os
import re
import socket
import ssl
from collections.abc import Awaitable, Callable

import httpx

# A source maps a registrable domain to the set of hostnames it knows about (any case, may be noisy).
HostSource = Callable[[str], Awaitable[set[str]]]

_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9](?:[a-z0-9-]{0,62}))+$")


def _norm(domain: str) -> str:
    return domain.strip().lower().lstrip("*.").rstrip(".")


def _keep_for_domain(hosts: set[str], domain: str) -> set[str]:
    """Lowercase, strip wildcards, and keep only real hostnames under ``domain`` (or the apex itself)."""
    domain = _norm(domain)
    out: set[str] = set()
    for raw in hosts:
        host = _norm(raw)
        if not host or "*" in host or " " in host:
            continue
        if (host == domain or host.endswith("." + domain)) and _HOST_RE.match(host):
            out.add(host)
    return out


async def _get(url: str, *, timeout: float, headers: dict[str, str] | None = None) -> httpx.Response | None:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
            return await client.get(url)
    except (httpx.HTTPError, OSError):
        return None


# ── Free sources (no API key) ─────────────────────────────────────────────────────────────────────


async def crtsh(domain: str, *, timeout: float = 20.0) -> set[str]:
    """Certificate-transparency log (crt.sh): every cert name issued for ``%.domain``."""
    resp = await _get(f"https://crt.sh/?q=%25.{_norm(domain)}&output=json", timeout=timeout)
    if resp is None:
        return set()
    hosts: set[str] = set()
    try:
        for row in resp.json():
            for name in str(row.get("name_value", "")).splitlines():
                hosts.add(name)
    except (ValueError, AttributeError, TypeError):
        return set()
    return hosts


async def alienvault_otx(domain: str, *, timeout: float = 15.0) -> set[str]:
    """AlienVault OTX passive DNS — hostnames that have resolved to/under the domain."""
    resp = await _get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{_norm(domain)}/passive_dns", timeout=timeout
    )
    if resp is None:
        return set()
    try:
        return {str(row.get("hostname", "")) for row in resp.json().get("passive_dns", [])}
    except (ValueError, AttributeError, TypeError):
        return set()


async def hackertarget(domain: str, *, timeout: float = 15.0) -> set[str]:
    """HackerTarget hostsearch — "host,ip" lines (free, IP-rate-limited)."""
    resp = await _get(f"https://api.hackertarget.com/hostsearch/?q={_norm(domain)}", timeout=timeout)
    if resp is None or "API count exceeded" in resp.text or "error" in resp.text.lower():
        return set()
    return {line.split(",", 1)[0] for line in resp.text.splitlines() if "," in line}


async def rapiddns(domain: str, *, timeout: float = 15.0) -> set[str]:
    """RapidDNS subdomain table — scrape the hostnames out of the HTML rows."""
    resp = await _get(f"https://rapiddns.io/subdomain/{_norm(domain)}?full=1", timeout=timeout)
    if resp is None:
        return set()
    return set(re.findall(rf"[a-z0-9][a-z0-9.-]*\.{re.escape(_norm(domain))}", resp.text, re.IGNORECASE))


async def anubis(domain: str, *, timeout: float = 15.0) -> set[str]:
    """Anubis (jldc.me) aggregated subdomain DB — a JSON list of hostnames."""
    resp = await _get(f"https://jldc.me/anubis/subdomains/{_norm(domain)}", timeout=timeout)
    if resp is None:
        return set()
    try:
        return {str(h) for h in resp.json()}
    except (ValueError, TypeError):
        return set()


async def urlscan(domain: str, *, timeout: float = 15.0) -> set[str]:
    """urlscan.io search — the page/task domains seen for the target (free, rate-limited)."""
    resp = await _get(f"https://urlscan.io/api/v1/search/?q=domain:{_norm(domain)}&size=1000", timeout=timeout)
    if resp is None:
        return set()
    hosts: set[str] = set()
    try:
        for row in resp.json().get("results", []):
            page = row.get("page") or {}
            task = row.get("task") or {}
            hosts.add(str(page.get("domain", "")))
            hosts.add(str(task.get("domain", "")))
    except (ValueError, AttributeError, TypeError):
        return set()
    return hosts


def _cert_sans_sync(domain: str, *, timeout: float) -> set[str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we only want to read the SANs, not trust the chain
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                der = tls.getpeercert(binary_form=True)
        if not der:
            return set()
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        cert = x509.load_der_x509_certificate(der)
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return set(san.value.get_values_for_type(x509.DNSName))
    except Exception:  # noqa: BLE001 — TLS/parse failure or missing cryptography: just no SANs
        return set()


async def cert_sans(domain: str, *, timeout: float = 8.0) -> set[str]:
    """The live TLS certificate's Subject Alternative Names — sibling hostnames sharing the cert."""
    return await asyncio.to_thread(_cert_sans_sync, _norm(domain), timeout=timeout)


# ── Premium sources (activate when their API key is in the environment) ─────────────────────────────


async def securitytrails(domain: str, *, timeout: float = 15.0) -> set[str]:
    key = os.environ.get("SECURITYTRAILS_API_KEY", "").strip()
    if not key:
        return set()
    domain = _norm(domain)
    resp = await _get(
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false",
        timeout=timeout, headers={"APIKEY": key},
    )
    if resp is None:
        return set()
    try:
        return {f"{sub}.{domain}" for sub in resp.json().get("subdomains", [])}
    except (ValueError, AttributeError, TypeError):
        return set()


async def virustotal(domain: str, *, timeout: float = 15.0) -> set[str]:
    key = (os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY") or "").strip()
    if not key:
        return set()
    resp = await _get(
        f"https://www.virustotal.com/api/v3/domains/{_norm(domain)}/subdomains?limit=1000",
        timeout=timeout, headers={"x-apikey": key},
    )
    if resp is None:
        return set()
    try:
        return {str(row.get("id", "")) for row in resp.json().get("data", [])}
    except (ValueError, AttributeError, TypeError):
        return set()


async def shodan(domain: str, *, timeout: float = 15.0) -> set[str]:
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not key:
        return set()
    domain = _norm(domain)
    resp = await _get(f"https://api.shodan.io/dns/domain/{domain}?key={key}", timeout=timeout)
    if resp is None:
        return set()
    try:
        return {f"{sub}.{domain}" if sub else domain for sub in resp.json().get("subdomains", [])}
    except (ValueError, AttributeError, TypeError):
        return set()


FREE_SOURCES: list[HostSource] = [crtsh, alienvault_otx, hackertarget, rapiddns, anubis, urlscan, cert_sans]
PREMIUM_SOURCES: list[HostSource] = [securitytrails, virustotal, shodan]
ALL_SOURCES: list[HostSource] = FREE_SOURCES + PREMIUM_SOURCES


async def gather_passive_subdomains(
    domain: str, *, sources: list[HostSource] | None = None
) -> set[str]:
    """Run every source concurrently and return the deduped, scope-normalised union of hostnames.

    Fail-open: each source is independent, so one being down or rate-limited never blocks the others.
    Premium sources without their API key simply contribute nothing.
    """
    domain = _norm(domain)
    if not domain:
        return set()
    chosen = sources if sources is not None else ALL_SOURCES
    results = await asyncio.gather(*(src(domain) for src in chosen), return_exceptions=True)
    union: set[str] = set()
    for res in results:
        if isinstance(res, set):
            union |= res
    return _keep_for_domain(union, domain)
