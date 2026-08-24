"""ASN / network-block intelligence — which autonomous system and IP ranges an organisation owns.

A single in-scope IP is a thread you can pull: the IP belongs to an ASN, and that ASN announces a set
of IP prefixes — the organisation's whole routed footprint. Knowing it turns "scan this host" into
"here is the network this host lives in", which is the top of the recon funnel for a wide bug-bounty
scope and the context that makes a PTR sweep or a port scan worth running.

**This module is intelligence, not a licence to scan.** It reports the ASN and its prefixes; it never
by itself sends traffic to those ranges. Whether any discovered prefix is actually swept/scanned is
still decided by the scan's scope gate (``ptr_sweep``/``discover_http_ports`` drop every out-of-scope
IP), so learning an org's ranges can never widen what dastcore is authorised to touch.

Data comes from **RIPEstat** (``stat.ripe.net``, public, no key). Each call is best-effort and fail-open,
and the JSON fetcher is injectable so the parsing is unit-testable offline.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# A JSON fetcher maps a RIPEstat data URL -> the parsed JSON dict, or None on any failure. Injectable.
JsonFetcher = Callable[[str], Awaitable[dict | None]]

_RIPESTAT = "https://stat.ripe.net/data"
_ASN_RE = re.compile(r"^(?:as)?(\d+)$", re.IGNORECASE)


def _norm_asn(value: str) -> str:
    """Normalise an ASN token to ``ASnnnn`` (accepts ``15169``, ``as15169``, ``AS15169``)."""
    match = _ASN_RE.match(value.strip())
    return f"AS{match.group(1)}" if match else ""


async def _default_fetcher(url: str) -> dict | None:
    import httpx

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(url)
        data = resp.json()
    except (httpx.HTTPError, OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


@dataclass
class NetworkInfo:
    """The ASN(s) and covering prefix RIPEstat reports for a single IP."""

    ip: str
    asns: list[str] = field(default_factory=list)
    prefix: str = ""


@dataclass
class AsnIntel:
    """An organisation's routed footprint: its ASNs, their holders, and every announced prefix."""

    asns: list[str] = field(default_factory=list)
    holders: dict[str, str] = field(default_factory=dict)  # ASN -> holder/description
    prefixes: list[str] = field(default_factory=list)  # every announced prefix across the ASNs


async def network_info(ip: str, *, fetcher: JsonFetcher | None = None) -> NetworkInfo | None:
    """The ASN(s) and prefix covering ``ip`` (RIPEstat ``network-info``). None if unavailable."""
    fetch = fetcher or _default_fetcher
    data = await fetch(f"{_RIPESTAT}/network-info/data.json?resource={ip.strip()}")
    payload = (data or {}).get("data") if isinstance(data, dict) else None
    if not isinstance(payload, dict):
        return None
    asns = [_norm_asn(str(a)) for a in payload.get("asns", []) if _norm_asn(str(a))]
    return NetworkInfo(ip=ip.strip(), asns=asns, prefix=str(payload.get("prefix", "")))


async def as_holder(asn: str, *, fetcher: JsonFetcher | None = None) -> str:
    """The holder/description of an ASN (RIPEstat ``as-overview``). Empty on failure."""
    asn = _norm_asn(asn)
    if not asn:
        return ""
    fetch = fetcher or _default_fetcher
    data = await fetch(f"{_RIPESTAT}/as-overview/data.json?resource={asn}")
    payload = (data or {}).get("data") if isinstance(data, dict) else None
    return str(payload.get("holder", "")) if isinstance(payload, dict) else ""


async def announced_prefixes(asn: str, *, fetcher: JsonFetcher | None = None) -> list[str]:
    """Every IPv4/IPv6 prefix an ASN announces (RIPEstat ``announced-prefixes``). Empty on failure."""
    asn = _norm_asn(asn)
    if not asn:
        return []
    fetch = fetcher or _default_fetcher
    data = await fetch(f"{_RIPESTAT}/announced-prefixes/data.json?resource={asn}")
    payload = (data or {}).get("data") if isinstance(data, dict) else None
    if not isinstance(payload, dict):
        return []
    prefixes: list[str] = []
    for row in payload.get("prefixes", []):
        if isinstance(row, dict) and row.get("prefix"):
            prefixes.append(str(row["prefix"]))
    return prefixes


async def gather_asn_intel(ips: list[str], *, fetcher: JsonFetcher | None = None) -> AsnIntel:
    """From seed IPs, resolve their ASN(s), each ASN's holder, and all announced prefixes.

    Purely informational: the returned prefixes are the org's routed ranges, surfaced for context and
    for an *optionally* scope-gated PTR/port sweep — never scanned by this function.
    """
    intel = AsnIntel()
    unique_ips = list(dict.fromkeys(ip.strip() for ip in ips if ip.strip()))
    if not unique_ips:
        return intel

    infos = await asyncio.gather(*(network_info(ip, fetcher=fetcher) for ip in unique_ips))
    asns: list[str] = []
    for info in infos:
        for asn in info.asns if info else []:
            if asn not in asns:
                asns.append(asn)
    intel.asns = asns

    holders = await asyncio.gather(*(as_holder(asn, fetcher=fetcher) for asn in asns))
    prefix_lists = await asyncio.gather(*(announced_prefixes(asn, fetcher=fetcher) for asn in asns))
    seen_prefixes: set[str] = set()
    for asn, holder, prefixes in zip(asns, holders, prefix_lists, strict=True):
        if holder:
            intel.holders[asn] = holder
        for prefix in prefixes:
            if prefix not in seen_prefixes:
                seen_prefixes.add(prefix)
                intel.prefixes.append(prefix)
    return intel


def asn_intel_findings(intel: AsnIntel, target: str) -> list[Finding]:
    """One info finding summarising the org's ASN footprint (context for the report; not a vuln)."""
    if not intel.asns:
        return []
    holders = ", ".join(f"{asn} ({intel.holders.get(asn, '?')})" for asn in intel.asns)
    detail = (
        f"Target resolves into {holders}. That ASN announces {len(intel.prefixes)} IP prefix(es): "
        f"{', '.join(intel.prefixes[:20])}{'…' if len(intel.prefixes) > 20 else ''}."
    )
    request = HttpRequest(method="GET", url=target)
    point = InjectionPoint(location="header", name="asn", base_value="", request_template=request)
    return [
        Finding(
            id=f"asn-footprint:{intel.asns[0]}",
            rule_id="asn-footprint",
            name="Autonomous-system footprint",
            severity="info",
            cwe="CWE-200",
            owasp="WSTG-INFO-01",
            family="osint",
            injection_point=point,
            evidence=[Evidence(type="response_match", data=detail, confidence="high")],
            request=request,
            response=HttpResponse(status_code=0, url=target, text=detail),
            remediation=(
                "Informativo: revisa que todos los prefijos/hosts del ASN que deban estar en el alcance "
                "de las pruebas estén cubiertos, y que no haya servicios expuestos inesperados en esos rangos."
            ),
        )
    ]
