"""DNS record enrichment — the records behind a hostname, and the hostnames behind an IP range.

Subdomain discovery answers "what hosts exist"; this answers "what does each host's DNS actually say".
Two complementary capabilities:

- **Record enrichment** — for a known host, resolve its ``A``/``AAAA``/``CNAME``/``MX``/``TXT``/``NS``/``SOA``
  records. The ``CNAME`` is the highest-value one for us: a dangling ``CNAME`` to an unclaimed third-party
  service is the textbook subdomain-takeover signal, so these records feed ``detectors/takeover.py``
  directly. ``MX``/``TXT`` reveal the mail/SaaS providers an org uses; ``NS`` reveals its DNS host.
- **Reverse (PTR) sweep** — a bug-bounty scope often includes a CIDR range (``ScopeChecker`` already
  understands it). Reverse-resolving each IP in an in-scope range turns ``10.0.0.0/24`` into the real
  hostnames living there — surface a pure forward brute force never sees.

Everything is **best-effort and fail-open** (a resolver that is down or missing returns nothing, never
raises) and **scope-gated by the caller** — a PTR hostname is dropped unless it is in scope. The record
resolver is injectable, so the whole module is unit-testable offline with no network and no ``dnspython``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field

# A record resolver maps (host, rrtype) -> the record values. Best-effort: an empty list means
# "no such record / couldn't resolve", never an error.
RecordResolver = Callable[[str, str], Awaitable[list[str]]]
# A PTR resolver maps an IP -> the hostnames it reverse-resolves to (best-effort, may be empty).
PtrResolver = Callable[[str], Awaitable[list[str]]]

_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA")
_DQUOTE = '"'


def _norm_host(value: str) -> str:
    return value.strip().lower().lstrip("*.").rstrip(".")


@dataclass
class RecordSet:
    """The DNS records resolved for one hostname. Empty lists = no record of that type (or unresolved)."""

    host: str
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    soa: list[str] = field(default_factory=list)

    @property
    def resolves(self) -> bool:
        """Whether the host itself points anywhere (has an address or a CNAME)."""
        return bool(self.a or self.aaaa or self.cname)


async def _default_record_resolver(host: str, rrtype: str) -> list[str]:
    """Resolve one record type via ``dnspython`` if installed; return [] on any failure (fail-open).

    ``dnspython`` is an optional dependency (``pip install dastcore[recon]``). Without it this module
    still runs — record enrichment simply returns nothing, and the PTR sweep falls back to the stdlib.
    """

    def _query() -> list[str]:
        try:
            import dns.resolver  # type: ignore[import-untyped]
        except ImportError:
            return []
        try:
            answers = dns.resolver.resolve(host, rrtype, lifetime=8.0)
        except Exception:  # noqa: BLE001 — NXDOMAIN/NoAnswer/timeout: no records for this type
            return []
        values: list[str] = []
        for rdata in answers:
            text = rdata.to_text().strip()
            if rrtype == "MX":  # "10 mail.example.com." -> the mail host
                text = text.split()[-1].rstrip(".").lower()
            elif rrtype in ("NS", "CNAME", "SOA"):  # end with a trailing dot; SOA is "ns admin ..."
                text = text.split()[0].rstrip(".").lower()
            values.append(text.strip(_DQUOTE))
        return values

    return await asyncio.to_thread(_query)


async def gather_records(
    host: str, *, resolver: RecordResolver | None = None, types: Iterable[str] = _RECORD_TYPES
) -> RecordSet:
    """Resolve the requested record types for ``host`` concurrently into a ``RecordSet``."""
    host = _norm_host(host)
    record_set = RecordSet(host=host)
    if not host:
        return record_set
    resolve = resolver or _default_record_resolver
    wanted = [t.upper() for t in types]
    results = await asyncio.gather(*(resolve(host, rrtype) for rrtype in wanted), return_exceptions=True)
    for rrtype, result in zip(wanted, results, strict=True):
        if not isinstance(result, list):
            continue
        values = [str(v).strip() for v in result if str(v).strip()]
        setattr(record_set, rrtype.lower(), values)
    return record_set


async def gather_dns_records(
    hosts: Iterable[str], *, resolver: RecordResolver | None = None, concurrency: int = 20
) -> dict[str, RecordSet]:
    """Resolve records for many hosts concurrently. Keyed by normalised host; deduped."""
    unique = sorted({_norm_host(h) for h in hosts if _norm_host(h)})
    if not unique:
        return {}
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def _one(host: str) -> tuple[str, RecordSet]:
        async with semaphore:
            return host, await gather_records(host, resolver=resolver)

    return dict(await asyncio.gather(*(_one(h) for h in unique)))


def cname_map(records: dict[str, RecordSet]) -> dict[str, str]:
    """host -> its first CNAME target, for the hosts that have one (feeds takeover detection)."""
    return {host: rs.cname[0] for host, rs in records.items() if rs.cname}


# ── Reverse (PTR) sweep ─────────────────────────────────────────────────────────────────────────────


async def _default_ptr_resolver(ip: str) -> list[str]:
    """Reverse-resolve an IP to hostnames via the stdlib (works with no ``dnspython``). Fail-open."""

    def _query() -> list[str]:
        try:
            name, aliases, _ = socket.gethostbyaddr(ip)
        except (OSError, UnicodeError):
            return []
        return [name, *aliases]

    return await asyncio.to_thread(_query)


def _iter_scope_ips(cidrs: Iterable[str], *, max_hosts: int) -> list[str]:
    """Every host IP in the given CIDRs (host addresses only), capped at ``max_hosts`` total."""
    out: list[str] = []
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            continue
        # ``.hosts()`` skips network/broadcast; a /32 or /31 still yields its address(es).
        addresses = network.hosts() if network.num_addresses > 2 else iter(network)
        for address in addresses:
            out.append(str(address))
            if len(out) >= max_hosts:
                return out
    return out


async def ptr_sweep(
    cidrs: Iterable[str],
    in_scope: Callable[[str], bool],
    *,
    resolver: PtrResolver | None = None,
    max_hosts: int = 1024,
    concurrency: int = 64,
) -> set[str]:
    """Reverse-resolve the in-scope IPs of ``cidrs`` and return the hostnames that are themselves in scope.

    ``in_scope`` gates twice: an IP is only probed if it is in scope, and a discovered hostname is only
    kept if it is in scope too — a PTR record can point anywhere, and we never wander out of scope.
    """
    ips = [ip for ip in _iter_scope_ips(cidrs, max_hosts=max_hosts) if in_scope(ip)]
    if not ips:
        return set()
    resolve = resolver or _default_ptr_resolver
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def _one(ip: str) -> list[str]:
        async with semaphore:
            try:
                return await resolve(ip)
            except Exception:  # noqa: BLE001 — one dead PTR must not abort the sweep
                return []

    hosts: set[str] = set()
    for names in await asyncio.gather(*(_one(ip) for ip in ips)):
        for name in names:
            host = _norm_host(name)
            if host and in_scope(host):
                hosts.add(host)
    return hosts
