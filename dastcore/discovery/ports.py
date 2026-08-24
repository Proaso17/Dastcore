"""Port / service discovery — find the *other* HTTP services a host exposes.

Liveness probing only checks 80/443, but real targets serve apps on 8080, 8443, 3000, 5000, 8000,
9200 (Elasticsearch), 15672 (RabbitMQ UI)… each one a whole extra application the scanner never sees
unless someone types the port by hand. This connect-scans a curated set of common ports (native
asyncio, so it works with no external tool), then confirms which open ports actually speak HTTP and
turns each live one into a scan root.

**Native + accelerated:** the built-in scanner is a TCP connect scan (no raw sockets, no privileges).
When ``naabu`` is installed it can front this via ``recon/adapters.py`` for speed; the native path is
the always-available fallback.

**Scope is absolute.** A port is only scanned when ``host:port`` is in scope, and every HTTP probe goes
through the shared :class:`HttpClient` (whose ``ScopeChecker`` also enforces ``allowed_ports``), so a
scope that restricts ports drops the others automatically. The connector is injectable for offline tests.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from dastcore.core.http_client import HttpClient, OutOfScopeError

# A connector returns True if a TCP connection to (host, port) succeeds within the timeout. Injectable.
Connector = Callable[[str, int, float], Awaitable[bool]]

# Curated common web/app/service ports — high signal, kept small so a multi-host sweep stays bounded.
TOP_PORTS: tuple[int, ...] = (
    80, 443, 81, 300, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095, 2096, 2480, 3000, 3128, 3333,
    4243, 4443, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5280, 5281, 5601, 5800, 6543, 7000, 7001,
    7396, 7474, 8000, 8001, 8008, 8014, 8042, 8060, 8069, 8080, 8081, 8083, 8088, 8090, 8091, 8095,
    8118, 8123, 8172, 8181, 8222, 8243, 8280, 8281, 8333, 8337, 8443, 8500, 8834, 8880, 8888, 8983,
    9000, 9001, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9500, 9800, 9981, 10000, 11371, 12443,
    15672, 16080, 18091, 18092, 20720, 32000, 55440, 55672,
)

# Ports we try HTTPS on first (everything else is tried HTTP first). 80/8080/etc. -> http.
_TLS_PORTS: frozenset[int] = frozenset(
    {443, 832, 981, 1311, 2083, 2087, 2096, 4443, 4993, 8172, 8243, 8333, 8443, 8834, 9043, 9443, 12443}
)


async def _default_connector(host: str, port: int, timeout: float) -> bool:
    """A TCP connect probe: open a connection and close it. Open = the port answered."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (TimeoutError, OSError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except (TimeoutError, OSError):
        pass
    return True


async def scan_ports(
    host: str,
    ports: tuple[int, ...] | list[int] = TOP_PORTS,
    *,
    connector: Connector | None = None,
    concurrency: int = 200,
    timeout: float = 1.5,
) -> list[int]:
    """Connect-scan ``host`` and return the sorted list of open ports. Fail-open per port."""
    host = host.strip().lower().rstrip(".")
    if not host:
        return []
    connect = connector or _default_connector
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def _one(port: int) -> int | None:
        async with semaphore:
            try:
                return port if await connect(host, port, timeout) else None
            except Exception:  # noqa: BLE001 — one probe failing must not abort the sweep
                return None

    results = await asyncio.gather(*(_one(p) for p in dict.fromkeys(ports)))
    return sorted(p for p in results if p is not None)


def _candidate_url(host: str, port: int) -> str:
    """The URL to try for an open port: HTTPS-first for TLS ports, plus the scheme's default port stays bare."""
    if port in _TLS_PORTS or port == 443:
        return f"https://{host}/" if port == 443 else f"https://{host}:{port}/"
    return f"http://{host}/" if port == 80 else f"http://{host}:{port}/"


async def discover_http_ports(
    client: HttpClient,
    host: str,
    *,
    ports: tuple[int, ...] | list[int] = TOP_PORTS,
    connector: Connector | None = None,
) -> list[str]:
    """Scan ``host``'s ports and return the root URLs of the ones that answer HTTP, in scope.

    Each open port becomes a candidate root URL (HTTPS for TLS ports, HTTP otherwise); a URL is kept
    only if it is in scope and the shared client actually gets an HTTP response from it. The result is
    ready to hand to the crawler as additional scan roots.
    """
    open_ports = await scan_ports(host, ports, connector=connector)
    roots: list[str] = []
    for port in open_ports:
        url = _candidate_url(host, port)
        if not client.is_in_scope(url):
            continue
        try:
            resp = await client.get(url, timeout=6.0, retries=0)
        except OutOfScopeError:
            continue
        except Exception:  # noqa: BLE001 — a port that opens TCP but isn't HTTP is simply skipped
            continue
        if resp is not None and resp.status_code > 0:
            roots.append(url)
    return roots
