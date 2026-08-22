"""Subdomain discovery for the scan flow: find the *other* hosts of a target so vulnerabilities
get tested across the whole attack surface, not just the one URL you typed.

Sources, most to least safe:

- **Passive** — the crt.sh certificate-transparency log (no traffic to the target). Optional.
- **Native DNS brute force** — resolve ``word.domain`` for each word in a wordlist, with **wildcard-DNS
  calibration**: if a random name resolves, the domain answers everything, so DNS alone can't confirm a
  host and we fall back to comparing the HTTP homepage against a random-host baseline (zero false hosts).
- **External accelerators** — ``subfinder`` if it's on PATH (best-effort; skipped when absent).

**Scope is absolute.** Every candidate host must pass ``is_asset_in_scope`` before it is ever resolved or
probed, so discovery of ``admin.example.com`` only proceeds when the scan's scope actually covers it
(e.g. ``*.example.com`` / ``allow_subdomains``). Third-party domains are never touched.

``resolver`` and ``prober`` are injectable, so the whole thing is unit-testable offline.
"""

from __future__ import annotations

import asyncio
import secrets
import shutil
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from dastcore.core.http_client import HttpClient, OutOfScopeError
from dastcore.core.models import HttpResponse

_WORDLISTS = Path(__file__).parent / "wordlists"
_DEPTH_LIMITS: dict[str, int | None] = {"light": 50, "balanced": 250, "aggressive": None}
# How many levels of nested subdomains to recurse into (found host -> enumerate ITS subdomains).
_RECURSION: dict[str, int] = {"light": 0, "balanced": 1, "aggressive": 2}


def subdomain_recursion_depth(depth: str) -> int:
    return _RECURSION.get(depth, _RECURSION["aggressive"])


Resolver = Callable[[str], Awaitable[list[str]]]
# A prober returns (url, response) for a live host, or None if nothing answered.
Prober = Callable[[str], Awaitable[tuple[str, HttpResponse] | None]]


@dataclass(frozen=True)
class DiscoveredHost:
    host: str
    url: str
    status_code: int
    source: str = "discovery"


def load_subdomain_wordlist(depth: str = "aggressive", path: str | Path | None = None) -> list[str]:
    source = Path(path) if path else _WORDLISTS / "subdomains.txt"
    seen: set[str] = set()
    words: list[str] = []
    for line in source.read_text(encoding="utf-8", errors="ignore").splitlines():
        entry = line.strip().lower().lstrip("*.").rstrip(".")
        if entry and not line.lstrip().startswith("#") and entry not in seen:
            seen.add(entry)
            words.append(entry)
    limit = _DEPTH_LIMITS.get(depth, None)
    return words if limit is None else words[:limit]


async def _default_resolver(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({str(info[4][0]) for info in infos})


def _same_page(a: HttpResponse, b: HttpResponse) -> bool:
    """Two responses that look like the same (wildcard) default page — same status, ~same size."""
    if a.status_code != b.status_code:
        return False
    la, lb = len(a.text or ""), len(b.text or "")
    return abs(la - lb) <= max(64, int(0.03 * max(la, lb, 1)))


class SubdomainDiscoverer:
    def __init__(
        self,
        client: HttpClient,
        *,
        wordlist: list[str],
        resolver: Resolver | None = None,
        prober: Prober | None = None,
        concurrency: int = 40,
        use_passive: bool = True,
        use_external: bool = True,
        probe_timeout: float = 6.0,
        seeds: list[str] | None = None,
        recursion_depth: int = 0,
        use_permutations: bool = False,
        permutation_words: list[str] | None = None,
    ) -> None:
        self._client = client
        self._wordlist = wordlist
        self._resolver = resolver or _default_resolver
        self._prober = prober or self._probe
        self._concurrency = max(1, concurrency)
        self._use_passive = use_passive
        self._use_external = use_external
        self._probe_timeout = probe_timeout  # short per-probe timeout so a slow host doesn't drag
        # Manual seeds: known hosts to always probe+scan (and recurse into), regardless of the wordlist.
        self._seeds = [s.strip().lower().lstrip("*.").rstrip(".") for s in (seeds or []) if s.strip()]
        # Recursive enumeration: after finding subdomains, enumerate THEIR subdomains, up to this depth.
        self._recursion_depth = max(0, recursion_depth)
        # Permutation wave: mutate the found subdomains (api -> api-dev, api2…) and probe those too.
        self._use_permutations = use_permutations
        self._permutation_words = permutation_words or []

    async def _probe(self, host: str) -> tuple[str, HttpResponse] | None:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            if not self._client.is_in_scope(url):
                continue
            try:
                resp = await self._client.get(url, timeout=self._probe_timeout, retries=0)
            except OutOfScopeError:
                continue
            except Exception:  # noqa: BLE001 — an unreachable host is simply not discovered
                continue
            if resp is not None:
                return url, resp
        return None

    async def _passive_crtsh(self, domain: str) -> set[str]:
        try:
            import httpx

            from dastcore.recon.adapters import CrtShAdapter

            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as http:
                resp = await http.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
            return {asset.host for asset in CrtShAdapter().parse(resp.text)}
        except Exception:  # noqa: BLE001 — passive source is best-effort
            return set()

    async def _external_subfinder(self, domain: str) -> set[str]:
        if shutil.which("subfinder") is None:
            return set()
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-silent", "-d", domain,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            return {line.strip().lower().rstrip(".") for line in out.decode("utf-8", "replace").splitlines() if line.strip()}
        except Exception:  # noqa: BLE001 — accelerator is best-effort
            return set()

    async def _enumerate_and_probe(self, domain: str) -> list[DiscoveredHost]:
        """One level: enumerate subdomains of ``domain``, scope-gate, resolve and probe them. ``domain``
        itself is always probed (at this point it's a known/seed host, not a guess)."""
        domain = domain.strip().lower().lstrip("*.").rstrip(".")
        if not domain:
            return []
        candidates: set[str] = {domain} | {f"{word}.{domain}" for word in self._wordlist}
        if self._use_passive:
            candidates |= await self._passive_crtsh(domain)
        if self._use_external:
            candidates |= await self._external_subfinder(domain)
        return await self._resolve_and_probe(candidates, domain, always_keep={domain})

    async def _resolve_and_probe(
        self, candidates: set[str], domain: str, *, always_keep: set[str] | None = None
    ) -> list[DiscoveredHost]:
        """Scope-gate, DNS-resolve and HTTP-probe a set of candidate hosts. ``always_keep`` hosts are
        probed even if DNS wouldn't resolve them (the queried root, a manual seed)."""
        always_keep = always_keep or set()
        # Scope is the hard gate: never resolve or probe a host we aren't authorised for.
        in_scope = sorted(host for host in candidates if self._client.is_asset_in_scope(host))
        if not in_scope:
            return []

        wildcard = bool(await self._resolver(f"dc{secrets.token_hex(10)}.{domain}"))
        semaphore = asyncio.Semaphore(self._concurrency)

        if wildcard:
            resolved = in_scope  # DNS answers everything; the HTTP probe/baseline decides reality
        else:
            async def _resolves(host: str) -> str | None:
                async with semaphore:
                    return host if (host in always_keep or await self._resolver(host)) else None

            resolved = [host for host in await asyncio.gather(*(_resolves(h) for h in in_scope)) if host]

        baseline: HttpResponse | None = None
        if wildcard:
            probed_baseline = await self._prober(f"dc{secrets.token_hex(10)}.{domain}")
            baseline = probed_baseline[1] if probed_baseline else None

        async def _check(host: str) -> DiscoveredHost | None:
            async with semaphore:
                probed = await self._prober(host)
            if probed is None:
                return None
            url, resp = probed
            if wildcard and baseline is not None and _same_page(resp, baseline):
                return None  # just the wildcard default page, not a distinct host
            return DiscoveredHost(host=host, url=url, status_code=resp.status_code)

        return [host for host in await asyncio.gather(*(_check(h) for h in resolved)) if host]

    async def discover(self, domain: str) -> list[DiscoveredHost]:
        """Discover live in-scope hosts under ``domain`` (+ any manual seeds), recursively: found
        subdomains are themselves enumerated up to ``recursion_depth``, so nested hosts aren't missed."""
        domain = domain.strip().lower().lstrip("*.").rstrip(".")
        found: dict[str, DiscoveredHost] = {}
        visited: set[str] = set()
        queue: list[tuple[str, int]] = []
        if domain:
            queue.append((domain, 0))
        for seed in self._seeds:  # manual seeds start as roots too: probed, scanned, and recursed into
            if seed != domain and self._client.is_asset_in_scope(seed):
                queue.append((seed, 0))

        while queue:
            base, depth = queue.pop(0)
            if base in visited:
                continue
            visited.add(base)
            for host in await self._enumerate_and_probe(base):
                found.setdefault(host.host, host)
                if depth < self._recursion_depth and host.host != base and host.host not in visited:
                    queue.append((host.host, depth + 1))

        # Permutation wave: mutate the found subdomains and probe the new candidates (same scope gate).
        if self._use_permutations and self._permutation_words and domain and found:
            from dastcore.discovery.permutations import generate_permutations

            candidates = generate_permutations(set(found), domain, self._permutation_words)
            for host in await self._resolve_and_probe(candidates, domain):
                found.setdefault(host.host, host)

        return sorted(found.values(), key=lambda h: h.host)
