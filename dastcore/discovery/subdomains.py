"""Subdomain discovery for the scan flow: find the *other* hosts of a target so vulnerabilities
get tested across the whole attack surface, not just the one URL you typed.

Sources, most to least safe:

- **Passive (multi-source)** — CT logs, passive-DNS datasets, URL archives, and the live TLS cert's SANs
  (`discovery/passive_sources.py`; no traffic to the target). Premium sources activate with an API key.
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
    from dastcore.discovery.seclists import resolve_wordlist

    resolved = resolve_wordlist("subdomains", path)
    source = Path(resolved) if resolved else _WORDLISTS / "subdomains.txt"
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


def _matches_any(resp: HttpResponse, baselines: list[HttpResponse]) -> bool:
    """True if ``resp`` looks like any of the sampled wildcard catch-all pages. Sampling several random
    hosts (not one) absorbs a catch-all that varies a little per hostname — e.g. an ISP NXDOMAIN-hijack or
    parking page that echoes the name — so such pages aren't mistaken for distinct, real hosts."""
    return any(_same_page(resp, b) for b in baselines)


# Under a wildcard/catch-all domain, DNS resolves *every* name, so a wordlist brute-force can't be
# confirmed by DNS and explodes into a probe for every word. These bound that: only this many brute-force
# guesses are HTTP-probed (passively-observed and seed hosts are always kept, on top), and the catch-all
# page is characterised from this many random samples. Recursion and permutations are disabled entirely
# under a wildcard (every generated name would "resolve", multiplying the noise) — see ``discover``.
_WILDCARD_PROBE_CAP = 75
_WILDCARD_BASELINE_SAMPLES = 3


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
        passive_gather: Callable[[str], Awaitable[set[str]]] | None = None,
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
        # ``use_passive`` gates *all* passive discovery: crt.sh plus the multi-source gather (passive DNS,
        # URL archives, cert SANs; premium sources activate with their API key). Off = fully offline.
        self._use_passive = use_passive
        self._use_external = use_external
        # The multi-source gather is queried once for the root domain; injectable for offline tests.
        self._passive_gather = passive_gather
        self._root = ""
        self._wildcard_root = False  # set in discover(): the root answers every name (wildcard/ISP hijack)
        self._passive_root: set[str] = set()
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
        # Priority hosts are real, observed names (seeds + passively gathered + external tools) — worth
        # probing even under a wildcard, unlike the wordlist guesses (which DNS can't confirm there).
        priority: set[str] = {domain}
        if self._use_external:
            priority |= await self._external_subfinder(domain)
        if self._passive_root and domain == self._root:
            priority |= self._passive_root  # multi-source passive hits (incl. crt.sh), gathered for the root
        candidates: set[str] = priority | {f"{word}.{domain}" for word in self._wordlist}
        return await self._resolve_and_probe(candidates, domain, always_keep={domain}, priority=priority)

    async def _resolve_and_probe(
        self, candidates: set[str], domain: str, *, always_keep: set[str] | None = None,
        priority: set[str] | None = None,
    ) -> list[DiscoveredHost]:
        """Scope-gate, DNS-resolve and HTTP-probe a set of candidate hosts. ``always_keep`` hosts are
        probed even if DNS wouldn't resolve them (the queried root, a manual seed); ``priority`` hosts
        (observed, not guessed) survive the wildcard probe cap."""
        always_keep = always_keep or set()
        priority = priority or set()
        # Scope is the hard gate: never resolve or probe a host we aren't authorised for.
        in_scope = sorted(host for host in candidates if self._client.is_asset_in_scope(host))
        if not in_scope:
            return []

        # Reuse the root's wildcard verdict (detected once in discover) to avoid a second DNS probe;
        # re-detect only for a different domain (rare — recursion is off under a wildcard root anyway).
        wildcard = self._wildcard_root if domain == self._root else bool(
            await self._resolver(f"dc{secrets.token_hex(10)}.{domain}")
        )
        semaphore = asyncio.Semaphore(self._concurrency)

        if wildcard:
            # DNS answers everything, so DNS can't filter and a full wordlist probe would explode. Probe
            # the observed/priority hosts plus a bounded slice of the remaining guesses; the HTTP baseline
            # decides reality. Keeps the passively-discovered real hosts, drops the brute-force blow-up.
            rest = [h for h in in_scope if h not in priority]
            resolved = sorted(priority & set(in_scope)) + rest[:_WILDCARD_PROBE_CAP]
        else:
            async def _resolves(host: str) -> str | None:
                async with semaphore:
                    return host if (host in always_keep or await self._resolver(host)) else None

            resolved = [host for host in await asyncio.gather(*(_resolves(h) for h in in_scope)) if host]

        baselines: list[HttpResponse] = []
        if wildcard:
            # Characterise the catch-all page from several random hosts (it may vary a little per name).
            samples = await asyncio.gather(
                *(self._prober(f"dc{secrets.token_hex(10)}.{domain}") for _ in range(_WILDCARD_BASELINE_SAMPLES))
            )
            baselines = [probed[1] for probed in samples if probed is not None]

        async def _check(host: str) -> DiscoveredHost | None:
            async with semaphore:
                probed = await self._prober(host)
            if probed is None:
                return None
            url, resp = probed
            if wildcard and baselines and _matches_any(resp, baselines):
                return None  # just the wildcard default page, not a distinct host
            return DiscoveredHost(host=host, url=url, status_code=resp.status_code)

        return [host for host in await asyncio.gather(*(_check(h) for h in resolved)) if host]

    async def discover(self, domain: str) -> list[DiscoveredHost]:
        """Discover live in-scope hosts under ``domain`` (+ any manual seeds), recursively: found
        subdomains are themselves enumerated up to ``recursion_depth``, so nested hosts aren't missed."""
        domain = domain.strip().lower().lstrip("*.").rstrip(".")
        self._root = domain
        # Is the root a wildcard/catch-all (every name resolves — a real wildcard, or an ISP NXDOMAIN
        # hijack)? Detect once here so _resolve_and_probe can reuse it, and so recursion/permutations —
        # which would each generate names that all "resolve" and multiply the probe explosion — are off.
        self._wildcard_root = bool(await self._resolver(f"dc{secrets.token_hex(10)}.{domain}")) if domain else False
        # Multi-source passive gathering: one query per source for the root domain (CT logs, passive DNS,
        # URL archives, cert SANs, + premium if keyed). Results are scope-gated/validated like everything
        # else, so a passive host that doesn't resolve or answer is dropped.
        if self._use_passive and domain:
            gather = self._passive_gather
            if gather is None:
                from dastcore.discovery.passive_sources import gather_passive_subdomains

                gather = gather_passive_subdomains
            try:
                self._passive_root = await gather(domain)
            except Exception:  # noqa: BLE001 — passive gathering is best-effort, never fatal
                self._passive_root = set()
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
                # Recurse only on a non-wildcard domain: under a wildcard every child name resolves, so
                # recursion would re-enumerate the whole wordlist per noise host (the 3h blow-up we fixed).
                if (not self._wildcard_root and depth < self._recursion_depth
                        and host.host != base and host.host not in visited):
                    queue.append((host.host, depth + 1))

        # Permutation wave: mutate the found subdomains and probe the new candidates (same scope gate).
        # Skipped under a wildcard root — every permuted name would "resolve" and just add noise.
        if self._use_permutations and not self._wildcard_root and self._permutation_words and domain and found:
            from dastcore.discovery.permutations import generate_permutations

            candidates = generate_permutations(set(found), domain, self._permutation_words)
            for host in await self._resolve_and_probe(candidates, domain):
                found.setdefault(host.host, host)

        return sorted(found.values(), key=lambda h: h.host)
