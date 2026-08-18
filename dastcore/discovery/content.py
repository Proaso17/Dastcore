"""Content discovery (directory / endpoint brute-forcing) — the ffuf/dirb capability, native.

Every request goes through the shared :class:`HttpClient`, so it is **scope-enforced and
rate-limited** exactly like the rest of the scanner — content discovery can never step outside the
authorised host. Discovered paths are then fed back into the crawler + detectors so vulnerabilities
are tested on them too.

Zero false positives come from **autocalibration**: before brute-forcing we ask the server for a
handful of random, certainly-nonexistent paths and learn how it answers "not found". A candidate is
only reported when its response is meaningfully different from that baseline. This defeats:

- *soft 404s* (the server returns 200 with a friendly page for everything),
- *catch-all redirects* (everything 302s to ``/login``),
- *dynamic error pages* (the not-found body changes size every time) — the tolerance widens to match
  the observed variance, so noise never becomes a finding.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import HttpResponse

_WORDLISTS = Path(__file__).parent / "wordlists"
# Depth takes a prefix of the (priority-ordered) wordlist. None = the whole list.
_DEPTH_LIMITS: dict[str, int | None] = {"light": 100, "balanced": 450, "aggressive": None}

# Statuses that can indicate a real resource. 404/410/400 are "not found"; everything a garbage path
# also returns is filtered out by calibration regardless.
_INTERESTING = frozenset({200, 201, 202, 204, 206, 301, 302, 307, 308, 401, 403, 405, 500, 501, 503})

# Per-depth file-extension fuzzing (word -> word.ext) and how deep to recurse into found directories.
_EXTENSIONS: dict[str, list[str]] = {
    "light": [],
    "balanced": ["php", "json", "txt", "html", "bak", "old", "zip"],
    "aggressive": [
        "php", "asp", "aspx", "jsp", "json", "xml", "txt", "html", "htm", "bak", "old", "orig", "save",
        "zip", "tar.gz", "tgz", "rar", "7z", "sql", "db", "sqlite", "log", "conf", "config", "ini",
        "yml", "yaml", "env", "pem", "key", "swp", "~",
    ],
}
_RECURSION: dict[str, int] = {"light": 0, "balanced": 1, "aggressive": 2}


def content_extensions(depth: str) -> list[str]:
    return list(_EXTENSIONS.get(depth, _EXTENSIONS["aggressive"]))


def content_recursion_depth(depth: str) -> int:
    return _RECURSION.get(depth, _RECURSION["aggressive"])


@dataclass(frozen=True)
class DiscoveredEndpoint:
    url: str
    status_code: int
    length: int


def load_content_wordlist(depth: str = "aggressive", path: str | Path | None = None) -> list[str]:
    """Load the built-in content wordlist (or a user file) and slice it to ``depth``."""
    source = Path(path) if path else _WORDLISTS / "content.txt"
    seen: set[str] = set()
    words: list[str] = []
    for line in source.read_text(encoding="utf-8", errors="ignore").splitlines():
        entry = line.strip().lstrip("/")
        if entry and not line.lstrip().startswith("#") and entry not in seen:
            seen.add(entry)
            words.append(entry)
    limit = _DEPTH_LIMITS.get(depth, None)
    return words if limit is None else words[:limit]


def _location_path(resp: HttpResponse) -> str:
    """The path a redirect points at (host stripped), for comparing against the baseline redirect."""
    location = resp.headers.get("location") or resp.headers.get("Location") or ""
    return urlsplit(location).path if location else ""


@dataclass
class _Baseline:
    """What the server returns for paths that definitely don't exist."""

    statuses: set[int]
    lengths_by_status: dict[int, list[int]]
    redirect_paths: set[str]

    def explains(self, resp: HttpResponse) -> bool:
        """True if ``resp`` looks just like the server's not-found answer (so it is NOT a hit)."""
        status = resp.status_code
        if status not in self.statuses:
            return False
        if status in (301, 302, 307, 308):
            # Same generic redirect target as garbage paths → not a real resource.
            return _location_path(resp) in self.redirect_paths
        lengths = self.lengths_by_status.get(status, [])
        if not lengths:
            return True
        length = len(resp.text or "")
        spread = max(lengths) - min(lengths)
        tolerance = max(64, spread, int(0.03 * max(max(lengths), length)))
        return min(abs(length - base) for base in lengths) <= tolerance


def _has_extension(word: str) -> bool:
    return "." in word.rsplit("/", 1)[-1]


def adaptive_concurrency(base: int, latency_ms: float) -> int:
    """More in-flight probes for a high-latency host, so throughput stays near the rps ceiling.

    A slow-but-healthy server (each response takes a while, but it handles many at once) is
    concurrency-limited, not rate-limited: with only ``base`` probes in flight the pipe sits idle
    waiting. Scaling concurrency up with latency fills it. It's always bounded by the client's token
    bucket (rps), so this never sends faster than the user asked — it just stops wasting the budget."""
    if latency_ms <= 250:
        return base
    return max(base, min(64, int(base * latency_ms / 250)))


class ContentDiscoverer:
    """Brute-force paths under a base URL, reporting only calibrated hits.

    Beyond the flat wordlist it fuzzes **file extensions** (``config`` → ``config.php``, ``config.bak``…)
    and **recurses into discovered directories** (find ``/admin/`` → brute-force ``/admin/*``), just like
    a full dirb/ffuf sweep. Every directory gets its own not-found calibration, and a total-probe budget
    keeps even the aggressive, recursive sweep bounded.
    """

    def __init__(
        self,
        client: HttpClient,
        *,
        wordlist: list[str],
        extensions: list[str] | None = None,
        recursion_depth: int = 0,
        concurrency: int = 12,
        max_paths: int = 20000,
        calibration_probes: int = 5,
        timeout_giveup: int = 30,
        max_seconds: float = 600.0,
        probe_timeout: float = 6.0,
    ) -> None:
        self._client = client
        self._wordlist = wordlist
        self._extensions = extensions or []
        self._recursion_depth = max(0, recursion_depth)
        self._base_concurrency = max(1, concurrency)
        self._concurrency = self._base_concurrency
        self._max_paths = max_paths
        self._calibration_probes = calibration_probes
        # A discovery probe uses a short timeout and no retries: a real path answers fast, and a
        # slow/dead one shouldn't cost 10s x 2 retries (that's what stalled the getnyma scan).
        self._probe_timeout = probe_timeout
        self._calibrated_latency_ms = 0.0
        # Circuit breaker: a host that keeps timing out (accepts connections but never answers) is
        # abandoned after this many timeouts, so one dead host can't stall the whole scan for hours.
        # A healthy host answers 404s instantly and never trips it. A generous wall-clock cap backstops it.
        self._timeout_giveup = timeout_giveup
        self._max_seconds = max_seconds
        self._timeouts = 0
        self._stopped = False
        self._deadline = 0.0

    async def _get(self, url: str) -> HttpResponse | None:
        try:
            return await self._client.get(url, timeout=self._probe_timeout, retries=0)
        except OutOfScopeError:
            return None
        except BudgetExceededError:
            raise
        except (httpx.TimeoutException, httpx.TransportError, OSError):
            # A network stall on this host: count it, and give up on the host once too many pile up.
            self._timeouts += 1
            if self._timeouts >= self._timeout_giveup:
                self._stopped = True
            return None
        except Exception:  # noqa: BLE001 — a single dead path must not abort the sweep
            return None

    async def _calibrate(self, base: str) -> _Baseline | None:
        """Learn the not-found fingerprint for THIS directory. None if it is unreachable."""
        baseline = _Baseline(statuses=set(), lengths_by_status={}, redirect_paths=set())
        seen_any = False
        latencies: list[float] = []
        shapes = ["{t}", "{t}.html", "{t}.php", "{t}.json", "{t}/"]
        for i in range(max(3, self._calibration_probes)):
            token = "dc" + secrets.token_hex(12)
            resp = await self._get(urljoin(base, shapes[i % len(shapes)].format(t=token)))
            if resp is None:
                continue
            seen_any = True
            latencies.append(float(getattr(resp, "elapsed_ms", 0.0) or 0.0))
            baseline.statuses.add(resp.status_code)
            baseline.lengths_by_status.setdefault(resp.status_code, []).append(len(resp.text or ""))
            if resp.status_code in (301, 302, 307, 308):
                baseline.redirect_paths.add(_location_path(resp))
        if latencies:
            self._calibrated_latency_ms = sorted(latencies)[len(latencies) // 2]  # median
        return baseline if seen_any else None

    def _candidates(self, word: str) -> list[str]:
        """The probes for one word: the route itself, extension variants, and (for recursion) a dir probe."""
        out = [word]
        if not _has_extension(word):
            out += [f"{word}.{ext}" for ext in self._extensions]
        if self._recursion_depth > 0:
            out.append(word + "/")  # a hit here means a directory to recurse into
        return out

    async def discover(self, base_url: str) -> list[DiscoveredEndpoint]:
        base = base_url if base_url.endswith("/") else base_url + "/"
        if not self._client.is_in_scope(base):
            return []
        hits: dict[str, DiscoveredEndpoint] = {}
        budget = [self._max_paths]
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(base, 0)]
        self._timeouts = 0
        self._stopped = False
        self._deadline = time.monotonic() + self._max_seconds

        while queue and budget[0] > 0 and not self._stopped and time.monotonic() < self._deadline:
            directory, depth = queue.pop(0)
            if directory in visited:
                continue
            visited.add(directory)
            baseline = await self._calibrate(directory)
            if baseline is None:
                continue
            if depth == 0:  # adapt concurrency to the host's measured latency (fill the rps pipe)
                self._concurrency = adaptive_concurrency(self._base_concurrency, self._calibrated_latency_ms)
            child_dirs = await self._sweep(directory, depth, baseline, hits, budget)
            for child in child_dirs:
                if child not in visited:
                    queue.append((child, depth + 1))

        return sorted(hits.values(), key=lambda e: e.url)

    async def _sweep(
        self,
        directory: str,
        depth: int,
        baseline: _Baseline,
        hits: dict[str, DiscoveredEndpoint],
        budget: list[int],
    ) -> list[str]:
        """Brute-force one directory; record hits, return the child directories to recurse into."""
        semaphore = asyncio.Semaphore(self._concurrency)
        child_dirs: set[str] = set()

        async def probe(candidate: str) -> None:
            if budget[0] <= 0 or self._stopped or time.monotonic() >= self._deadline:
                return
            budget[0] -= 1
            async with semaphore:
                url = urljoin(directory, candidate)
                resp = await self._get(url)
            if resp is None or resp.status_code not in _INTERESTING or baseline.explains(resp):
                return
            final = resp.url or url
            hits[final] = DiscoveredEndpoint(url=final, status_code=resp.status_code, length=len(resp.text or ""))
            is_dir = final.rstrip().endswith("/") or (
                resp.status_code in (301, 302, 307, 308) and _location_path(resp).endswith("/")
            )
            if is_dir and depth < self._recursion_depth:
                child_dirs.add(urljoin(directory, candidate.rstrip("/") + "/"))

        candidates = [c for word in self._wordlist for c in self._candidates(word)]
        await asyncio.gather(*(probe(candidate) for candidate in candidates))
        return sorted(child_dirs)
