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
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

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
    ) -> None:
        self._client = client
        self._wordlist = wordlist
        self._extensions = extensions or []
        self._recursion_depth = max(0, recursion_depth)
        self._concurrency = max(1, concurrency)
        self._max_paths = max_paths
        self._calibration_probes = calibration_probes

    async def _get(self, url: str) -> HttpResponse | None:
        try:
            return await self._client.get(url)
        except OutOfScopeError:
            return None
        except BudgetExceededError:
            raise
        except Exception:  # noqa: BLE001 — a single dead path must not abort the sweep
            return None

    async def _calibrate(self, base: str) -> _Baseline | None:
        """Learn the not-found fingerprint for THIS directory. None if it is unreachable."""
        baseline = _Baseline(statuses=set(), lengths_by_status={}, redirect_paths=set())
        seen_any = False
        shapes = ["{t}", "{t}.html", "{t}.php", "{t}.json", "{t}/"]
        for i in range(max(3, self._calibration_probes)):
            token = "dc" + secrets.token_hex(12)
            resp = await self._get(urljoin(base, shapes[i % len(shapes)].format(t=token)))
            if resp is None:
                continue
            seen_any = True
            baseline.statuses.add(resp.status_code)
            baseline.lengths_by_status.setdefault(resp.status_code, []).append(len(resp.text or ""))
            if resp.status_code in (301, 302, 307, 308):
                baseline.redirect_paths.add(_location_path(resp))
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

        while queue and budget[0] > 0:
            directory, depth = queue.pop(0)
            if directory in visited:
                continue
            visited.add(directory)
            baseline = await self._calibrate(directory)
            if baseline is None:
                continue
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
            if budget[0] <= 0:
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
