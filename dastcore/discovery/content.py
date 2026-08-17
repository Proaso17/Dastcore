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
_DEPTH_LIMITS: dict[str, int | None] = {"light": 100, "balanced": 300, "aggressive": None}

# Statuses that can indicate a real resource. 404/410/400 are "not found"; everything a garbage path
# also returns is filtered out by calibration regardless.
_INTERESTING = frozenset({200, 201, 202, 204, 206, 301, 302, 307, 308, 401, 403, 405, 500, 501, 503})


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


class ContentDiscoverer:
    """Brute-force paths under a base URL, reporting only calibrated hits."""

    def __init__(
        self,
        client: HttpClient,
        *,
        wordlist: list[str],
        concurrency: int = 12,
        max_paths: int = 6000,
        calibration_probes: int = 5,
    ) -> None:
        self._client = client
        self._wordlist = wordlist
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
        """Learn the not-found fingerprint from random paths. None if the base is unreachable."""
        baseline = _Baseline(statuses=set(), lengths_by_status={}, redirect_paths=set())
        seen_any = False
        shapes = ["{t}", "{t}.html", "{t}.php", "{t}.json", "{t}/"]
        for i in range(max(3, self._calibration_probes)):
            token = "dc" + secrets.token_hex(12)
            shape = shapes[i % len(shapes)]
            resp = await self._get(urljoin(base, shape.format(t=token)))
            if resp is None:
                continue
            seen_any = True
            baseline.statuses.add(resp.status_code)
            baseline.lengths_by_status.setdefault(resp.status_code, []).append(len(resp.text or ""))
            if resp.status_code in (301, 302, 307, 308):
                baseline.redirect_paths.add(_location_path(resp))
        return baseline if seen_any else None

    async def discover(self, base_url: str) -> list[DiscoveredEndpoint]:
        base = base_url if base_url.endswith("/") else base_url + "/"
        if not self._client.is_in_scope(base):
            return []
        baseline = await self._calibrate(base)
        if baseline is None:
            return []

        candidates = self._wordlist[: self._max_paths]
        semaphore = asyncio.Semaphore(self._concurrency)
        hits: dict[str, DiscoveredEndpoint] = {}

        async def probe(word: str) -> None:
            async with semaphore:
                url = urljoin(base, word)
                resp = await self._get(url)
            if resp is None or resp.status_code not in _INTERESTING or baseline.explains(resp):
                return
            final = resp.url or url
            hits[final] = DiscoveredEndpoint(url=final, status_code=resp.status_code, length=len(resp.text or ""))

        await asyncio.gather(*(probe(word) for word in candidates))
        return sorted(hits.values(), key=lambda e: e.url)
