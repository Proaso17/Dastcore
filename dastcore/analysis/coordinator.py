"""Target coordinator (XBOW-style): score and de-duplicate the discovered surface before hunting.

Recon hands us the live assets; this decides the order to hunt them and collapses the ones that are the
same deployment. Each asset's homepage is fetched once, content-fingerprinted (volatile bits masked, like
the crawler), and assets whose homepage is byte-identical are merged into one representative — so a
program with hundreds of subdomains parked on the same template page is scanned once, not hundreds of
times. Survivors are ordered by a promise score (auth surface, server-side tech, reachability, recon
tier) so the juiciest targets are hunted first under a budget.

Deterministic and dependency-light: the fetch is injected, so it unit-tests offline. Deliberately NOT
parallel — bounty rules of engagement want low-and-slow, and the active scanner already parallelises
within a single target; fanning out across hosts would fight the per-program rate limits.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from dastcore.recon.models import Asset
from dastcore.validation.baseline import normalize_body

_FINGERPRINT_CAP = 20000
# A login/password surface means an authenticated app behind it — high promise (BOLA/BFLA live there).
_AUTH_FORM = re.compile(
    r"""type=['"]?password|name=['"]?(?:password|passwd|pwd)\b|<form[^>]+login|id=['"]?login\b""", re.IGNORECASE
)
# Server-side stacks expose far more injectable surface than a static page — weight assets running them.
_SERVERSIDE_TECH = frozenset({
    "php", "java", "spring", "wordpress", "drupal", "joomla", "node", "express", "django", "flask",
    "rails", "ruby", "asp.net", "dotnet", "laravel", "tomcat", "nginx", "apache", "iis",
})

# A fetch returns (status_code, body) for a URL, or None if unreachable. Injected for offline tests.
Fetch = Callable[[str], Awaitable["tuple[int, str] | None"]]


@dataclass
class Coordination:
    """The coordinator's verdict: the hunt order, the collapsed duplicates, and per-asset scores."""

    order: list[Asset] = field(default_factory=list)          # representatives, highest promise first
    duplicates: dict[str, list[str]] = field(default_factory=dict)  # representative URL -> URLs it stands for
    scores: dict[str, float] = field(default_factory=dict)    # asset URL -> promise score
    skipped: int = 0                                          # duplicate-content assets collapsed away


def content_fingerprint(body: str) -> str:
    """A homepage's identity by CONTENT (volatile bits masked), matching the crawler's location identity."""
    return hashlib.sha1(normalize_body(body[:_FINGERPRINT_CAP]).encode("utf-8", "ignore")).hexdigest()


def score_target(asset: Asset, status: int | None, body: str) -> float:
    """How promising an asset is to hunt (higher = first). Deterministic signals only."""
    score = 0.0
    if status == 200:
        score += 3.0
    elif status is not None and 300 <= status < 400:
        score += 1.0
    if body and _AUTH_FORM.search(body):
        score += 4.0  # an auth surface unlocks the authenticated app (where the real bugs are)
    if {t.lower() for t in asset.tech} & _SERVERSIDE_TECH:
        score += 2.0
    score += {1: 5.0, 2: 2.0}.get(asset.tier, 0.0)  # recon's coarse tier (admin/api/internal first)
    return score


async def coordinate(assets: list[Asset], fetch: Fetch) -> Coordination:
    """Fetch each live asset's homepage, collapse identical-content deployments, and order by promise.

    Assets without a URL are ignored (nothing to hunt). An asset whose homepage can't be fetched (or is
    empty) is kept as its own target — never merged — so an unreachable or blank response can't silently
    swallow a distinct host. Ordering and representative-selection are stable (ties break by URL)."""
    live = [a for a in assets if a.url]
    scores: dict[str, float] = {}
    # fingerprint -> representatives' probe rows; a unique "solo:" fingerprint for anything we can't merge.
    groups: dict[str, list[tuple[float, Asset]]] = {}
    for index, asset in enumerate(live):
        assert asset.url is not None
        got = await fetch(asset.url)
        status, body = got if got is not None else (None, "")
        score = score_target(asset, status, body)
        scores[asset.url] = score
        normalized = normalize_body(body[:_FINGERPRINT_CAP]) if body else ""
        # Only merge on a real, non-empty homepage; otherwise give it a unique key so it stands alone.
        fingerprint = content_fingerprint(body) if normalized.strip() else f"solo:{index}:{asset.url}"
        groups.setdefault(fingerprint, []).append((score, asset))

    representatives: list[tuple[float, Asset]] = []
    duplicates: dict[str, list[str]] = {}
    skipped = 0
    for members in groups.values():
        members.sort(key=lambda m: (-m[0], m[1].url or ""))  # best-scored represents the group (stable)
        rep_score, rep = members[0]
        representatives.append((rep_score, rep))
        dups = [a.url for _, a in members[1:] if a.url]
        if dups:
            duplicates[rep.url or ""] = dups
            skipped += len(dups)

    representatives.sort(key=lambda m: (-m[0], m[1].url or ""))  # hunt the most promising first
    return Coordination(
        order=[asset for _, asset in representatives], duplicates=duplicates, scores=scores, skipped=skipped
    )
