"""Subdomain permutation (alterx/altdns-style): mutate the subdomains you already found to catch the
ones a flat wordlist misses. If ``api.example.com`` is live, its siblings ``api-dev``, ``api2``,
``staging-api``, ``prod-api``, ``api-internal``… very often are too — but ``api-dev`` is in no wordlist.

This only *generates candidate hostnames*; they go through the same scope gate + resolve + probe as any
other subdomain, so nothing is ever assumed live. Bounded by ``max_candidates`` to stay tractable.
"""

from __future__ import annotations

from pathlib import Path

_WORDLISTS = Path(__file__).parent / "wordlists"
_NUMBERS = ("1", "2", "3", "01", "02")


def load_permutation_words(path: str | Path | None = None) -> list[str]:
    source = Path(path) if path else _WORDLISTS / "permutations.txt"
    seen: set[str] = set()
    words: list[str] = []
    for line in source.read_text(encoding="utf-8", errors="ignore").splitlines():
        entry = line.strip().lower()
        if entry and not entry.startswith("#") and entry not in seen:
            seen.add(entry)
            words.append(entry)
    return words


def generate_permutations(
    hosts: set[str], base_domain: str, words: list[str], *, max_candidates: int = 3000
) -> set[str]:
    """Candidate hostnames mutated from ``hosts`` (subdomains of ``base_domain``), capped."""
    base = base_domain.strip().lower().lstrip("*.").rstrip(".")
    out: set[str] = set()
    for host in hosts:
        host = host.strip().lower().rstrip(".")
        if host == base or not host.endswith("." + base):
            continue
        sub = host[: -(len(base) + 1)]  # the labels before ".base"
        labels = sub.split(".")
        first, rest = labels[0], ("." + ".".join(labels[1:]) if len(labels) > 1 else "")
        for word in words:
            if word == first:
                continue
            out.add(f"{word}-{first}{rest}.{base}")  # dev-api
            out.add(f"{first}-{word}{rest}.{base}")  # api-dev
            out.add(f"{word}{first}{rest}.{base}")  # devapi
            out.add(f"{first}{word}{rest}.{base}")  # apidev
            out.add(f"{word}{rest}.{base}")  # environment swap: api. -> dev.
        for number in _NUMBERS:
            out.add(f"{first}{number}{rest}.{base}")  # api2
    out -= hosts  # don't re-probe what we already found
    return set(sorted(out)[:max_candidates])  # sorted for a deterministic cap
