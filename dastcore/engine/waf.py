"""Payload tampers / encoders for WAF-evasion confirmation.

A *blocked* request is not a *safe* one: a WAF can hide a real vulnerability by filtering
the obvious payload. These transforms rewrite a payload so it still means the same thing to
the backend (the DB still runs the SQL, the browser still runs the script) but slips past a
naive signature filter. The scanner only uses them as a **confirmation** step: when a raw
payload is blocked, it retries with tampers, and a tampered variant whose oracle fires proves
the target is vulnerable *and* the WAF was masking it — never the other way round.

Each tamper is a pure ``str -> str``; a no-op (returns the input unchanged) is skipped by the
caller. They are intentionally conservative so the tampered payload keeps its semantics.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import quote

# SQL/JS keywords worth case-mangling to defeat case-sensitive signature filters.
_KEYWORDS = re.compile(
    r"\b(select|union|from|where|or|and|insert|update|delete|script|alert|onerror|onload|sleep|benchmark)\b",
    re.IGNORECASE,
)
_SQL_KEYWORD = re.compile(r"\b(select|union|from|where|and|or|insert|update|delete)\b", re.IGNORECASE)


def _swap_case(text: str) -> str:
    """Alternate the case of keyword characters (SELECT -> SeLeCt)."""

    def mangle(match: re.Match[str]) -> str:
        return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(match.group(0)))

    return _KEYWORDS.sub(mangle, text)


def _url_encode(text: str) -> str:
    """Percent-encode the characters a signature filter keys on (quotes, brackets, spaces)."""
    return quote(text, safe="")


def _double_url_encode(text: str) -> str:
    return quote(quote(text, safe=""), safe="")


def _sql_inline_comments(text: str) -> str:
    """Break SQL keywords with an inline comment (SELECT -> SEL/**/ECT) and spaces with /**/."""
    broken = _SQL_KEYWORD.sub(lambda m: f"{m.group(0)[:2]}/**/{m.group(0)[2:]}", text)
    return broken.replace(" ", "/**/")


def _mixed(text: str) -> str:
    """Case-swap keywords, then inline-comment them — stacked evasion."""
    return _sql_inline_comments(_swap_case(text))


# (name, transform). Ordered cheapest/most-portable first.
TAMPERS: list[tuple[str, Callable[[str], str]]] = [
    ("case-swap", _swap_case),
    ("url-encode", _url_encode),
    ("sql-comments", _sql_inline_comments),
    ("double-url-encode", _double_url_encode),
    ("mixed", _mixed),
]


def tampered_variants(payload: str) -> list[tuple[str, str]]:
    """Return (name, tampered) pairs that actually differ from the original payload."""
    seen: set[str] = {payload}
    variants: list[tuple[str, str]] = []
    for name, transform in TAMPERS:
        candidate = transform(payload)
        if candidate not in seen:
            seen.add(candidate)
            variants.append((name, candidate))
    return variants
