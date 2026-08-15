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


# (name, transform). Ordered cheapest/most-portable first. Applied for every family.
TAMPERS: list[tuple[str, Callable[[str], str]]] = [
    ("case-swap", _swap_case),
    ("url-encode", _url_encode),
    ("sql-comments", _sql_inline_comments),
    ("double-url-encode", _double_url_encode),
    ("mixed", _mixed),
]


# --- family-specific tampers: equivalent syntax that stays valid to the backend ----------------
# Each keeps the payload's meaning for its family while dropping the token a signature keys on, so
# a *blocking* WAF misses it and the oracle still fires on the backend's real behaviour.


def _sql_ws_comment(text: str) -> str:
    """Whitespace via inline comments — keeps keywords intact, so it stays valid SQL (``a b`` -> ``a/**/b``)."""
    return text.replace(" ", "/**/")


def _sql_ws_newline(text: str) -> str:
    """Whitespace via a newline — SQL treats it as space, many space-based signatures don't."""
    return text.replace(" ", "\n")


_SHELL_CMD = re.compile(r"\b(id|whoami|cat|ls|uname|curl|wget|ping|nslookup|echo|dir|type)\b", re.IGNORECASE)


def _cmdi_ifs(text: str) -> str:
    """Shell whitespace via ``${IFS}`` — the shell still splits on it, a space filter is bypassed."""
    return text.replace(" ", "${IFS}")


def _cmdi_quote_insert(text: str) -> str:
    """Break a command word with empty quotes (``id`` -> ``i""d``): the shell strips them and runs ``id``."""
    return _SHELL_CMD.sub(lambda m: f'{m.group(0)[0]}""{m.group(0)[1:]}', text)


def _cmdi_backslash(text: str) -> str:
    """Break a command word with a backslash (``id`` -> ``i\\d``): the shell drops it and runs ``id``."""
    return _SHELL_CMD.sub(lambda m: f"{m.group(0)[0]}\\{m.group(0)[1:]}", text)


def _lfi_path_backslash(text: str) -> str:
    """Backslash separators — Windows resolves ``..\\`` the same as ``../`` past ``../``-only filters."""
    return text.replace("../", "..\\")


# Appended after the generic TAMPERS when the rule's family is known.
_FAMILY_TAMPERS: dict[str, list[tuple[str, Callable[[str], str]]]] = {
    "sqli": [("ws-comment", _sql_ws_comment), ("ws-newline", _sql_ws_newline)],
    "cmdi": [("ifs", _cmdi_ifs), ("quote-insert", _cmdi_quote_insert), ("cmd-backslash", _cmdi_backslash)],
    "lfi": [("path-backslash", _lfi_path_backslash)],
}


def tampered_variants(payload: str, family: str = "") -> list[tuple[str, str]]:
    """Return (name, tampered) pairs that differ from the original — generic tampers first, then
    the family-specific equivalents (``family=""`` keeps the generic-only behaviour)."""
    seen: set[str] = {payload}
    variants: list[tuple[str, str]] = []
    for name, transform in TAMPERS + _FAMILY_TAMPERS.get(family, []):
        candidate = transform(payload)
        if candidate not in seen:
            seen.add(candidate)
            variants.append((name, candidate))
    return variants
