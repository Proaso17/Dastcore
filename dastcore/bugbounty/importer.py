"""Import a bug-bounty ``Program`` from a program's *pasted policy / scope text* (Mode A).

The researcher copies the program page — the Scope table, the rules, the safe-harbor blurb — and this
turns it into a ready-to-review :class:`Program`, instead of typing every field by hand. It is a pure
text parser (no network, no scraping — works for any platform), deliberately conservative: it extracts
what is clearly present and records everything else as a **note** for the human to confirm. Nothing here
starts a scan — the caller always shows the resulting program for review first (the authorization gate
still applies).

What it pulls out:

* **In-scope / out-of-scope hosts** — exact domains, ``*.wildcards`` and CIDR ranges, split by the
  policy's own "out of scope" section. Non-web assets (Android/iOS apps, binaries, source repos,
  smart contracts) are filtered out with a note, since DASTCore only tests web/API.
* **Rate limit** — an explicit "N requests per second"; a low default is *suggested* (not forced) when
  the policy reads like a bank / safe-harbor "avoid harm" program.
* **No-automated-scanning** — a policy that forbids scanners flips ``no_automated_scanning`` on.
* **Attribution header** — an ``X-…`` header the program asks you to send is captured into
  ``required_headers``.
* **Safe harbor** — detected and surfaced as a note (informational).
* **Bug-bounty mode** — on by default for a real-platform import, so N/A-class findings are suppressed
  from the report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from dastcore.bugbounty.program import Platform, Program, ProgramLimits, ProgramScope

_PLATFORMS: frozenset[str] = frozenset({"hackerone", "bugcrowd", "intigriti", "immunefi", "self"})

# The bounty platforms' own hosts are never scan targets — drop them if a program URL leaks one in.
_PLATFORM_HOSTS: frozenset[str] = frozenset({
    "hackerone.com", "hackerone.net", "bugcrowd.com", "intigriti.com", "immunefi.com",
})

# Host-ish tokens.
_CIDR = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")
_WILDCARD = re.compile(r"\*\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]+)*\.[a-z]{2,}", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s,;'\"<>()\]]+", re.IGNORECASE)
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)

# Lines/tokens that denote a non-web asset we don't test — filtered out (with a note).
_NON_WEB = re.compile(
    r"\b(android|ios|iphone|ipad|\.apk\b|\.ipa\b|testflight|play\.google|apps\.apple|itunes\.apple|"
    r"google play|app store|mobile app|smart contract|firmware|executable|binary|source code)\b",
    re.IGNORECASE,
)
# Section headers.
_OUT_HEADER = re.compile(r"out[\s_-]*of[\s_-]*scope|fuera de (?:alcance|scope)|no elegibles?", re.IGNORECASE)
_IN_HEADER = re.compile(r"\bin[\s_-]*scope\b|en (?:alcance|scope)|assets? in scope|dominios? en alcance", re.IGNORECASE)

# Policy signals.
_SAFE_HARBOR = re.compile(r"safe harbor|safe harbour|gold standard", re.IGNORECASE)
_NO_AUTOMATION = re.compile(
    r"no (?:automated|automatic)|automated (?:tools?|scann?ers?)\s+(?:are\s+)?(?:not\s+allowed|prohibited|forbidden)"
    r"|do not (?:use|run) (?:automated|scanners?)|sin herramientas autom|no (?:se permiten|uses?) (?:scanners?|autom)",
    re.IGNORECASE,
)
_RATE = re.compile(
    r"(\d+(?:\.\d+)?)\s*(?:requests?|req|peticiones?)\s*(?:per|/|por)\s*(?:second|sec|segundo|s)\b", re.IGNORECASE
)
_FINANCE = re.compile(r"\bbank|banking|banco|financ|payment|fintech|avoid harm|minimi[sz]e", re.IGNORECASE)
_ATTR_HEADER = re.compile(r"\b(X-[A-Za-z][A-Za-z0-9-]*)\b\s*[:=]?\s*([^\s,;]+)?", re.IGNORECASE)
_H1_HANDLE = re.compile(r"hackerone\.com/([A-Za-z0-9_.-]+)", re.IGNORECASE)
_BUGCROWD = re.compile(r"bugcrowd\.com/([A-Za-z0-9_.-]+)", re.IGNORECASE)


@dataclass
class ImportResult:
    """The parsed program plus a human-readable trail of what was inferred, guessed, or dropped."""

    program: Program
    notes: list[str] = field(default_factory=list)
    filtered: list[str] = field(default_factory=list)  # hosts/lines dropped as non-web assets


def _hosts_in_line(line: str) -> tuple[list[str], list[str], list[str]]:
    """Extract (domains, wildcards, cidrs) from one line, de-noised. URLs are reduced to their host."""
    domains: list[str] = []
    wildcards = [m.group(0).lower() for m in _WILDCARD.finditer(line)]
    cidrs = [m.group(0) for m in _CIDR.finditer(line)]
    # Blank the tokens already claimed so _DOMAIN doesn't re-grab the wildcard/cidr apex.
    scrubbed = _WILDCARD.sub(" ", line)
    scrubbed = _CIDR.sub(" ", scrubbed)
    for m in _URL.finditer(scrubbed):
        host = re.sub(r"^https?://", "", m.group(0), flags=re.IGNORECASE).split("/")[0].split(":")[0].split("@")[-1]
        if _DOMAIN.fullmatch(host):
            domains.append(host.lower())
    scrubbed = _URL.sub(" ", scrubbed)
    for m in _DOMAIN.finditer(scrubbed):
        domains.append(m.group(0).lower())
    return domains, wildcards, cidrs


def _dedup(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def parse_program_policy(text: str, platform: str = "hackerone", handle: str = "") -> ImportResult:
    """Parse pasted program-policy text into a reviewable :class:`Program` plus notes."""
    plat: Platform = platform if platform in _PLATFORMS else "self"  # type: ignore[assignment]
    notes: list[str] = []
    filtered: list[str] = []

    in_domains: list[str] = []
    in_wildcards: list[str] = []
    in_cidrs: list[str] = []
    out_hosts: list[str] = []

    mode = "in"
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if _OUT_HEADER.search(line) and not _hosts_in_line(line)[0] and not _WILDCARD.search(line):
            mode = "out"
            continue
        if _IN_HEADER.search(line) and mode == "out" and not _WILDCARD.search(line):
            mode = "in"
            continue
        if _NON_WEB.search(line):  # a mobile/binary/source asset row — not something we test
            hit = _WILDCARD.findall(line) or _hosts_in_line(line)[0] or [line[:60]]
            filtered.extend(hit)
            continue
        domains, wildcards, cidrs = _hosts_in_line(line)
        if mode == "out":
            out_hosts.extend(domains + wildcards + cidrs)
        else:
            in_domains.extend(domains)
            in_wildcards.extend(wildcards)
            in_cidrs.extend(cidrs)

    # Drop the platform's own hosts (e.g. a "hackerone.com/<handle>" program URL) — never a target.
    in_domains = [d for d in in_domains if d not in _PLATFORM_HOSTS]
    out_hosts_raw = [h for h in out_hosts if h not in _PLATFORM_HOSTS]
    in_domains, in_wildcards, in_cidrs = _dedup(in_domains), _dedup(in_wildcards), _dedup(in_cidrs)
    out_hosts = _dedup(out_hosts_raw)
    # An apex that is also covered by a wildcard is redundant noise in the domains list — drop it.
    wc_apexes = {w[2:] for w in in_wildcards}
    in_domains = [d for d in in_domains if d not in wc_apexes]

    # Handle from a program URL if not supplied.
    if not handle:
        m = _H1_HANDLE.search(text) or _BUGCROWD.search(text)
        if m:
            handle = m.group(1)
            if _BUGCROWD.search(text) and plat == "hackerone":
                plat = "bugcrowd"

    # Limits.
    limits = ProgramLimits()
    rate = _RATE.search(text)
    if rate:
        limits.requests_per_second = max(0.5, float(rate.group(1)))
        notes.append(f"Rate limit detectado en la política: {limits.requests_per_second} req/s.")
    elif _FINANCE.search(text) or _SAFE_HARBOR.search(text):
        limits.requests_per_second = 2.0
        limits.max_concurrency = 2
        notes.append("Sin rate limit explícito, pero la política parece de banca/finanzas o con 'avoid "
                     "harm' → propuesto 2 req/s · concurrencia 2 (conservador). Ajústalo si procede.")
    if _NO_AUTOMATION.search(text):
        limits.no_automated_scanning = True
        notes.append("La política prohíbe herramientas automáticas → 'solo recon' activado (sin escaneo activo).")

    # Attribution header (X-…) if the policy asks for one.
    required_headers: dict[str, str] = {}
    for m in _ATTR_HEADER.finditer(text):
        name, value = m.group(1), (m.group(2) or "").strip().strip("<>\"'").rstrip(".,;:")
        if value and not value.lower().startswith(("http", "content", "access")):
            required_headers[name] = value
            notes.append(f"Cabecera de atribución requerida detectada: {name}: {value}.")
            break

    if _SAFE_HARBOR.search(text):
        notes.append("Safe harbor detectado (autoriza técnicas de prueba dentro del scope). Recuerda: no "
                     "cubre infraestructura de terceros.")

    seeds = in_domains + [w[2:] for w in in_wildcards]
    program = Program(
        platform=plat,
        handle=(handle.strip() or "objetivo"),
        scope=ProgramScope(domains=in_domains, wildcards=in_wildcards, cidrs=in_cidrs, out_of_scope=out_hosts),
        limits=limits,
        bug_bounty_mode=plat != "self",  # a real bounty import defaults to hiding N/A-class findings
        required_headers=required_headers,
        seeds=_dedup(seeds),
    )

    if not program.scope.allow_patterns():
        notes.append("⚠️ No se detectó ningún host en alcance. Pega la tabla de Scope (dominios / *.dominio "
                     "/ rangos) o añádelos a mano antes de guardar.")
    if filtered:
        notes.append(f"Descartados {len(filtered)} assets no-web (Android/iOS/binarios/código) — DASTCore "
                     "solo prueba web/API.")
    if plat != "self":
        notes.append("Modo bug bounty activado por defecto (oculta del reporte los hallazgos que se cierran "
                     "como N/A). Desmárcalo si quieres verlos todos.")

    return ImportResult(program=program, notes=notes, filtered=filtered)
