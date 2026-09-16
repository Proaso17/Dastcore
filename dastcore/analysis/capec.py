"""CAPEC attack-pattern knowledge for the planner brain — pentesting "training" encoded as data.

MITRE's CAPEC (Common Attack Pattern Enumeration and Classification, https://capec.mitre.org) catalogues
*how* adversaries attack. Each pattern carries prerequisites (what the target must expose for the attack to
apply), a likelihood, a typical severity, and the CWEs it targets. This module distils the web-application
patterns most relevant to a black-box DAST into a curated catalogue and maps each one to:

  * the **prerequisite signal** on a ``TargetProfile`` that makes it applicable (observed params/paths/API/
    login/backend — real evidence, NOT a bare stack prior), and
  * the dastcore **vuln family** it drives, weighted by CAPEC likelihood.

The planner consults this to (a) contribute likelihood-weighted, CAPEC-cited votes to the family ranking and
(b) surface the attack patterns + how a pentester works each — so the brain reasons from the attack catalogue,
transparently, like an analyst who has done the reading. It only influences PRIORITISATION and the visible
reasoning; it never changes what counts as a finding (every finding still passes its detector's oracle), so
the zero-false-positive guarantee is untouched.

Design rule (pinned by the planner tests): a pattern applies only on an OBSERVED prerequisite, never on a
language/CMS prior alone — so CAPEC reinforces and explains an evidence-rich profile without perturbing the
stack-prior rankings the brain already computes.

CAPEC ids, names, likelihoods, severities and CWE mappings here are taken from the MITRE CAPEC catalogue.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from dastcore.analysis.planner import TargetProfile

# CAPEC "Likelihood Of Attack" → the weight its vote adds to a family. Modest and additive: CAPEC reinforces
# the evidence-based score without swamping it, and the per-family total is capped below.
_LIKELIHOOD_WEIGHT: dict[str, float] = {"high": 1.2, "medium": 0.8, "low": 0.5}
_CAPEC_FAMILY_CAP: float = 2.5  # a single family can gain at most this much from all CAPEC patterns combined


@dataclass(frozen=True)
class AttackPattern:
    """One CAPEC attack pattern, mapped to the target signal that makes it applicable and the dastcore
    family it drives. ``applies`` is a deterministic predicate over the recon ``TargetProfile``."""

    capec_id: str          # e.g. "CAPEC-66"
    name: str              # CAPEC pattern name
    family: str            # dastcore vuln family this pattern drives (must be a family the scanner knows)
    cwes: tuple[str, ...]  # CWE ids the pattern targets (for coverage mapping to dastcore's detectors)
    likelihood: str        # "high" | "medium" | "low" (CAPEC Likelihood Of Attack)
    severity: str          # "very high" | "high" | "medium" | "low" (CAPEC Typical Severity)
    why: str               # how a pentester works this pattern (the encoded technique / "training")
    applies: Callable[[TargetProfile], bool]  # prerequisite check against observed recon signals

    def weight(self) -> float:
        return _LIKELIHOOD_WEIGHT.get(self.likelihood, 0.6)


# --- prerequisite helpers: map CAPEC prerequisites to OBSERVED recon signals (params/paths/shape) ----------
def _param(rx: re.Pattern[str]) -> Callable[[TargetProfile], bool]:
    return lambda p: any(rx.search(n) for n in p.param_names)


def _path(rx: re.Pattern[str]) -> Callable[[TargetProfile], bool]:
    return lambda p: any(rx.search(s) for s in p.paths)


def _any(*preds: Callable[[TargetProfile], bool]) -> Callable[[TargetProfile], bool]:
    return lambda p: any(pred(p) for pred in preds)


_PX_QUERY = re.compile(r"(?:^|[_\-.])(q|query|search|keyword|kw|term|filter|sort|order|name|email|id)(?:$|[_\-.])", re.I)
_PX_OBJECT = re.compile(r"(?:^|[_\-.])(id|uid|user|account|acct|owner|object|profile|order|customer|doc|record)", re.I)
_PX_FILE = re.compile(r"(?:^|[_\-.])(file|path|dir|folder|include|inc|page|template|tpl|doc|load|download|view)", re.I)
_PX_CMD = re.compile(r"(?:^|[_\-.])(cmd|exec|command|run|ping|shell|system|host|ip|domain)", re.I)
_PX_URL = re.compile(r"(?:^|[_\-.])(url|uri|redirect|redir|next|return|dest|destination|callback|continue|link|feed|import|proxy|fetch)", re.I)
_PX_XML = re.compile(r"(?:^|[_\-.])(xml|import|feed|soap|wsdl|rss|sitemap|data)", re.I)
_PX_TEXT = re.compile(r"(?:^|[_\-.])(name|comment|message|msg|subject|title|bio|desc|body|content|text|search|q)(?:$|[_\-.])", re.I)
_PX_CRLF = re.compile(r"(?:^|[_\-.])(url|redirect|location|header|lang|locale|ref|referer|next)", re.I)
_PX_UPLOAD = re.compile(r"(?:^|[_\-.])(upload|attachment|avatar|photo|image|document|media)", re.I)

_PT_ADMIN = re.compile(r"/(admin|administrator|dashboard|manage|management|console|backoffice|wp-admin)(/|$)", re.I)
_PT_OBJECT = re.compile(r"/(users?|accounts?|profiles?|orders?|objects?|items?|documents?|invoices?)(/|$)", re.I)
_PT_UPLOAD = re.compile(r"/(upload|uploads|media|files?|attachments?|import)(/|$)", re.I)


def _has_query_surface(p: TargetProfile) -> bool:
    return p.api_kind == "rest" or any(_PX_QUERY.search(n) for n in p.param_names)


def _db_backed(p: TargetProfile) -> bool:
    # A data-driven app whose input reaches a query: an observed query/object param, a REST API, or a
    # Supabase/SQL backend. Never fires on a bare language prior (no observed surface) — the design rule.
    return _has_query_surface(p) or p.backend == "supabase" or _db_object(p)


def _db_object(p: TargetProfile) -> bool:
    return any(_PX_OBJECT.search(n) for n in p.param_names) or any(_PT_OBJECT.search(s) for s in p.paths)


# --- the curated catalogue (web-application CAPEC patterns, grounded in the MITRE catalogue) ---------------
_CATALOG: tuple[AttackPattern, ...] = (
    # Inject Unexpected Items (CAPEC-152)
    AttackPattern(
        "CAPEC-66", "SQL Injection", "sqli", ("CWE-89", "CWE-1286"), "high", "high",
        "Inyecta metacaracteres SQL en parámetros que llegan a una consulta; confirma con lógica booleana, "
        "errores y tiempo (blind). Enumera esquema/credenciales si es explotable.",
        _db_backed,
    ),
    AttackPattern(
        "CAPEC-63", "Cross-Site Scripting (XSS)", "xss", ("CWE-79", "CWE-20"), "high", "very high",
        "Refleja/almacena un marcador y comprueba si se ejecuta en el DOM; prueba contextos HTML/atributo/JS "
        "y, en SPA, DOM XSS y sinks del cliente.",
        _any(_param(_PX_TEXT), lambda p: p.is_spa),
    ),
    AttackPattern(
        "CAPEC-88", "OS Command Injection", "cmdi", ("CWE-78",), "high", "very high",
        "Encadena separadores de shell (; | && `$()`) en parámetros que invocan procesos; confirma out-of-band "
        "o por tiempo (sleep/ping).",
        _param(_PX_CMD),
    ),
    AttackPattern(
        "CAPEC-126", "Path Traversal", "lfi", ("CWE-22",), "high", "very high",
        "Sube directorios (../, codificaciones, null byte) en parámetros de fichero/ruta para leer fuera del "
        "directorio permitido; encadena a LFI/inclusión.",
        _param(_PX_FILE),
    ),
    AttackPattern(
        "CAPEC-242", "Code Injection", "code-injection", ("CWE-94",), "medium", "high",
        "Inyecta código del lenguaje/plantilla del servidor (SSTI incluido) donde el input se evalúa; confirma "
        "con expresiones aritméticas y primitivas del motor.",
        _any(_param(re.compile(r"(?:^|[_\-.])(template|tpl|eval|code|expr|render|preview)", re.I))),
    ),
    AttackPattern(
        "CAPEC-250", "XML Injection", "xxe", ("CWE-91", "CWE-611"), "medium", "high",
        "Inyecta estructura/entidades externas donde se parsea XML; prueba XXE (lectura de ficheros, SSRF) y "
        "expansión de entidades.",
        _param(_PX_XML),
    ),
    AttackPattern(
        "CAPEC-676", "NoSQL Injection", "nosqli", ("CWE-943",), "medium", "high",
        "Inyecta operadores de consulta (p. ej. $ne/$gt/$where de Mongo) en filtros JSON de una API para "
        "saltar autenticación o exfiltrar.",
        _any(lambda p: "express" in p.frameworks, lambda p: p.api_kind == "rest" and "node" in p.languages),
    ),
    AttackPattern(
        "CAPEC-136", "LDAP Injection", "ldap", ("CWE-90",), "low", "high",
        "Inyecta metacaracteres de filtro LDAP (*, ), &, |) en login/búsqueda contra un directorio para "
        "saltar autenticación o enumerar.",
        lambda p: p.has_login,
    ),
    AttackPattern(
        "CAPEC-83", "XPath Injection", "xpath", ("CWE-643",), "low", "medium",
        "Inyecta sintaxis XPath en parámetros de búsqueda cuyo backend consulta XML para saltar filtros o "
        "extraer nodos.",
        _param(re.compile(r"(?:^|[_\-.])(q|query|search|filter|user|name)(?:$|[_\-.])", re.I)),
    ),
    AttackPattern(
        "CAPEC-34", "HTTP Response Splitting", "crlf", ("CWE-113",), "low", "medium",
        "Inyecta CR/LF en valores reflejados en cabeceras (redirect/location/lang) para partir la respuesta o "
        "envenenar caché.",
        _param(_PX_CRLF),
    ),
    AttackPattern(
        "CAPEC-460", "HTTP Parameter Pollution (HPP)", "hpp", ("CWE-88", "CWE-235"), "medium", "medium",
        "Envía parámetros duplicados; según qué capa gane (primero/último/concatena) puede saltar validación "
        "o reglas del WAF y alterar la lógica de la app.",
        lambda p: bool(p.param_names) or p.api_kind == "rest",
    ),
    # Subvert Access Control (CAPEC-225)
    AttackPattern(
        "CAPEC-1", "Accessing Functionality Not Properly Constrained by ACLs", "authz",
        ("CWE-285", "CWE-862"), "high", "high",
        "Descubre recursos/funciones y accede directo sin pasar por el control (BFLA): fuerza rutas de admin y "
        "acciones privilegiadas desde un rol bajo o sin sesión.",
        _any(_path(_PT_ADMIN), lambda p: p.api_kind != "none"),
    ),
    AttackPattern(
        "CAPEC-87", "Forceful Browsing", "authz", ("CWE-425",), "medium", "medium",
        "Navega a URLs no enlazadas (paneles, exports, backups, objetos por id) que el servidor no protege por "
        "sesión/rol.",
        _any(_path(_PT_ADMIN), _path(_PT_OBJECT)),
    ),
    AttackPattern(
        "CAPEC-77", "Manipulating User-Controlled Variables (IDOR/BOLA)", "authz", ("CWE-639", "CWE-863"),
        "high", "high",
        "Cambia identificadores de objeto controlados por el usuario para acceder a datos de otras cuentas "
        "(BOLA/IDOR); compara con ≥2 identidades e incluye verbos de escritura.",
        _any(_param(_PX_OBJECT), _path(_PT_OBJECT), lambda p: p.backend == "supabase"),
    ),
    AttackPattern(
        "CAPEC-115", "Authentication Bypass", "authz", ("CWE-287",), "medium", "medium",
        "Busca caminos que eluden el login (rutas alternativas, parámetros de rol, verbos/normalización de "
        "ruta, tokens predecibles).",
        lambda p: p.has_login,
    ),
    AttackPattern(
        "CAPEC-49", "Password Brute Forcing", "weak-creds", ("CWE-307", "CWE-521"), "high", "high",
        "Prueba credenciales por defecto/débiles contra el login respetando rate-limit; verifica bloqueo de "
        "cuenta y enumeración de usuarios.",
        lambda p: p.has_login,
    ),
    AttackPattern(
        "CAPEC-593", "Session Hijacking", "session", ("CWE-384", "CWE-287"), "high", "very high",
        "Analiza la gestión de sesión: entropía del token, flags de cookie (HttpOnly/Secure/SameSite), "
        "rotación tras login y expiración.",
        _any(lambda p: p.auth_kind == "session", lambda p: p.has_login),
    ),
    AttackPattern(
        "CAPEC-61", "Session Fixation", "session", ("CWE-384",), "medium", "medium",
        "Comprueba si el identificador de sesión se rota al autenticarse; si no, un id fijado por el atacante "
        "queda autenticado.",
        lambda p: p.auth_kind == "session",
    ),
    AttackPattern(
        "CAPEC-62", "Cross-Site Request Forgery (CSRF)", "csrf", ("CWE-352",), "medium", "high",
        "Comprueba si las acciones que cambian estado aceptan peticiones cross-site sin token anti-CSRF ni "
        "SameSite; forja una petición desde otro origen.",
        lambda p: p.has_login,
    ),
    # Abuse Existing Functionality (CAPEC-210)
    AttackPattern(
        "CAPEC-664", "Server Side Request Forgery (SSRF)", "ssrf", ("CWE-918", "CWE-20"), "high", "high",
        "Apunta un parámetro de URL/callback/import a recursos internos (169.254.169.254, localhost) y "
        "confirma out-of-band; en Next.js revisa el optimizador de imágenes (/_next/image?url=).",
        _any(_param(_PX_URL), lambda p: "nextjs" in p.frameworks),
    ),
    # Manipulate Data Structures (CAPEC-255)
    AttackPattern(
        "CAPEC-586", "Object Injection (Insecure Deserialization)", "deserialization", ("CWE-502",),
        "medium", "high",
        "Envía objetos serializados manipulados donde el servidor deserializa datos del cliente "
        "(ViewState/Marshal/pickle/Java) para lograr ejecución.",
        _any(lambda p: bool(p.languages & {"java", "dotnet", "ruby"}),
             lambda p: bool(p.frameworks & {"rails", "spring", "aspnet"})),
    ),
    # Abuse Existing Functionality / manipulate resources — file upload, caching, proxy chain, UI redress
    AttackPattern(
        "CAPEC-650", "Upload a Web Shell to a Web Server", "upload", ("CWE-434", "CWE-553"), "medium", "high",
        "Sube un fichero ejecutable (extensión/MIME/doble extensión/null byte) a una ruta accesible para "
        "lograr ejecución; encadena con path traversal en el nombre.",
        _any(lambda p: p.has_file_upload, _param(_PX_UPLOAD), _path(_PT_UPLOAD)),
    ),
    AttackPattern(
        "CAPEC-141", "Cache Poisoning", "cache-poisoning", ("CWE-345", "CWE-349"), "high", "high",
        "Envenena la caché con entradas no incluidas en la clave (cabeceras unkeyed) o por desincronización, "
        "para que otros usuarios reciban tu respuesta manipulada.",
        lambda p: p.waf or p.endpoint_count >= 10,
    ),
    AttackPattern(
        "CAPEC-33", "HTTP Request Smuggling", "smuggling", ("CWE-444",), "medium", "high",
        "Aprovecha que el proxy/CDN y el backend interpretan distinto Content-Length/Transfer-Encoding para "
        "colar una petición oculta y envenenar la cola o la caché.",
        lambda p: p.waf,
    ),
    AttackPattern(
        "CAPEC-103", "Clickjacking", "clickjacking", ("CWE-1021",), "medium", "high",
        "Superpone la UI sensible en un iframe transparente para robar clics; comprueba falta de "
        "X-Frame-Options / CSP frame-ancestors en las acciones autenticadas.",
        lambda p: p.has_login,
    ),
)

# The dastcore vuln families a pattern is allowed to drive (keeps the catalogue aligned with the scanner).
KNOWN_FAMILIES: frozenset[str] = frozenset(
    {"sqli", "xss", "cmdi", "lfi", "code-injection", "xxe", "nosqli", "ldap", "xpath", "crlf",
     "authz", "weak-creds", "session", "csrf", "ssrf", "deserialization",
     "hpp", "upload", "cache-poisoning", "smuggling", "clickjacking"}
)


# Coverage is judged at the FAMILY level, not by strict per-pattern CWE. A CAPEC pattern's MITRE CWE is
# often not the exact CWE dastcore emits for that family (e.g. dastcore reports LFI as CWE-98 while
# CAPEC-126 lists CWE-22), so matching CWEs would falsely under-report real coverage. Every family in the
# catalogue is one dastcore ACTIVELY tests — that is how each pattern was mapped — so catalogue patterns are
# covered; the honest signal in the maturity map is the reference GAPS below (attacks dastcore can't test).
#
# Families whose coverage is real but SHALLOW (passive/heuristic), shown as "partial" rather than "full".
_PARTIAL_FAMILIES: frozenset[str] = frozenset({"clickjacking", "csrf"})

# Reference gaps: high-value web CAPEC patterns dastcore does NOT cover, so the maturity map is honest about
# its blind spots (a DAST can't see business logic / social engineering / network position; DoS is opt-in).
_REFERENCE_GAPS: tuple[tuple[str, str, str, str], ...] = (
    ("CAPEC-26", "Leveraging Race Conditions", "logic",
     "condiciones de carrera / TOCTOU: requieren envío concurrente + verificación de estado; no cubierto"),
    ("CAPEC-212", "Functionality Misuse", "business-logic",
     "abuso de lógica de negocio: depende del significado de la app; no es genéricamente detectable en DAST"),
    ("CAPEC-98", "Phishing", "social",
     "ingeniería social: fuera del alcance de un DAST"),
    ("CAPEC-125", "Flooding (DoS)", "dos",
     "denegación de servicio / agotamiento de recursos: intrusivo; solo bajo --dos explícito, no por defecto"),
    ("CAPEC-94", "Adversary in the Middle (AiTM)", "mitm",
     "requiere posición de red; fuera del alcance de un DAST de aplicación"),
    ("CAPEC-148", "Content Spoofing", "content",
     "content/UI spoofing: parcial; se detecta el reflejo pero no el engaño visual completo"),
)


@dataclass(frozen=True)
class CoverageEntry:
    """One row of the CAPEC maturity map: a pattern and how well dastcore covers it."""

    capec_id: str
    name: str
    area: str      # dastcore family (for catalogue rows) or a gap-area label (for reference gaps)
    status: str    # "full" (active detector) | "partial" (passive/heuristic) | "none" (gap)
    detail: str    # the CWEs the pattern targets, or why it's a gap


def coverage_report() -> dict[str, object]:
    """The CAPEC maturity map: for every catalogue pattern the coverage dastcore has for its family
    (full / partial), plus the reference gaps it deliberately or inherently does not test (none). Coverage
    is family-level (see the note on ``_PARTIAL_FAMILIES``); the target CWEs are shown for reference."""
    rows: list[CoverageEntry] = []
    for ap in _CATALOG:
        status = "partial" if ap.family in _PARTIAL_FAMILIES else "full"
        depth = "pasiva/heurística" if status == "partial" else "detector activo"
        rows.append(CoverageEntry(ap.capec_id, ap.name, ap.family, status,
                                  f"{depth} · CWE objetivo {', '.join(ap.cwes)}"))
    gaps = [CoverageEntry(cid, name, area, "none", reason) for cid, name, area, reason in _REFERENCE_GAPS]
    all_rows = rows + gaps
    counts = {s: sum(1 for e in all_rows if e.status == s) for s in ("full", "partial", "none")}
    return {"rows": all_rows, "catalogue": rows, "gaps": gaps, "counts": counts, "total": len(all_rows)}


def applicable_patterns(profile: TargetProfile) -> list[AttackPattern]:
    """The CAPEC patterns whose prerequisites the recon profile satisfies — the attacks that actually apply
    to THIS target, in catalogue order (most-cited injection/access-control first)."""
    return [ap for ap in _CATALOG if ap.applies(profile)]


def patterns_for_families(
    patterns: Iterable[AttackPattern], families: Iterable[str]
) -> list[AttackPattern]:
    """The subset of ``patterns`` whose family is in ``families`` — used to attach the applicable attack
    patterns to a functional area or a per-host plan (so each zone/host cites how it is attacked)."""
    wanted = set(families)
    return [ap for ap in patterns if ap.family in wanted]


def label_patterns(patterns: Iterable[AttackPattern]) -> tuple[str, ...]:
    """Short ``"CAPEC-66 SQL Injection"`` labels for display on an area/host plan (deduped, order kept)."""
    return tuple(dict.fromkeys(f"{ap.capec_id} {ap.name}" for ap in patterns))


def capec_family_votes(profile: TargetProfile) -> list[tuple[str, float, str]]:
    """Likelihood-weighted, CAPEC-cited votes per family for the planner's scorer — capped per family so a
    family with many applicable patterns can't swamp the evidence-based score. Returns (family, weight,
    reason) with the reason naming the CAPEC ids, e.g. ``("authz", 2.5, "CAPEC (CAPEC-1, CAPEC-77): …")``."""
    gain: dict[str, float] = {}
    ids: dict[str, list[str]] = {}
    for ap in applicable_patterns(profile):
        gain[ap.family] = min(gain.get(ap.family, 0.0) + ap.weight(), _CAPEC_FAMILY_CAP)
        ids.setdefault(ap.family, []).append(ap.capec_id)
    votes: list[tuple[str, float, str]] = []
    for family, weight in gain.items():
        cited = ", ".join(dict.fromkeys(ids[family]))
        votes.append((family, round(weight, 3), f"patrones CAPEC ({cited})"))
    return votes
