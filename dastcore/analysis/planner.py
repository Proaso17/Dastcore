"""Adaptive scan planner — dastcore's decision brain.

Recon tells us WHAT a target is; this turns that into a prioritised strategy for WHERE to push, the way a
pentester sizes up a target before attacking. It is a deterministic expert system: signals in a
``TargetProfile`` (technology, CMS, SPA-vs-server-rendered, API kind, auth panel, WAF, subdomains) flow
through encoded heuristics into a ``ScanPlan`` — an ordered set of moves, each with its reasoning. No LLM,
no network: reproducible and auditable. The plan is both surfaced to the user (so the "thinking" is
visible) and used to steer the scan (focus the juicy hosts first, emphasise the relevant vuln classes).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass(frozen=True)
class TargetProfile:
    """What recon learned the target IS. All fields optional; the planner reasons over whatever is known."""

    tech: frozenset[str] = frozenset()          # display tech tags, e.g. {"WordPress", "PHP", "nginx"}
    languages: frozenset[str] = frozenset()     # normalized: php/java/node/dotnet/python/ruby
    cms: str = ""                               # "wordpress" | "drupal" | "joomla" | ""
    server: str = ""                            # "nginx" | "apache" | "iis" | ""
    is_spa: bool = False                        # client-rendered single-page app
    has_login: bool = False                     # an auth/login form or panel was seen
    api_kind: str = "none"                      # "rest" | "graphql" | "none"
    backend: str = "none"                       # "supabase" | "none"
    waf: bool = False
    hosts: tuple[str, ...] = ()                 # discovered hostnames in scope


@dataclass
class PlanItem:
    """One decided move: a short focus label, the vuln families it emphasises, and WHY."""

    focus: str
    families: tuple[str, ...]
    why: str


@dataclass
class ScanPlan:
    items: list[PlanItem] = field(default_factory=list)
    priority_families: tuple[str, ...] = ()     # de-duplicated, highest-priority first
    focus_hosts: tuple[str, ...] = ()           # hosts to scan first (juicy subdomains before marketing)
    push_auth: bool = False                     # a login panel → try weak creds / steer to authenticated scan
    use_headless: bool = False                  # SPA → render with the browser
    notes: list[str] = field(default_factory=list)


# Language → the vuln families that stack most exposes (a pentester's priors).
_LANG_FAMILIES: dict[str, tuple[str, ...]] = {
    "php": ("sqli", "lfi", "code-injection", "cmdi", "xxe"),
    "java": ("deserialization", "rce", "ssrf", "xxe", "sqli"),          # rce = Log4Shell (JNDI)
    "node": ("nosqli", "proto_pollution", "ssti", "cmdi"),
    "dotnet": ("deserialization", "sqli", "xxe"),
    "python": ("ssti", "sqli", "code-injection"),
    "ruby": ("ssti", "sqli", "code-injection"),
}
# Subdomain labels worth attacking before the marketing site.
_JUICY_HOST = re.compile(
    r"(?:^|[.\-])(admin|api|internal|intranet|staging|stage|dev|test|qa|uat|beta|preprod|pre-?prod|"
    r"portal|dashboard|panel|manage|console|auth|login|sso|vpn|git|jenkins|jira|grafana|kibana)(?:[.\-]|$)",
    re.IGNORECASE,
)


def _host_of(value: str) -> str:
    return urlsplit(value if "://" in value else f"//{value}").hostname or value


def order_hosts(hosts: tuple[str, ...]) -> tuple[str, ...]:
    """Juicy subdomains first (admin/api/staging/…), then the rest — original order preserved within each."""
    juicy = [h for h in hosts if _JUICY_HOST.search(_host_of(h))]
    rest = [h for h in hosts if not _JUICY_HOST.search(_host_of(h))]
    return tuple(dict.fromkeys(juicy + rest))


def plan_scan(profile: TargetProfile) -> ScanPlan:
    """Turn what the target IS into a prioritised strategy — the decision brain (deterministic)."""
    plan = ScanPlan()
    families: list[str] = []

    def add(focus: str, fams: tuple[str, ...], why: str) -> None:
        plan.items.append(PlanItem(focus=focus, families=fams, why=why))
        families.extend(fams)

    # Server-side language → injection/RCE surface it typically exposes.
    for lang in sorted(profile.languages):
        fams = _LANG_FAMILIES.get(lang)
        if fams:
            add(f"Stack {lang}", fams, f"stack {lang}: prioriza {', '.join(fams)} (superficie típica de ese lenguaje)")

    # CMS-specific playbooks.
    if profile.cms == "wordpress":
        add("WordPress", ("rce", "sqli", "xss"),
            "WordPress: revisa /wp-json y xmlrpc.php (SSRF/DoS/pingback), enumeración de usuarios (?author=N) y "
            "CVEs de plugins/temas (versión → CVE)")
    elif profile.cms == "drupal":
        add("Drupal", ("sqli", "rce"),
            "Drupal: Drupalgeddon (SQLi→RCE) y CVEs por versión")
    elif profile.cms == "joomla":
        add("Joomla", ("sqli", "lfi"), "Joomla: SQLi/LFI conocidos y CVEs por versión")

    # Client-rendered SPA → the browser is where the bugs are.
    if profile.is_spa:
        plan.use_headless = True
        add("SPA (cliente)", ("xss",),
            "SPA renderizada en cliente: DOM XSS + CSTI con el navegador headless, y secretos en el bundle JS")

    # API shape → authorization is the crown jewel.
    if profile.api_kind == "rest":
        add("API REST", ("authz", "mass_assignment", "sqli"),
            "API REST: BOLA/BFLA/IDOR (autorización a nivel de objeto/función) y mass assignment — el mayor riesgo real")
    elif profile.api_kind == "graphql":
        add("GraphQL", ("graphql", "authz"),
            "GraphQL: introspección, sugerencia de campos, batching/aliasing (DoS) e inyección en argumentos")

    if profile.backend == "supabase":
        add("Supabase", ("authz",),
            "Backend Supabase: mina tablas del bundle y prueba RLS/BOLA (lectura y escritura) con 2 identidades")

    # Auth panel → credentials and token attacks, and pivot to authenticated coverage.
    if profile.has_login:
        plan.push_auth = True
        add("Panel de autenticación", ("weak-creds", "jwt", "session"),
            "Panel de login detectado: prueba credenciales débiles, ataques a JWT y session fixation; escanea "
            "AUTENTICADO para desbloquear la superficie tras el login (aquí viven BOLA/BFLA)")

    if profile.waf:
        plan.notes.append("WAF/CDN delante: activa evasión (--waf-evasion) y usa insertion points 'moved'; "
                          "los hallazgos pueden salir parciales si bloquea el escaneo.")

    plan.focus_hosts = order_hosts(profile.hosts)
    if any(_JUICY_HOST.search(_host_of(h)) for h in profile.hosts):
        plan.notes.append("Subdominios jugosos primero: se escanean antes admin./api./staging./dev. que el sitio de marketing.")

    if not plan.items:
        add("Genérico", ("sqli", "xss", "lfi", "open_redirect"),
            "Sin señales fuertes de stack/CMS: cobertura base (SQLi, XSS, LFI, open redirect) sobre toda la superficie")

    plan.priority_families = tuple(dict.fromkeys(families))  # de-dup, keep first-seen (priority) order
    return plan


def render_plan(profile: TargetProfile, plan: ScanPlan) -> str:
    """A human-readable summary of the target profile and the chosen strategy — the visible 'thinking'."""
    ident = ", ".join(sorted(profile.tech)) or "sin fingerprint claro"
    lines = [f"Perfil del objetivo: {ident}."]
    shape = []
    if profile.is_spa:
        shape.append("SPA")
    if profile.api_kind != "none":
        shape.append(f"API {profile.api_kind}")
    if profile.backend != "none":
        shape.append(profile.backend)
    if profile.has_login:
        shape.append("panel de login")
    if profile.waf:
        shape.append("WAF")
    if shape:
        lines.append("Forma: " + ", ".join(shape) + ".")
    lines.append("Plan (prioridad): " + " → ".join(item.focus for item in plan.items) + ".")
    for item in plan.items:
        lines.append(f"  • {item.focus}: {item.why}")
    if plan.priority_families:
        lines.append(
            "Ataque priorizado (active scan): " + ", ".join(plan.priority_families[:8])
            + (" …" if len(plan.priority_families) > 8 else "")
            + " — estas clases se prueban primero (cola de requests y orden de reglas) y con MÁS intensidad "
              "(payloads intensivos + evasión de WAF automática), gastando el presupuesto donde es más "
              "probable que haya bug. Cada payload extra lo sigue confirmando el oráculo (cero falsos positivos)."
        )
    if plan.focus_hosts and len(plan.focus_hosts) > 1:
        lines.append("Orden de hosts: " + ", ".join(plan.focus_hosts[:6]) + (" …" if len(plan.focus_hosts) > 6 else "") + ".")
    lines.extend(f"  ⚠ {note}" for note in plan.notes)
    return "\n".join(lines)
