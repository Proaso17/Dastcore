"""Adaptive scan planner — dastcore's decision brain.

Recon tells us WHAT a target is; this turns that into a prioritised strategy for WHERE to push, the way a
pentester sizes up a target before attacking. It is a deterministic expert system: signals in a
``TargetProfile`` flow through encoded heuristics into a ``ScanPlan``. No LLM, no network: reproducible and
auditable. The plan is surfaced to the user (so the "thinking" is visible) and used to steer the scan
(focus the juicy hosts first, emphasise the relevant vuln classes, raise intensity on them).

The decision is a **confidence score per family**, not a flat list: every signal that fires contributes a
weighted vote with a cited reason, and the families are ranked by total score. So a PHP app where recon
actually observed ``file``/``path`` parameters scores LFI above a generic SQLi prior — the brain reasons
from evidence, not just stack priors, and every number is traceable (``family_scores`` + ``reasoning``).
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
    # --- deeper application analysis (all optional; the brain weighs whatever is present) ---
    frameworks: frozenset[str] = frozenset()    # specific frameworks: nextjs/laravel/rails/django/flask/spring/express/aspnet
    auth_kind: str = ""                         # "jwt" | "session" | "oauth" | "basic" | ""
    param_names: frozenset[str] = frozenset()   # every parameter name recon actually observed — real injectable surface
    endpoint_count: int = 0                     # size of the discovered surface
    has_file_upload: bool = False               # an upload endpoint/param was seen
    exposed_secrets: bool = False               # secrets/keys found in the JS bundle
    security_posture: str = ""                  # "hardened" | "mixed" | "lax" | "" — from the security-header posture
    waf_vendor: str = ""                        # "cloudflare" | "akamai" | "vercel" | "aws" | … (for targeted evasion)


@dataclass
class PlanItem:
    """One decided move: a short focus label, the vuln families it emphasises, and WHY."""

    focus: str
    families: tuple[str, ...]
    why: str


@dataclass
class HostPlan:
    """A per-host sub-plan: different hosts play different roles (admin vs api vs marketing), so the brain
    tailors the families to each instead of one strategy for the whole target."""

    host: str
    role: str                   # "admin" | "api" | "auth" | "staging" | "devops" | "web"
    families: tuple[str, ...]   # role-tailored families, blended with the target's global priorities
    why: str


@dataclass
class ScanPlan:
    items: list[PlanItem] = field(default_factory=list)
    priority_families: tuple[str, ...] = ()     # ranked by confidence score, highest first
    focus_hosts: tuple[str, ...] = ()           # hosts to scan first (juicy subdomains before marketing)
    push_auth: bool = False                     # a login panel → try weak creds / steer to authenticated scan
    use_headless: bool = False                  # SPA → render with the browser
    notes: list[str] = field(default_factory=list)
    family_scores: dict[str, float] = field(default_factory=dict)  # the per-family confidence (transparency)
    reasoning: list[str] = field(default_factory=list)             # the visible "thinking": why each family ranks
    host_plans: list[HostPlan] = field(default_factory=list)       # per-host strategy when the surface spans roles


# Language → the vuln families it most exposes (a pentester's priors). Order within a tuple is the prior
# ranking; the scorer weights by position so a pure-language profile keeps this exact order.
_LANG_FAMILIES: dict[str, tuple[str, ...]] = {
    "php": ("sqli", "lfi", "code-injection", "cmdi", "xxe"),
    "java": ("deserialization", "rce", "ssrf", "xxe", "sqli"),          # rce = Log4Shell (JNDI)
    "node": ("nosqli", "proto_pollution", "ssti", "cmdi"),
    "dotnet": ("deserialization", "sqli", "xxe"),
    "python": ("ssti", "sqli", "code-injection"),
    "ruby": ("ssti", "sqli", "code-injection"),
}
_LANG_BASE = 4.0  # weight of a language's top family; each next family in the tuple is worth 0.5 less

# Framework-specific playbooks: the families + the concrete note a pentester would act on.
_FRAMEWORK_FAMILIES: dict[str, tuple[str, ...]] = {
    "nextjs": ("ssrf", "open_redirect"),
    "laravel": ("sqli", "code-injection"),
    "symfony": ("sqli", "code-injection"),
    "rails": ("deserialization", "ssti", "sqli"),
    "django": ("ssti", "sqli"),
    "flask": ("ssti",),
    "spring": ("rce", "ssrf", "deserialization"),
    "express": ("nosqli", "proto_pollution", "ssti"),
    "aspnet": ("deserialization", "sqli", "xxe"),
}
_FRAMEWORK_NOTE: dict[str, str] = {
    "nextjs": "Next.js: SSRF en el optimizador de imágenes (/_next/image?url=), bypass de middleware, revisa /api/*.",
    "laravel": "Laravel: APP_DEBUG filtra env/trazas (Ignition RCE CVE-2021-3129); revisa /telescope y /_ignition.",
    "symfony": "Symfony: profiler/_fragment expuestos y deserialización; revisa /_profiler y /app_dev.php.",
    "rails": "Rails: deserialización de Marshal/cookie, y render de input (SSTI/ERB); revisa rutas con :id.",
    "django": "Django: SSTI si renderiza input y DEBUG=True expone settings/trazas; revisa /admin.",
    "flask": "Flask: SSTI (Jinja2) si renderiza input; revisa el modo debug (consola Werkzeug).",
    "spring": "Spring: Log4Shell (JNDI), Spring4Shell, actuator expuesto (/actuator/*), SSRF.",
    "express": "Express/Node: NoSQLi en filtros Mongo, prototype pollution, SSTI si usa plantillas.",
    "aspnet": "ASP.NET: deserialización (ViewState/BinaryFormatter); revisa endpoints .asmx/.svc.",
}
_FRAMEWORK_BASE = 3.0  # a detected framework is strong evidence — slightly under a full language stack

# Parameter-name evidence → families. Observing a real param is stronger than a generic stack prior, so
# these votes meaningfully reorder the ranking. Each distinct matching name votes once; capped per family.
_PARAM_SIGNALS: list[tuple[re.Pattern[str], tuple[tuple[str, float], ...]]] = [
    (re.compile(r"(?:^|[_\-.])(file|path|dir|folder|include|inc|page|template|tpl|doc|load|download)", re.I),
     (("lfi", 1.5),)),
    (re.compile(r"(?:^|[_\-.])(url|uri|redirect|redir|next|return|dest|destination|callback|continue|link)", re.I),
     (("open_redirect", 1.2), ("ssrf", 0.8))),
    (re.compile(r"(?:^|[_\-.])(id|uid|user|account|acct|order|object|owner|profile|customer)", re.I),
     (("authz", 1.5), ("sqli", 0.5))),
    (re.compile(r"(?:^|[_\-.])(cmd|exec|command|run|ping|shell|system)", re.I),
     (("cmdi", 1.5),)),
    (re.compile(r"(?:^|[_\-.])(query|search|keyword|filter|sort)", re.I),
     (("sqli", 0.8), ("xss", 0.6))),
    (re.compile(r"(?:^|[_\-.])(xml|import|feed|payload)", re.I),
     (("xxe", 1.0),)),
    (re.compile(r"(?:^|[_\-.])(name|comment|message|msg|subject|title|bio|desc)", re.I),
     (("xss", 0.6),)),
    (re.compile(r"(?:^|[_\-.])(upload|attachment|avatar|photo|image)", re.I),
     (("upload", 1.0),)),
]
_PARAM_CAP = 4.0  # a single family can gain at most this much from parameter names (a huge API can't swamp)

_AUTH_KIND_FAMILY: dict[str, tuple[str, float, str]] = {
    "jwt": ("jwt", 3.0, "token JWT: prueba alg=none, confusión de algoritmo, kid/jwk injection, secreto débil"),
    "session": ("session", 2.0, "sesión por cookie: session fixation, flags de cookie, fijación/rotación"),
    "oauth": ("oauth", 2.5, "OAuth: redirect_uri abierto, robo de code/token, CSRF de state, scope creep"),
    "basic": ("weak-creds", 1.5, "HTTP Basic: prueba credenciales débiles/por defecto"),
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


# A host's subdomain label reveals its ROLE, and the role changes the strategy: an admin panel is an
# authz target, an API is a BOLA/mass-assignment target, a staging box is usually under-hardened, a
# devops tool is a default-credentials/known-CVE target. First match wins; anything else is "web".
_HOST_ROLES: list[tuple[re.Pattern[str], str, tuple[str, ...], str]] = [
    (re.compile(r"(?:^|[.\-])(admin|dashboard|panel|manage|console|portal|backoffice)(?:[.\-]|$)", re.I), "admin",
     ("authz", "weak-creds", "jwt"),
     "panel de administración: autorización (BOLA/BFLA) y credenciales — la superficie tras el login"),
    (re.compile(r"(?:^|[.\-])(api|graphql|rest|gateway|gw)(?:[.\-]|$)", re.I), "api",
     ("authz", "mass_assignment", "sqli", "nosqli"),
     "API: BOLA/BFLA/IDOR y mass assignment — el mayor riesgo real de una API"),
    (re.compile(r"(?:^|[.\-])(auth|login|sso|accounts?|oauth|identity|idp)(?:[.\-]|$)", re.I), "auth",
     ("weak-creds", "jwt", "session"),
     "superficie de autenticación: credenciales débiles, ataques a JWT y a la sesión"),
    (re.compile(r"(?:^|[.\-])(staging|stage|dev|develop|test|qa|uat|beta|preprod|pre-?prod|sandbox)(?:[.\-]|$)", re.I),
     "staging", ("sqli", "xss", "lfi", "exposure"),
     "entorno no-productivo: suele estar menos endurecido, con debug/trazas y secretos expuestos"),
    (re.compile(r"(?:^|[.\-])(git|gitlab|jenkins|jira|grafana|kibana|vpn|ci|nexus|harbor|sonar)(?:[.\-]|$)", re.I),
     "devops", ("weak-creds", "rce"),
     "herramienta de infraestructura: prueba credenciales por defecto y CVEs conocidos de esa herramienta"),
]
_WEB_ROLE = ("web", ("xss", "open_redirect"), "sitio web/marketing: XSS reflejado y open redirect, más la "
             "cobertura base del stack")


def _classify_host(host: str) -> tuple[str, tuple[str, ...], str]:
    """(role, role families, why) for a hostname — first matching role wins, else a generic web role."""
    for pattern, role, families, why in _HOST_ROLES:
        if pattern.search(host):
            return role, families, why
    return _WEB_ROLE


def plan_hosts(hosts: tuple[str, ...], global_families: tuple[str, ...] = ()) -> list[HostPlan]:
    """A per-host sub-plan (juicy hosts first): each host's role-tailored families, blended with the
    target's global priorities so stack/framework evidence still applies everywhere."""
    plans: list[HostPlan] = []
    for host in order_hosts(tuple(hosts)):
        bare = _host_of(host)
        role, families, why = _classify_host(bare)
        blended = tuple(dict.fromkeys([*families, *global_families]))[:6]
        plans.append(HostPlan(host=bare, role=role, families=blended, why=why))
    return plans


def plan_scan(profile: TargetProfile) -> ScanPlan:
    """Turn what the target IS into a prioritised strategy — the decision brain (deterministic).

    Families are ranked by a confidence score: each signal casts a weighted, reasoned vote. Insertion
    order (first vote) breaks ties, so a pure-language profile keeps its prior ordering while observed
    evidence (frameworks, real parameter names, auth kind) reshapes the ranking."""
    plan = ScanPlan()
    scores: dict[str, float] = {}
    reasons: dict[str, list[str]] = {}

    def bump(family: str, weight: float, reason: str) -> None:
        scores[family] = round(scores.get(family, 0.0) + weight, 3)
        reasons.setdefault(family, []).append(reason)

    def add(focus: str, fams: tuple[str, ...], why: str) -> None:
        plan.items.append(PlanItem(focus=focus, families=fams, why=why))

    # Server-side language → the injection/RCE surface it typically exposes (weighted by prior rank).
    for lang in sorted(profile.languages):
        fams = _LANG_FAMILIES.get(lang)
        if fams:
            for index, fam in enumerate(fams):
                bump(fam, _LANG_BASE - index * 0.5, f"stack {lang}")
            add(f"Stack {lang}", fams,
                f"stack {lang}: prioriza {', '.join(fams)} (superficie típica de ese lenguaje)")

    # Specific frameworks → concrete, higher-signal playbooks.
    for fw in sorted(profile.frameworks):
        fams = _FRAMEWORK_FAMILIES.get(fw)
        if fams:
            for index, fam in enumerate(fams):
                bump(fam, _FRAMEWORK_BASE - index * 0.5, f"framework {fw}")
            note = _FRAMEWORK_NOTE.get(fw)
            add(f"Framework {fw}", fams, note or f"framework {fw}: playbook específico")
            if note:
                plan.notes.append(note)

    # CMS-specific playbooks.
    if profile.cms == "wordpress":
        for fam in ("rce", "sqli", "xss"):
            bump(fam, 3.0 if fam == "rce" else 2.0, "CMS WordPress")
        add("WordPress", ("rce", "sqli", "xss"),
            "WordPress: revisa /wp-json y xmlrpc.php (SSRF/DoS/pingback), enumeración de usuarios (?author=N) y "
            "CVEs de plugins/temas (versión → CVE)")
    elif profile.cms == "drupal":
        bump("sqli", 3.0, "CMS Drupal")
        bump("rce", 2.5, "CMS Drupal (Drupalgeddon)")
        add("Drupal", ("sqli", "rce"), "Drupal: Drupalgeddon (SQLi→RCE) y CVEs por versión")
    elif profile.cms == "joomla":
        bump("sqli", 3.0, "CMS Joomla")
        bump("lfi", 2.0, "CMS Joomla")
        add("Joomla", ("sqli", "lfi"), "Joomla: SQLi/LFI conocidos y CVEs por versión")

    # Client-rendered SPA → the browser is where the bugs are.
    if profile.is_spa:
        plan.use_headless = True
        bump("xss", 2.5, "SPA renderizada en cliente")
        add("SPA (cliente)", ("xss",),
            "SPA renderizada en cliente: DOM XSS + CSTI con el navegador headless, y secretos en el bundle JS")

    # API shape → authorization is the crown jewel.
    if profile.api_kind == "rest":
        bump("authz", 3.5, "API REST")
        bump("mass_assignment", 2.5, "API REST")
        bump("sqli", 1.0, "API REST")
        add("API REST", ("authz", "mass_assignment", "sqli"),
            "API REST: BOLA/BFLA/IDOR (autorización a nivel de objeto/función) y mass assignment — el mayor riesgo real")
    elif profile.api_kind == "graphql":
        bump("graphql", 3.5, "API GraphQL")
        bump("authz", 2.5, "API GraphQL")
        add("GraphQL", ("graphql", "authz"),
            "GraphQL: introspección, sugerencia de campos, batching/aliasing (DoS) e inyección en argumentos")

    if profile.backend == "supabase":
        bump("authz", 3.0, "backend Supabase (RLS)")
        add("Supabase", ("authz",),
            "Backend Supabase: mina tablas del bundle y prueba RLS/BOLA (lectura y escritura) con 2 identidades")

    # Auth panel → credentials and token attacks, and pivot to authenticated coverage.
    if profile.has_login:
        plan.push_auth = True
        for fam, weight in (("weak-creds", 2.5), ("jwt", 1.5), ("session", 1.5)):
            bump(fam, weight, "panel de login detectado")
        add("Panel de autenticación", ("weak-creds", "jwt", "session"),
            "Panel de login detectado: prueba credenciales débiles, ataques a JWT y session fixation; si unas "
            "credenciales por defecto funcionan, AUTO-PIVOTA (inicia sesión y escanea la superficie interna que "
            "desbloquean — el alcance real); aquí viven BOLA/BFLA")

    # Observed auth mechanism → the precise token/session attacks.
    spec = _AUTH_KIND_FAMILY.get(profile.auth_kind)
    if spec is not None:
        fam, weight, why = spec
        bump(fam, weight, f"auth {profile.auth_kind}")
        plan.notes.append(why)

    # Real injectable surface: the parameter names recon actually observed (evidence beats priors).
    param_gain: dict[str, float] = {}
    param_hits: dict[str, set[str]] = {}
    for name in sorted(profile.param_names):
        for pattern, votes in _PARAM_SIGNALS:
            if pattern.search(name):
                for fam, weight in votes:
                    param_gain[fam] = min(param_gain.get(fam, 0.0) + weight, _PARAM_CAP)
                    param_hits.setdefault(fam, set()).add(name)
    for fam, gain in param_gain.items():
        sample = ", ".join(sorted(param_hits[fam])[:3])
        bump(fam, round(gain, 3), f"params observados ({sample})")

    if profile.has_file_upload:
        bump("upload", 3.0, "endpoint/campo de subida de ficheros")
        add("Subida de ficheros", ("upload",),
            "Se observó subida de ficheros: prueba tipos/extensiones ejecutables y path traversal en el nombre")

    # Security posture from the header hardening — where is the value likely to be.
    if profile.security_posture == "lax":
        for fam in ("sqli", "xss", "lfi"):
            bump(fam, 0.8, "postura laxa (faltan cabeceras de seguridad)")
        plan.notes.append("Postura laxa (faltan cabeceras de seguridad): app poco endurecida, la inyección es más "
                          "probable — barrido amplio.")
    elif profile.security_posture == "hardened":
        bump("authz", 1.0, "postura endurecida (cabeceras completas)")
        plan.notes.append("Postura endurecida (cabeceras completas): la inyección obvia es menos probable; el valor "
                          "está en lógica de negocio y autorización (BOLA/BFLA).")

    if profile.exposed_secrets:
        plan.notes.append("Secretos/API keys expuestos en el bundle JS: valídalos y repórtalos; pueden abrir más superficie.")

    if profile.waf:
        vendor = f" ({profile.waf_vendor})" if profile.waf_vendor else ""
        plan.notes.append(f"WAF/CDN delante{vendor}: activa evasión (--waf-evasion) y usa insertion points 'moved'; "
                          "los hallazgos pueden salir parciales si bloquea el escaneo.")

    plan.focus_hosts = order_hosts(profile.hosts)
    if any(_JUICY_HOST.search(_host_of(h)) for h in profile.hosts):
        plan.notes.append("Subdominios jugosos primero: se escanean antes admin./api./staging./dev. que el sitio de marketing.")

    # Nothing distinctive learned → base coverage. (A client-only SPA already added its own item above, so
    # this only fires for a genuinely featureless target.)
    if not scores:
        for fam, weight in (("sqli", 3.0), ("xss", 2.5), ("lfi", 2.0), ("open_redirect", 1.5)):
            bump(fam, weight, "sin señales fuertes de stack/CMS")
        add("Genérico", ("sqli", "xss", "lfi", "open_redirect"),
            "Sin señales fuertes de stack/CMS: cobertura base (SQLi, XSS, LFI, open redirect) sobre toda la superficie")

    # Rank by confidence; stable on ties (dict insertion order = first vote).
    plan.priority_families = tuple(sorted(scores, key=lambda f: -scores[f]))
    plan.family_scores = scores
    plan.reasoning = [
        f"{fam} ({scores[fam]:.1f}): " + "; ".join(dict.fromkeys(reasons[fam]))
        for fam in plan.priority_families[:8]
    ]
    # Per-host sub-plans when the surface spans more than one host or has a role-bearing subdomain:
    # the admin panel, the API and the marketing site each warrant a different strategy.
    distinct_hosts = {_host_of(h) for h in profile.hosts}
    if len(distinct_hosts) > 1 or any(_JUICY_HOST.search(h) for h in distinct_hosts):
        plan.host_plans = plan_hosts(profile.hosts, plan.priority_families)
    return plan


def render_plan(profile: TargetProfile, plan: ScanPlan) -> str:
    """A human-readable summary of the target profile and the chosen strategy — the visible 'thinking'."""
    ident = ", ".join(sorted(profile.tech)) or "sin fingerprint claro"
    lines = [f"Perfil del objetivo: {ident}."]
    shape = []
    if profile.frameworks:
        shape.append("/".join(sorted(profile.frameworks)))
    if profile.is_spa:
        shape.append("SPA")
    if profile.api_kind != "none":
        shape.append(f"API {profile.api_kind}")
    if profile.backend != "none":
        shape.append(profile.backend)
    if profile.has_login:
        shape.append("panel de login")
    if profile.auth_kind:
        shape.append(f"auth {profile.auth_kind}")
    if profile.endpoint_count:
        shape.append(f"{profile.endpoint_count} endpoints")
    if profile.security_posture:
        shape.append(f"postura {profile.security_posture}")
    if profile.waf:
        shape.append("WAF" + (f" {profile.waf_vendor}" if profile.waf_vendor else ""))
    if shape:
        lines.append("Forma: " + ", ".join(shape) + ".")
    lines.append("Plan (prioridad): " + " → ".join(item.focus for item in plan.items) + ".")
    for item in plan.items:
        lines.append(f"  • {item.focus}: {item.why}")
    if plan.reasoning:
        lines.append("Razonamiento (familia → puntuación → evidencia):")
        lines.extend(f"  · {line}" for line in plan.reasoning)
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
    if plan.host_plans:
        lines.append("Plan por host (rol → familias):")
        for hp in plan.host_plans[:8]:
            lines.append(f"  · {hp.host} [{hp.role}]: {', '.join(hp.families)} — {hp.why}")
    lines.extend(f"  ⚠ {note}" for note in plan.notes)
    return "\n".join(lines)
