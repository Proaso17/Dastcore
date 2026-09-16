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
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:  # avoid a runtime import cycle (capec imports TargetProfile from this module)
    from dastcore.analysis.capec import AttackPattern


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
    paths: frozenset[str] = frozenset()         # distinct URL paths observed — the basis for functional-area mapping
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
    capec: tuple[str, ...] = () # applicable CAPEC attack patterns for this host's families (see capec.py)


@dataclass
class AreaPlan:
    """A functional AREA of the application and how to work it — the way a pentester maps a target into
    zones (auth, API, admin, objects/IDOR, uploads, search, commerce, content) and then focuses each zone
    on the bug classes it tends to hide, rather than spraying the whole app uniformly."""

    name: str                       # "Autenticación", "API", "Administración", "Subida de ficheros", …
    families: tuple[str, ...]       # the vuln classes to focus on in this area
    signals: tuple[str, ...]        # the evidence that revealed the area (flags/paths/params)
    recon_paths: tuple[str, ...]    # high-signal paths to probe for this area
    why: str                        # how a pentester works the area (the techniques)
    capec: tuple[str, ...] = ()     # applicable CAPEC attack patterns for this area's families (see capec.py)


@dataclass
class ReconPlan:
    """How the brain decides to RECONNOITRE this target — the reconnaissance half of the decision, made
    from what the target appears to be. Which discovery techniques are worth it, the high-signal paths to
    probe for this stack, and how deep to go — so recon effort lands where the surface actually is."""

    use_headless: bool = False            # client-rendered → render with the browser to see the real surface
    extract_js_endpoints: bool = False    # SPA / JS-heavy → mine API endpoints (and secrets) from JS bundles
    discover_api_schemas: bool = False    # API-shaped → hunt OpenAPI/GraphQL schemas and ingest them
    mine_params: bool = False             # thin observed surface → mine hidden parameters (Arjun-style)
    probe_paths: tuple[str, ...] = ()     # stack-specific high-signal paths (/actuator, /.env, /wp-json…)
    depth: str = "standard"               # "light" | "standard" | "aggressive" — crawl/dirbust effort
    reasoning: list[str] = field(default_factory=list)  # the visible "thinking" behind each recon choice


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
    areas: list[AreaPlan] = field(default_factory=list)            # functional-area map (pentester decomposition)
    recon: ReconPlan = field(default_factory=ReconPlan)            # the reconnaissance strategy (see plan_recon)
    attack_patterns: list[AttackPattern] = field(default_factory=list)  # applicable CAPEC patterns (see capec.py)


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

# High-signal paths to probe per stack during recon — the ones a pentester checks first because they
# leak config/source/admin or expose a known-CVE endpoint. Far better signal than a generic wordlist.
_FRAMEWORK_RECON_PATHS: dict[str, tuple[str, ...]] = {
    "nextjs": ("/_next/image?url=/", "/api/", "/_next/static/"),
    "laravel": ("/.env", "/telescope", "/_ignition/execute-solution", "/storage/logs/laravel.log"),
    "symfony": ("/_profiler", "/app_dev.php", "/_fragment"),
    "rails": ("/rails/info/routes", "/rails/info/properties"),
    "django": ("/admin/", "/static/", "/__debug__/"),
    "flask": ("/console", "/static/"),
    "spring": ("/actuator", "/actuator/env", "/actuator/heapdump", "/actuator/gateway/routes"),
    "express": ("/api/", "/status", "/debug"),
    "aspnet": ("/trace.axd", "/elmah.axd", "/Telerik.Web.UI.WebResource.axd"),
}
_CMS_RECON_PATHS: dict[str, tuple[str, ...]] = {
    "wordpress": ("/wp-json/wp/v2/users", "/xmlrpc.php", "/wp-login.php", "/wp-content/debug.log"),
    "drupal": ("/user/login", "/CHANGELOG.txt", "/sites/default/files/"),
    "joomla": ("/administrator/", "/configuration.php-dist"),
}
_API_RECON_PATHS: dict[str, tuple[str, ...]] = {
    "rest": ("/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/api-docs", "/v2/api-docs"),
    "graphql": ("/graphql", "/graphiql", "/v1/graphql", "/api/graphql"),
}
_SUPABASE_RECON_PATHS = ("/rest/v1/", "/graphql/v1", "/auth/v1/settings")

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

# Observed URL paths are evidence too: an app that exposes /admin, /upload or /checkout tells you where its
# sensitive functions live. Each distinct matching path votes once (capped), like parameter names.
_PATH_SIGNALS: list[tuple[re.Pattern[str], tuple[tuple[str, float], ...]]] = [
    (re.compile(r"/(admin|administrator|dashboard|manage|management|console|backoffice|wp-admin)(/|$)", re.I),
     (("authz", 1.5),)),
    (re.compile(r"/(api|v\d+|graphql|graphiql|rest)(/|$)", re.I), (("authz", 1.2), ("mass_assignment", 0.8))),
    (re.compile(r"/(login|signin|register|signup|password|passwd|reset|forgot|sso|oauth|oidc|auth|token|mfa|otp)", re.I),
     (("weak-creds", 1.2), ("jwt", 0.5))),
    (re.compile(r"/(upload|uploads|media|files?|attachments?|import)(/|$)", re.I), (("upload", 1.2),)),
    (re.compile(r"/(search|query|find|lookup|autocomplete)(/|$)", re.I), (("sqli", 0.8), ("xss", 0.6))),
    (re.compile(r"/(users?|accounts?|profiles?|orders?|objects?|items?|documents?|invoices?)(/|$)", re.I),
     (("authz", 1.2),)),
    (re.compile(r"/(cart|checkout|payment|pay|billing|invoice|coupon|discount|subscription)(/|$)", re.I),
     (("authz", 1.0),)),
    (re.compile(r"/(redirect|redir|goto|out|away|return|url|link|continue)(/|$)", re.I),
     (("open_redirect", 1.0), ("ssrf", 0.5))),
]
_PATH_CAP = 3.0  # a family can gain at most this much from observed paths (bounded like parameter names)

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


def plan_hosts(
    hosts: tuple[str, ...], global_families: tuple[str, ...] = (),
    patterns: tuple[AttackPattern, ...] = (),
) -> list[HostPlan]:
    """A per-host sub-plan (juicy hosts first): each host's role-tailored families, blended with the
    target's global priorities so stack/framework evidence still applies everywhere. When ``patterns`` (the
    target's applicable CAPEC patterns) is given, each host also cites the ones that hit its families."""
    from dastcore.analysis.capec import label_patterns, patterns_for_families

    plans: list[HostPlan] = []
    for host in order_hosts(tuple(hosts)):
        bare = _host_of(host)
        role, families, why = _classify_host(bare)
        blended = tuple(dict.fromkeys([*families, *global_families]))[:6]
        capec = label_patterns(patterns_for_families(patterns, blended)) if patterns else ()
        plans.append(HostPlan(host=bare, role=role, families=blended, why=why, capec=capec))
    return plans


# Functional-area detection: a pentester maps the app into zones, then focuses each on its likely bugs.
# Each area is revealed by any of: a profile flag, an observed PATH, or an observed PARAM name.
_AREA_AUTH_PATH = re.compile(r"/(login|signin|sign-in|register|signup|sign-up|password|passwd|reset|forgot|"
                             r"sso|saml|oauth|oidc|auth|token|session|mfa|2fa|otp)", re.I)
_AREA_OAUTH = re.compile(r"/(oauth|oidc|authorize|\.well-known)", re.I)
_AREA_API_PATH = re.compile(r"/(api|v\d+|graphql|graphiql|rest|swagger|openapi)(/|$)", re.I)
_AREA_ADMIN_PATH = re.compile(r"/(admin|administrator|dashboard|manage|management|console|backoffice|wp-admin)(/|$)", re.I)
_AREA_OBJ_PATH = re.compile(r"/(users?|accounts?|profiles?|orders?|objects?|items?|documents?|invoices?)(/|$)", re.I)
_AREA_OBJ_PARAM = re.compile(r"(?:^|[_\-.])(id|uid|user|account|acct|owner|object|profile|order|customer)(?:$|[_\-.])", re.I)
_AREA_UPLOAD_PATH = re.compile(r"/(upload|uploads|media|files?|attachments?|import)(/|$)", re.I)
_AREA_UPLOAD_PARAM = re.compile(r"(?:^|[_\-.])(upload|file|attachment|avatar|photo|image|document)", re.I)
_AREA_SEARCH_PATH = re.compile(r"/(search|query|find|lookup|autocomplete)(/|$)", re.I)
_AREA_SEARCH_PARAM = re.compile(r"(?:^|[_\-.])(q|query|search|keyword|kw|term|filter|sort)(?:$|[_\-.])", re.I)
_AREA_COMMERCE_PATH = re.compile(r"/(cart|checkout|payment|pay|billing|invoice|coupon|discount|subscription)(/|$)", re.I)
_AREA_COMMERCE_PARAM = re.compile(r"(?:^|[_\-.])(price|amount|qty|quantity|total|coupon|discount|voucher|promo)", re.I)


def plan_areas(profile: TargetProfile) -> list[AreaPlan]:
    """Map the target into functional AREAS and give each its focus — a pentester's decomposition.

    An area is revealed by a profile flag, an observed path, or an observed parameter; each carries the
    vuln classes and techniques that area tends to hide, plus the high-signal paths to probe there. The
    areas are returned in the order a pentester would prioritise them (auth/API/admin before marketing)."""
    paths, params = profile.paths, profile.param_names

    def has_path(rx: re.Pattern[str]) -> bool:
        return any(rx.search(p) for p in paths)

    def has_param(rx: re.Pattern[str]) -> bool:
        return any(rx.search(n) for n in params)

    areas: list[AreaPlan] = []

    # 1) Authentication & identity — where account takeover lives.
    auth_sig = [s for s, on in (("panel de login", profile.has_login),
                                (f"auth {profile.auth_kind}", bool(profile.auth_kind)),
                                ("rutas de login/registro/reset", has_path(_AREA_AUTH_PATH))) if on]
    if auth_sig:
        oauth = profile.auth_kind == "oauth" or has_path(_AREA_OAUTH)
        areas.append(AreaPlan(
            "Autenticación e identidad",
            ("weak-creds", "jwt", "session", *(("oauth",) if oauth else ())), tuple(auth_sig),
            ("/login", "/register", "/password/reset", "/.well-known/openid-configuration", "/oauth/authorize"),
            "credenciales débiles/por defecto, forja y confusión de JWT (alg=none, kid/jwk), session fixation, "
            "reset poisoning y, con OAuth, redirect_uri abierto + CSRF de state"))

    # 2) API — authorization is the crown jewel.
    api_sig = [s for s, on in ((f"API {profile.api_kind}", profile.api_kind != "none"),
                               ("rutas /api//graphql", has_path(_AREA_API_PATH))) if on]
    if api_sig:
        fams = ("authz", "mass_assignment", "nosqli") + (("graphql",) if profile.api_kind == "graphql" else ("sqli",))
        areas.append(AreaPlan(
            "API", fams, tuple(api_sig),
            ("/openapi.json", "/swagger.json", "/graphql", "/api-docs"),
            "BOLA/BFLA/IDOR por objeto y función, mass assignment, introspección/batching en GraphQL; "
            "enumera IDs de objeto entre cuentas y prueba verbos/flags no documentados"))

    # 3) Administration / management — privilege escalation.
    if has_path(_AREA_ADMIN_PATH):
        areas.append(AreaPlan(
            "Administración", ("authz", "weak-creds", "csrf"), ("rutas /admin//dashboard",),
            ("/admin", "/admin/login", "/dashboard"),
            "escalada a nivel de función (BFLA) desde un rol bajo, credenciales por defecto del panel, "
            "y CSRF en las acciones que cambian estado"))

    # 4) User/object management — the IDOR heartland.
    obj_sig = [s for s, on in (("rutas /users//orders", has_path(_AREA_OBJ_PATH)),
                               ("params id/user/owner", has_param(_AREA_OBJ_PARAM))) if on]
    if obj_sig:
        areas.append(AreaPlan(
            "Gestión de objetos (IDOR/BOLA)", ("authz",), tuple(obj_sig), (),
            "enumera identificadores de objeto y prueba el acceso cross-account (BOLA/IDOR) con 2 identidades; "
            "incluye verbos de escritura (PUT/PATCH/DELETE), no solo lectura"))

    # 5) File upload / media — the RCE/stored-XSS door.
    up_sig = [s for s, on in (("endpoint de subida", profile.has_file_upload),
                              ("rutas /upload//media", has_path(_AREA_UPLOAD_PATH)),
                              ("params file/avatar", has_param(_AREA_UPLOAD_PARAM))) if on]
    if up_sig:
        areas.append(AreaPlan(
            "Subida de ficheros / media", ("upload", "lfi", "xss"), tuple(up_sig), ("/upload", "/media"),
            "extensiones/MIME ejecutables, doble extensión y null-byte, path traversal en el nombre, "
            "XSS almacenado en metadatos, y SSRF si acepta una URL de importación"))

    # 6) Search / query — reflected injection.
    se_sig = [s for s, on in (("rutas /search", has_path(_AREA_SEARCH_PATH)),
                              ("params q/search/filter", has_param(_AREA_SEARCH_PARAM))) if on]
    if se_sig:
        areas.append(AreaPlan(
            "Búsqueda / consulta", ("sqli", "nosqli", "xss"), tuple(se_sig), ("/search",),
            "inyección en el término de búsqueda (SQLi/NoSQLi) y XSS reflejado en la página de resultados"))

    # 7) Commerce / payment — business-logic abuse.
    co_sig = [s for s, on in (("rutas /cart//checkout", has_path(_AREA_COMMERCE_PATH)),
                              ("params price/qty/coupon", has_param(_AREA_COMMERCE_PARAM))) if on]
    if co_sig:
        areas.append(AreaPlan(
            "Comercio / pagos", ("authz", "logic", "race"), tuple(co_sig),
            ("/cart", "/checkout", "/api/orders"),
            "manipulación de precio/cantidad (negativos, decimales), abuso/reutilización de cupones, "
            "condiciones de carrera en checkout/cupón, e IDOR en pedidos/facturas de otras cuentas"))

    # 8) Content / CMS — version → CVE.
    if profile.cms:
        areas.append(AreaPlan(
            f"Contenido / CMS ({profile.cms})", ("rce", "sqli", "xss"), (f"CMS {profile.cms}",),
            (),  # the CMS recon paths come from plan_recon's _CMS_RECON_PATHS
            "mapea versión→CVE, plugins/temas vulnerables, xmlrpc/pingback, y enumeración de usuarios"))

    # 9) Fallback: a plain content/marketing surface with nothing distinctive — the classic client-side bugs.
    if not areas and paths:
        areas.append(AreaPlan(
            "Contenido / marketing", ("xss", "open_redirect"), ("sin un área funcional marcada",), (),
            "XSS reflejado y open redirect en los parámetros de navegación/enlaces del sitio"))

    # Cite the applicable CAPEC attack patterns per zone: for each area, the patterns whose prerequisites
    # this target satisfies AND whose family the area focuses on — so each zone shows how it is attacked.
    from dastcore.analysis.capec import applicable_patterns, label_patterns, patterns_for_families

    aps = applicable_patterns(profile)
    if aps:
        for area in areas:
            area.capec = label_patterns(patterns_for_families(aps, area.families))

    return areas


# Order to work the areas in during the active scan: authz-rich zones before the marketing surface, so a
# --time-budget is spent where the high-impact bugs concentrate.
_REQUEST_AREA_ORDER = ("Autenticación", "API", "Administración", "Objetos", "Subida", "Comercio", "Búsqueda", "Web")


def classify_request_area(request: object) -> tuple[str, tuple[str, ...]]:
    """Map a single request to its functional area + the vuln families to focus there — so the active scan
    can attack area by area (a search endpoint gets SQLi/XSS first, an upload endpoint LFI/XSS, an API
    object endpoint NoSQLi/SQLi…) instead of one flat priority for the whole surface. First match wins.

    Families are blended with the target's global priorities by the caller; the rule engine steers on the
    ones that are rule families (sqli/xss/lfi/nosqli/open_redirect), while authz/upload/auth stay the job
    of the dedicated detectors that already blanket the surface."""
    url = getattr(request, "url", "") or ""
    path = urlsplit(url).path or "/"
    params: set[str] = set(getattr(request, "params", {}) or {}) | set(getattr(request, "data", {}) or {})
    body = getattr(request, "json_body", None)
    if isinstance(body, dict):
        params |= {str(k) for k in body}

    def in_path(rx: re.Pattern[str]) -> bool:
        return bool(rx.search(path))

    def in_param(rx: re.Pattern[str]) -> bool:
        return any(rx.search(n) for n in params)

    if in_path(_AREA_ADMIN_PATH):
        return ("Administración", ("authz", "sqli"))
    if in_path(_AREA_API_PATH):
        return ("API", ("authz", "mass_assignment", "nosqli", "sqli"))
    if in_path(_AREA_AUTH_PATH):
        return ("Autenticación", ("weak-creds", "jwt", "sqli"))
    if in_path(_AREA_UPLOAD_PATH) or in_param(_AREA_UPLOAD_PARAM):
        return ("Subida", ("upload", "lfi", "xss"))
    if in_path(_AREA_COMMERCE_PATH) or in_param(_AREA_COMMERCE_PARAM):
        return ("Comercio", ("authz", "sqli", "xss"))
    if in_path(_AREA_SEARCH_PATH) or in_param(_AREA_SEARCH_PARAM):
        return ("Búsqueda", ("sqli", "nosqli", "xss"))
    if in_path(_AREA_OBJ_PATH) or in_param(_AREA_OBJ_PARAM):
        return ("Objetos", ("authz", "sqli"))
    return ("Web", ("xss", "open_redirect"))


def area_scan_order(name: str) -> int:
    """Sort key for the active scan's per-area order (lower = worked first). Unknown areas go last."""
    return _REQUEST_AREA_ORDER.index(name) if name in _REQUEST_AREA_ORDER else len(_REQUEST_AREA_ORDER)


def order_requests_by_area(requests: list) -> list:  # list[HttpRequest]; duck-typed to avoid an import cycle
    """Order requests by their functional area's pentester priority (auth/API/admin/objects before the
    marketing surface), stable within an area. Feeding this to the dedicated-detector phases makes each
    detector work the high-value zones FIRST — so a --time-budget is spent where the impact is — while
    dropping nothing: with budget to spare, the whole surface is still covered (zero coverage loss, unlike
    hard per-detector restriction, which a misclassification would turn into a false negative)."""
    return sorted(requests, key=lambda r: area_scan_order(classify_request_area(r)[0]))


def plan_recon(profile: TargetProfile) -> ReconPlan:
    """Decide HOW to reconnoitre this target from what it appears to be — the reconnaissance half of the
    brain. Deterministic: picks the discovery techniques that fit the stack, the high-signal paths to
    probe, and the crawl depth, each with a cited reason. Steers recon effort to where the surface is."""
    recon = ReconPlan()
    why = recon.reasoning
    paths: list[str] = []

    # Client-rendered apps hide their real surface behind JS — render it and mine the bundles.
    if profile.is_spa or "nextjs" in profile.frameworks:
        recon.use_headless = True
        recon.extract_js_endpoints = True
        why.append("SPA/cliente: renderiza con navegador headless y extrae endpoints (y secretos) del bundle JS")
    elif profile.exposed_secrets or "express" in profile.frameworks:
        recon.extract_js_endpoints = True
        why.append("JS con secretos/endpoints: mina los bundles (.map) para ampliar la superficie")

    # API-shaped → go find the schema; it is the fastest path to the real endpoint list.
    if profile.api_kind in ("rest", "graphql"):
        recon.discover_api_schemas = True
        paths += _API_RECON_PATHS.get(profile.api_kind, ())
        why.append(f"API {profile.api_kind}: busca el esquema (OpenAPI/GraphQL) e ingiere sus endpoints")

    # Framework / CMS / backend → probe the paths that stack is known to leak.
    for fw in sorted(profile.frameworks):
        fw_paths = _FRAMEWORK_RECON_PATHS.get(fw)
        if fw_paths:
            paths += fw_paths
            why.append(f"framework {fw}: sondea {', '.join(fw_paths[:3])}… (config/fuente/CVE conocido)")
    cms_paths = _CMS_RECON_PATHS.get(profile.cms)
    if cms_paths:
        paths += cms_paths
        why.append(f"CMS {profile.cms}: sondea {', '.join(cms_paths[:3])}…")
    if profile.backend == "supabase":
        recon.discover_api_schemas = True
        paths += _SUPABASE_RECON_PATHS
        why.append("backend Supabase: mina tablas del bundle y sondea /rest/v1 y /graphql/v1")

    # A thin observed surface on an app that clearly takes input → mine hidden parameters.
    if profile.api_kind in ("rest", "graphql") or (
        profile.endpoint_count >= 5 and len(profile.param_names) < profile.endpoint_count
    ):
        recon.mine_params = True
        why.append("superficie de parámetros fina frente al nº de endpoints: mina parámetros ocultos (Arjun)")

    # Depth from the size of the surface (a wildcard/many hosts or a large app warrants a deeper sweep).
    distinct_hosts = len({_host_of(h) for h in profile.hosts})
    if distinct_hosts >= 5 or profile.endpoint_count >= 50:
        recon.depth = "aggressive"
        why.append(f"superficie grande ({distinct_hosts} host(s), {profile.endpoint_count} endpoints): recon profundo")
    elif distinct_hosts <= 1 and profile.endpoint_count and profile.endpoint_count < 10:
        recon.depth = "light"
        why.append("superficie pequeña: recon ligero para no gastar presupuesto en descubrimiento")

    recon.probe_paths = tuple(dict.fromkeys(paths))  # de-dup, keep order
    return recon


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

    # Observed paths: where the sensitive functions live (/admin, /upload, /checkout…) is evidence too.
    path_gain: dict[str, float] = {}
    path_hits: dict[str, set[str]] = {}
    for path in sorted(profile.paths):
        for pattern, votes in _PATH_SIGNALS:
            if pattern.search(path):
                for fam, weight in votes:
                    path_gain[fam] = min(path_gain.get(fam, 0.0) + weight, _PATH_CAP)
                    path_hits.setdefault(fam, set()).add(path)
    for fam, gain in path_gain.items():
        sample = ", ".join(sorted(path_hits[fam])[:3])
        bump(fam, round(gain, 3), f"rutas observadas ({sample})")

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
        # A CDN/WAF at the edge is normal (Cloudflare/Supabase) and doesn't imply the scan is being
        # blocked — phrase it conditionally so it isn't a false "results may be partial" alarm.
        plan.notes.append(
            f"CDN/WAF en el borde{vendor} (capa normal). Si empieza a bloquear (403/429), activa "
            "--waf-evasion y usa insertion points 'moved'; solo entonces los hallazgos podrían salir parciales."
        )

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

    # CAPEC attack-pattern layer: the brain reasons from MITRE's attack catalogue. Contribute likelihood-
    # weighted, CAPEC-cited votes from the patterns whose PREREQUISITES this target actually satisfies (an
    # observed param/path/API/login/backend — never a bare stack prior, so it reinforces evidence without
    # perturbing the stack-prior rankings). Applied after the generic fallback so that only fires on a
    # truly featureless target. Purely a prioritisation/reasoning aid — detection oracles are unchanged.
    from dastcore.analysis.capec import applicable_patterns, capec_family_votes

    for fam, weight, reason in capec_family_votes(profile):
        bump(fam, weight, reason)
    plan.attack_patterns = applicable_patterns(profile)

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
        plan.host_plans = plan_hosts(profile.hosts, plan.priority_families, tuple(plan.attack_patterns))
    # Functional-area map (pentester decomposition): the app broken into zones, each with its focus.
    plan.areas = plan_areas(profile)
    # The reconnaissance half of the plan: how to discover this target's surface, not just how to attack it.
    plan.recon = plan_recon(profile)
    # Each area contributes its high-signal paths to the recon — the brain probes where each zone lives.
    if plan.areas:
        merged = list(plan.recon.probe_paths)
        for area in plan.areas:
            merged.extend(area.recon_paths)
        plan.recon.probe_paths = tuple(dict.fromkeys(merged))
    return plan


def identity_summary(profile: TargetProfile) -> str:
    """What the target *is*, for the plan header: tech fingerprints plus the CMS/backend/API-kind signals —
    so a Supabase/API target reads as 'backend supabase' instead of the misleading 'sin fingerprint claro'."""
    parts = sorted(profile.tech)
    if profile.cms:
        parts.append(f"CMS {profile.cms}")
    if profile.backend and profile.backend != "none":
        parts.append(f"backend {profile.backend}")
    if profile.api_kind and profile.api_kind != "none":
        parts.append(f"API {profile.api_kind}")
    return ", ".join(dict.fromkeys(parts)) or "sin fingerprint claro"


def render_plan(profile: TargetProfile, plan: ScanPlan) -> str:
    """A human-readable summary of the target profile and the chosen strategy — the visible 'thinking'."""
    lines = [f"Perfil del objetivo: {identity_summary(profile)}."]
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
            if hp.capec:
                lines.append(f"      CAPEC: {', '.join(hp.capec)}")
    if plan.areas:
        lines.append("Áreas (mapa del pentester → foco por zona):")
        for area in plan.areas:
            lines.append(f"  ▸ {area.name}: {', '.join(area.families)} — {area.why}")
            if area.capec:
                lines.append(f"      CAPEC: {', '.join(area.capec)}")
    if plan.attack_patterns:
        lines.append("Patrones de ataque aplicables (CAPEC → cómo trabajarlos):")
        for ap in plan.attack_patterns:
            lines.append(f"  ⚔ {ap.capec_id} {ap.name} [{ap.family}]: {ap.why}")
    recon = plan.recon
    techniques = [
        name for flag, name in (
            (recon.use_headless, "headless"), (recon.extract_js_endpoints, "JS-endpoints"),
            (recon.discover_api_schemas, "esquemas API"), (recon.mine_params, "params ocultos"),
        ) if flag
    ]
    if techniques or recon.probe_paths or recon.reasoning:
        lines.append(f"Reconocimiento (profundidad {recon.depth}): " + (", ".join(techniques) or "crawl base") + ".")
        if recon.probe_paths:
            shown = ", ".join(recon.probe_paths[:8])
            lines.append("  rutas de alto valor: " + shown + (" …" if len(recon.probe_paths) > 8 else ""))
        for line in recon.reasoning:
            lines.append(f"  · {line}")
    lines.extend(f"  ⚠ {note}" for note in plan.notes)
    return "\n".join(lines)
