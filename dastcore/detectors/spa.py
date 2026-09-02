"""Single-page-application / JS-framework awareness.

A modern SaaS frontend (Next.js, Nuxt, React, Vue, Angular, SvelteKit…) renders its content and
issues its XHR/fetch calls **in the browser**. The static HTTP crawler never runs that JavaScript, so
against such a target it sees an almost-empty shell and misses the real surface — exactly what happened
scanning the Vercel-hosted getnyma frontend with ``--engine http``.

This detector fingerprints the framework from headers + HTML markers and, when the scan is running
static-only, emits an ``info`` advisory telling the user to re-scan with ``--engine headless`` (or
``both``) so the JS-driven routes are actually discovered and tested. It's context, never a vuln.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# (header lowercased, required value substring or None, framework).
_HEADER_MARKERS: list[tuple[str, str | None, str]] = [
    ("x-powered-by", "next.js", "Next.js"),
    ("x-nextjs-cache", None, "Next.js"),
    ("x-nextjs-prerender", None, "Next.js"),
    ("x-powered-by", "nuxt", "Nuxt (Vue)"),
]

# (compiled HTML body pattern, framework). Ordered most-specific first.
_HTML_MARKERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"""id=["']__next["']|__NEXT_DATA__|/_next/static/""", re.IGNORECASE), "Next.js"),
    (re.compile(r"""id=["']__nuxt["']|window\.__NUXT__|/_nuxt/""", re.IGNORECASE), "Nuxt (Vue)"),
    (re.compile(r"""ng-version=|<app-root""", re.IGNORECASE), "Angular"),
    (re.compile(r"""__SVELTEKIT_|/_app/immutable/""", re.IGNORECASE), "SvelteKit"),
    (re.compile(r"""data-reactroot|react-dom(?:\.production)?(?:\.min)?\.js""", re.IGNORECASE), "React"),
    (re.compile(r"""data-v-[0-9a-f]{8}|window\.__VUE__""", re.IGNORECASE), "Vue"),
]

# A bare SPA shell: a single empty root div plus a module/bundled script and little else.
_SHELL_ROOT = re.compile(r"""<div\s+id=["'](?:root|app|__next|__nuxt)["']>\s*</div>""", re.IGNORECASE)
_SHELL_SCRIPT = re.compile(r"""<script[^>]+type=["']module["']|<script[^>]+src=["'][^"']+\.(?:m?js)""", re.IGNORECASE)


def detect_js_framework(response: HttpResponse) -> str | None:
    """The JS framework the response advertises (Next.js/Nuxt/React/…), a generic SPA, or None."""
    headers = {name.lower(): value.lower() for name, value in response.headers.items()}
    for header, needle, framework in _HEADER_MARKERS:
        value = headers.get(header)
        if value is not None and (needle is None or needle in value):
            return framework
    body = response.text or ""
    for pattern, framework in _HTML_MARKERS:
        if pattern.search(body):
            return framework
    if _SHELL_ROOT.search(body) and _SHELL_SCRIPT.search(body):
        return "SPA (JavaScript)"
    return None


async def run_spa_check(client: HttpClient, target: str, engine: str) -> list[Finding]:
    """Detect a JS/SPA frontend and, if scanning static-only, advise re-running with headless."""
    parts = urlsplit(target)
    origin = f"{parts.scheme}://{parts.netloc}/"
    try:
        response = await client.get(origin)
    except (OutOfScopeError, BudgetExceededError):
        return []

    framework = detect_js_framework(response)
    if framework is None:
        return []

    static_only = engine == "http"
    request = HttpRequest(method="GET", url=origin)
    if static_only:
        name = f"Aplicación JavaScript (SPA) detectada — cobertura estática limitada: {framework}"
        remediation = (
            f"El objetivo usa {framework}: su contenido y sus llamadas XHR/fetch se generan en el navegador, "
            "y el crawler estático no ejecuta JavaScript, por lo que su superficie real queda sin explorar. "
            "Vuelve a escanear con el motor **Navegador/headless** (--engine headless o both) y activa el "
            "**crawl interactivo** (--interactive / casilla «Crawl interactivo de SPA»): hace clic en controles "
            "seguros para disparar las llamadas API que la app solo hace al interactuar y así descubrir su "
            "superficie real. Con sesión (login/cookie) llegarás además a la parte autenticada."
        )
    else:
        name = f"Aplicación JavaScript (SPA) detectada: {framework}"
        remediation = f"El objetivo usa {framework}; se está escaneando con el motor headless, que ejecuta el JS."

    return [
        Finding(
            id=f"spa-detected:{parts.netloc}",
            rule_id="spa-detected",
            name=name,
            severity="info",
            cwe="CWE-200",
            owasp="WSTG-INFO-02",
            injection_point=InjectionPoint(location="header", name="-", base_value="", request_template=request),
            evidence=[Evidence(type="response_match", data=f"framework: {framework}", confidence="high")],
            request=request,
            response=response,
            remediation=remediation,
        )
    ]
