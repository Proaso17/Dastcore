"""Client-Side Template Injection (CSTI) detection (headless).

Reflected input that lands inside a client-side template region (AngularJS, Vue) is *evaluated by the
framework in the browser*, not by the server. The probe injects a unique arithmetic expression in
template braces (``{{a*b}}`` with random factors); confirmation requires the **computed product** to
appear in the rendered DOM while being **absent from the raw (non-rendered) HTTP response**. Those two
conditions together (a) prove a real client-side evaluation of our injected expression and (b)
distinguish CSTI from server-side SSTI — where the server would have computed the product already, so
it would show up in the raw response. A 7-8 digit product from random 4-digit factors won't appear by
chance, so this is a zero-false-positive signal.

Operates on a Playwright ``BrowserContext`` supplied by ``crawler_headless``; never launches a browser.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_NAV_TIMEOUT_MS = 8000
_MAX_PARAMS = 8  # bound per-URL work; CSTI needs a reflected param, most URLs have few


def _probe_numbers() -> tuple[int, int, int]:
    """Two 4-digit factors and their product — a 7-8 digit number that won't appear by chance
    and can't be guessed, so its presence post-render proves our expression was evaluated."""
    a = secrets.randbelow(9000) + 1000
    b = secrets.randbelow(9000) + 1000
    return a, b, a * b


def _craft(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


async def _framework(page) -> str:
    try:
        name = await page.evaluate(
            "() => window.angular ? ('AngularJS ' + ((window.angular.version && angular.version.full) || '')).trim()"
            " : (window.Vue ? 'Vue.js' : 'client-side template engine')"
        )
        return name or "client-side template engine"
    except Exception:  # noqa: BLE001 — evidence flavour only, never blocks the finding
        return "client-side template engine"


def _finding(request: HttpRequest, param: str, payload: str, product: int, framework: str,
             rendered: str) -> Finding:
    point = InjectionPoint(location="query", name=param, base_value="", request_template=request)
    crafted = _craft(request.url, param, payload)
    return Finding(
        id=f"csti:GET:{urlsplit(request.url).path or '/'}:{param}",
        rule_id="csti",
        name="Client-Side Template Injection (CSTI)",
        severity="high",
        cwe="CWE-1336",
        owasp="WSTG-CLNT-01",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
        family="xss",  # impact and remediation are client-side script execution (XSS-class)
        injection_point=point,
        evidence=[Evidence(
            type="dom_execution",
            data=(f"{framework} evaluated the injected template `{payload}` in '{param}': the product "
                  f"{product} appears in the rendered DOM but not in the raw HTTP response (client-side, "
                  f"not SSTI)"),
            confidence="high",
        )],
        request=HttpRequest(method="GET", url=request.url.split("?", 1)[0],
                            params={**(request.params or {}), param: payload}),
        response=HttpResponse(status_code=200, text=rendered[:2000], url=crafted),
        remediation=(
            "No pases entrada de usuario a regiones controladas por un motor de plantillas de cliente "
            "(AngularJS {{ }}, Vue). Renderiza el valor con text-binding (ng-bind / v-text / textContent), "
            "escapa las llaves, y desactiva la interpolación en zonas con datos no confiables "
            "(p. ej. ng-non-bindable). Añade una Content-Security-Policy estricta."
        ),
    )


async def probe_csti(context, request: HttpRequest) -> list[Finding]:
    """Probe every query parameter of one request for CSTI. Returns confirmed findings."""
    params = list(request.params or {})
    if not params:
        return []
    findings: list[Finding] = []
    for param in params[:_MAX_PARAMS]:
        a, b, product = _probe_numbers()
        payload = f"{{{{{a}*{b}}}}}"  # {{a*b}}
        crafted = _craft(request.url, param, payload)
        prod = str(product)

        # (1) Raw, non-rendered response. Shares the context's cookies/headers (auth session).
        try:
            raw = await context.request.get(crafted, timeout=_NAV_TIMEOUT_MS)
            raw_text = await raw.text()
        except Exception:  # noqa: BLE001 — can't rule out SSTI without the raw body, so skip
            continue
        if prod in raw_text:
            continue  # server already computed it -> that's SSTI, handled elsewhere; not CSTI

        # (2) Rendered DOM. The product only appears if a client template engine evaluated our input.
        page = await context.new_page()
        try:
            try:
                await page.goto(crafted, wait_until="load", timeout=_NAV_TIMEOUT_MS)
            except Exception:  # noqa: BLE001 — navigation failed: skip this param
                continue
            await page.wait_for_timeout(200)  # let the framework digest/render
            try:
                rendered = await page.evaluate("() => document.body ? document.body.innerText : ''") or ""
                html = await page.content()
            except Exception:  # noqa: BLE001
                continue
            if prod not in rendered and prod not in html:
                continue
            framework = await _framework(page)
        finally:
            await page.close()

        findings.append(_finding(request, param, payload, product, framework, rendered))
    return findings
