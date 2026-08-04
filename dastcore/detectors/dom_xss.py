"""DOM-based XSS detection (headless).

Detects client-side sinks that execute attacker-controlled data. The probe
injects a marker payload via the URL *fragment* (`#...`). The fragment is never
sent to the server, so if the payload executes it can only be because client
JavaScript read a DOM source (e.g. `location.hash`) and flowed it into a sink
(`innerHTML`, `document.write`, `eval`, ...). Execution — not reflection — is
the oracle, which makes this a zero-false-positive signal.

This module operates on a Playwright ``BrowserContext`` supplied by
``crawler_headless``; it never launches a browser itself.
"""
from __future__ import annotations

import secrets
from urllib.parse import urlsplit, urlunsplit

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# Common DOM-XSS sources (read on the client) and sinks (execute on the client).
DOM_XSS_SOURCES = ("location.hash", "location.search", "location.href", "document.referrer", "window.name")
DOM_XSS_SINKS = ("innerHTML", "outerHTML", "document.write", "eval", "setTimeout", "insertAdjacentHTML")

_MARKER_GLOBAL = "__dastcoreXss"
_NAV_TIMEOUT_MS = 8000


def _payload_for(token: str) -> str:
    # <img onerror> fires when the (relative, 404-ing) src fails to load — classic
    # innerHTML-sink trigger that <script> insertion would not give us.
    return f'<img src=x onerror="window.{_MARKER_GLOBAL}=\'{token}\'">'


def _strip_fragment(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


async def probe_dom_xss(context, url: str) -> Finding | None:
    """Probe a single URL for a fragment-driven DOM-XSS sink. Returns a Finding or None."""
    token = f"dast{secrets.token_hex(6)}"
    payload = _payload_for(token)
    base_url = _strip_fragment(url)
    crafted_url = f"{base_url}#{payload}"

    page = await context.new_page()
    try:
        try:
            await page.goto(crafted_url, wait_until="load", timeout=_NAV_TIMEOUT_MS)
        except Exception:
            return None
        # Give event-driven sinks (hashchange handlers, deferred renders) a moment to run.
        await page.wait_for_timeout(150)

        try:
            executed = await page.evaluate(f"() => window.{_MARKER_GLOBAL} || null")
        except Exception:
            executed = None

        if executed != token:
            return None

        try:
            rendered = await page.content()
        except Exception:
            rendered = ""

        request = HttpRequest(method="GET", url=base_url, params={"#fragment": payload})
        point = InjectionPoint(location="fragment", name="#", base_value="", request_template=request)
        response = HttpResponse(status_code=200, text=rendered[:2000], url=crafted_url)
        return Finding(
            id=f"dom-xss:GET:{urlsplit(base_url).path or '/'}:fragment",
            rule_id="dom-xss",
            name="DOM-based Cross-Site Scripting (XSS)",
            severity="high",
            cwe="CWE-79",
            owasp="WSTG-CLNT-01",
            injection_point=point,
            evidence=[
                Evidence(
                    type="dom_execution",
                    data=f"fragment payload executed on the client (marker '{token}' set via a DOM sink)",
                    confidence="high",
                )
            ],
            request=request,
            response=response,
            remediation=(
                "Never pass untrusted DOM sources (location.hash/search, document.referrer, "
                "window.name) into HTML sinks (innerHTML, document.write, eval). Use textContent "
                "or a sanitizer (e.g. DOMPurify), and add a strict Content-Security-Policy."
            ),
        )
    finally:
        await page.close()
