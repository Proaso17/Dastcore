"""Server-side XSLT injection. CWE-94 / OWASP A03:2021 (WSTG-INPV-11).

When user input flows into an XSLT stylesheet a transformer applies (a report/export builder that drops
the value into a ``<xsl:value-of select="…"/>`` or into the stylesheet template), the attacker controls
XSLT — which reads files (``document()`` / ``unparsed-text()``), calls extension functions, and on some
processors reaches OS commands. The sibling of XXE on the *transform* side.

Zero false positives from a self-identifying marker: ``system-property('xsl:vendor')`` returns the
processor's name (``libxslt``, ``SAXON``, ``Xalan``, …) **only when the input was evaluated as XSLT** — a
plain reflection echoes the literal payload, never the vendor string. We require the vendor to appear
after injection but NOT in the untouched baseline (so a page that merely mentions a processor is not a
hit), and to reproduce.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse
from dastcore.engine.injection_points import extract_injection_points
from dastcore.engine.rule_engine import build_mutated_request

_MAX_POINTS = 30

# The processor's own name — present ONLY when an XSLT engine evaluates system-property('xsl:vendor').
_VENDORS = r"libxslt|SAXON|Saxonica|Xalan|xsltproc|Microsoft|Apache"


def _payloads(left: str, right: str) -> tuple[str, ...]:
    """XSLT ``concat`` probes bracketing the processor vendor with unique delimiters, for the two common
    contexts: the value landing inside a ``select="…"`` and the value landing as stylesheet node content.
    Only a real transform yields ``left<vendor>right``; a reflected literal or a compile error never does."""
    expr = f"concat('{left}',system-property('xsl:vendor'),'{right}')"
    return (expr, f'<xsl:value-of select="{expr}"/>')


_BENIGN = "dcxsltprobe"  # baseline value: a plain token, never evaluates to a vendor string


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


def _finding(point, request: HttpRequest, response: HttpResponse, vendor: str) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"xslt-injection:{request.method}:{path}:{point.location}:{point.name}",
        rule_id="xslt-injection",
        name="Server-side XSLT injection",
        severity="high",
        cwe="CWE-94",
        owasp="A03:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        family="xslt",
        injection_point=point,
        evidence=[
            Evidence(
                type="reflected",
                data=(
                    f"la expresión XSLT inyectada en '{point.name}' ({point.location}) se evaluó: "
                    f"system-property('xsl:vendor') devolvió '{vendor}' — el servidor procesa la entrada como "
                    "XSLT (lectura de ficheros vía document()/unparsed-text(), funciones de extensión, posible RCE)"
                )[:200],
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "No construyas hojas de estilo XSLT con entrada del usuario ni la transformes como XSLT. Si debes "
            "transformar, usa un procesador con extensiones y acceso a red/ficheros desactivados (secure processing) "
            "y trata la entrada estrictamente como datos, nunca como parte de la plantilla."
        ),
    )


async def run_xslt_injection_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Inject an XSLT ``system-property`` probe into each point and report the ones evaluated as XSLT."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for request in requests:
        for point in extract_injection_points(request, include_headers=False):
            sig = (urlsplit(request.url).path or "/", point.location, point.name)
            if sig in seen:
                continue
            seen.add(sig)
            if len(seen) > _MAX_POINTS:
                return findings

            tok = secrets.token_hex(4)
            left, right = "xl" + tok, "xr" + tok
            # The vendor, bracketed by our unique delimiters: matched ONLY when the transform ran.
            marker = re.compile(re.escape(left) + rf"\s*({_VENDORS})\s*" + re.escape(right), re.IGNORECASE)
            for payload in _payloads(left, right):
                resp = await _send(client, build_mutated_request(point, payload))
                if resp is None:
                    continue
                m = marker.search(resp.text)
                if not m:
                    continue
                confirm = await _send(client, build_mutated_request(point, payload))
                if confirm is not None and marker.search(confirm.text):
                    findings.append(_finding(point, build_mutated_request(point, payload), resp, m.group(1)))
                    break
    return findings
