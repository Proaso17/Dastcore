"""Edge (WAF / reverse-proxy) posture summary.

The scan produces several edge-related signals in different places — WAF/CDN detection, the WAF
effectiveness audit (``--waf-audit``), and access-control bypasses of the edge by path normalization,
HTTP method tampering, or trusted request headers. This correlator gathers them into one advisory so a
pentest report has a single, coherent "how good is the edge, and can it be defeated?" section.

It only *summarizes findings already confirmed elsewhere*, so it adds no new false-positive surface. It
is advisory (excluded from the OWASP rollup) to avoid double-counting the findings it references.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# rule_id -> human technique label for the edge access-control bypasses.
_EDGE_BYPASS_RULES: dict[str, str] = {
    "path-normalization-bypass": "normalización de ruta",
    "verb-tampering": "manipulación de método HTTP",
    "access-bypass-trusted-header-ip": "cabecera de IP de confianza",
    "access-bypass-trusted-header-url": "cabecera de override de URL",
}


def summarize_edge_posture(findings: list[Finding], target: str) -> Finding | None:
    """Build a single edge-posture advisory from the edge-related findings, or None if there are none."""
    waf_detected = [f for f in findings if f.rule_id == "waf-detected"]
    audits = [f for f in findings if f.rule_id == "waf-audit"]
    bypasses = [f for f in findings if f.rule_id in _EDGE_BYPASS_RULES]
    if not (waf_detected or audits or bypasses):
        return None

    parts: list[str] = []
    parts.append("WAF/CDN detectado en el borde" if waf_detected else "No se detectó WAF/CDN en el borde")
    if audits:
        parts.append("auditoría de WAF ejecutada (ver el hallazgo 'waf-audit' para la matriz por familia)")

    if bypasses:
        by_tech: dict[str, list[str]] = {}
        for f in bypasses:
            tech = _EDGE_BYPASS_RULES[f.rule_id]
            path = urlsplit(f.request.url).path or "/"
            by_tech.setdefault(tech, []).append(path)
        detail = "; ".join(
            f"{tech} ({', '.join(sorted(set(paths))[:5])})" for tech, paths in sorted(by_tech.items())
        )
        parts.append(f"CONTROL DE BORDE EVADIBLE por {detail}")
    else:
        parts.append("no se hallaron bypasses del control de borde")

    summary = ". ".join(parts) + "."
    gaps = bool(bypasses) or any(f.severity == "low" for f in audits)

    request = HttpRequest(method="GET", url=target)
    return Finding(
        id=f"edge-posture:{urlsplit(target).netloc}",
        rule_id="edge-posture",
        name="Postura del borde (WAF/proxy)",
        severity="low" if gaps else "info",
        cwe="CWE-693",
        owasp="A05:2021",
        family="waf",
        injection_point=InjectionPoint(location="path", name="-", base_value="", request_template=request),
        evidence=[Evidence(type="differential", data=summary[:400], confidence="high")],
        request=request,
        response=HttpResponse(status_code=200, text=""),
        impact=(
            "Cuando el control de borde es evadible o deja pasar familias, no es una barrera fiable: "
            "corrige la causa raíz en la aplicación y no dependas del WAF/proxy como único control."
            if gaps
            else "El borde no mostró bypasses en esta prueba, pero no debe ser el único control."
        ),
        remediation=(
            "Normaliza la petición (ruta, método efectivo, cabeceras de confianza) ANTES de decidir el "
            "acceso, y hazlo igual en el proxy y en el backend. Aplica autorización en el backend."
        ),
    )
