"""Impact-first bug-bounty submission drafts, per platform. Human-in-the-loop — never auto-submitted.

Builds a Markdown draft from a triaged ``BountyFinding``: title, summary, affected asset, severity
(CVSS vector + VRT + CWE), numbered reproduction, a **minimal, non-destructive PoC** (the finding's own
read-only reproduction request), business impact, remediation and references. Platform layouts (HackerOne,
Bugcrowd, generic) reorder/relabel the same sections to match each platform's expected shape and tone.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from dastcore.bugbounty.program import Program
from dastcore.bugbounty.triage import BountyFinding
from dastcore.core.models import Finding

# Business-impact fallback when a finding has no proven-impact string of its own.
_IMPACT_BY_FAMILY: dict[str, str] = {
    "sqli": "Permite leer (y potencialmente modificar) datos arbitrarios de la base de datos, incluida información de otras cuentas.",
    "nosqli": "Permite manipular la consulta a la base de datos, evadiendo autenticación o filtrando datos de otras cuentas.",
    "cmdi": "Permite ejecutar comandos arbitrarios del sistema operativo en el servidor (ejecución remota de código).",
    "code-injection": "Permite ejecutar código/expresiones arbitrarias en el servidor (ejecución remota de código).",
    "ssi": "Permite ejecutar comandos del sistema vía Server-Side Includes (ejecución remota de código).",
    "ssti": "Permite evaluar expresiones en el motor de plantillas del servidor, típicamente escalable a ejecución de código.",
    "deserialization": "Permite deserializar datos no confiables, un gadget de ejecución remota de código.",
    "xxe": "Permite leer ficheros del servidor y alcanzar servicios internos vía entidades externas XML.",
    "ssrf": "Permite que el servidor haga peticiones a destinos internos (p. ej. metadatos cloud), habilitando robo de credenciales/movimiento lateral.",
    "lfi": "Permite leer ficheros arbitrarios del servidor (código, configuración, secretos).",
    "authz": "Permite acceder a objetos/funciones de otras cuentas (autorización a nivel de objeto/función ausente).",
    "auth": "Permite comprometer la autenticación (sesión/credenciales), facilitando el acceso a cuentas ajenas.",
    "upload": "Permite subir un fichero ejecutable/servible, escalable a ejecución de código o XSS almacenado.",
    "xss": "Permite ejecutar JavaScript en el navegador de la víctima (robo de sesión, acciones en su nombre).",
    "crlf": "Permite inyectar cabeceras de respuesta o partir la respuesta (cache poisoning, XSS, fijación de sesión).",
    "cache-poisoning": "Permite envenenar la caché para servir contenido malicioso a todos los usuarios.",
    "smuggling": "Permite desincronizar front-end y back-end para secuestrar peticiones de otros usuarios.",
}

# (section header, section key) per platform. Title is rendered separately.
_LAYOUTS: dict[str, list[tuple[str, str]]] = {
    "hackerone": [
        ("Summary", "summary"),
        ("Affected asset", "asset"),
        ("Steps To Reproduce", "steps"),
        ("Proof of Concept", "poc"),
        ("Impact", "impact"),
        ("Severity", "severity"),
        ("Remediation", "remediation"),
        ("References", "refs"),
    ],
    "bugcrowd": [
        ("Description", "summary"),
        ("Affected asset", "asset"),
        ("Steps to Reproduce", "steps"),
        ("Proof of Concept", "poc"),
        ("Business Impact", "impact"),
        ("Severity (VRT + CVSS)", "severity"),
        ("Remediation", "remediation"),
        ("References", "refs"),
    ],
    "generic": [
        ("Summary", "summary"),
        ("Affected asset", "asset"),
        ("Severity", "severity"),
        ("Steps to reproduce", "steps"),
        ("Proof of concept", "poc"),
        ("Impact", "impact"),
        ("Remediation", "remediation"),
        ("References", "refs"),
    ],
}

PLATFORMS = tuple(_LAYOUTS)


def _impact_text(bf: BountyFinding) -> str:
    finding = bf.finding
    if finding.impact:  # a demonstrated, read-only proof of impact
        return finding.impact
    return _IMPACT_BY_FAMILY.get(finding.family, f"Explotable como {bf.vrt_category} (severidad {finding.severity}).")


def _title(bf: BountyFinding, platform: str) -> str:
    host = urlsplit(bf.finding.request.url).hostname or "target"
    if platform == "bugcrowd":
        return f"# [{bf.vrt_priority}] {bf.finding.name} — {host}"
    return f"# {bf.finding.name} on {host}"


def _sections(bf: BountyFinding) -> dict[str, str]:
    finding: Finding = bf.finding
    parts = urlsplit(finding.request.url)
    point = finding.injection_point
    evidence = (
        "; ".join(e.data for e in finding.evidence) or "el oráculo confirmó la vulnerabilidad de forma diferencial"
    )
    cwe_num = finding.cwe.replace("CWE-", "")
    poc = [
        "PoC mínima y **no destructiva** (reproduce el fallo sin causar daño):",
        "",
        "```bash",
        finding.repro_curl,
        "```",
    ]
    if finding.impact:
        poc += ["", f"**Impacto demostrado** (extracción de solo lectura y acotada): {finding.impact}"]
    return {
        "summary": (
            f"Se identificó **{finding.name}** ({bf.vrt_category}) en `{parts.hostname}`, en el parámetro "
            f"`{point.name}` ({point.location}). {_impact_text(bf)}"
        ),
        "asset": (
            f"- **URL:** `{finding.request.method} {finding.request.url}`\n"
            f"- **Host:** `{parts.hostname}`\n"
            f"- **Parámetro / punto de inyección:** `{point.location}:{point.name}`"
        ),
        "severity": (
            f"- **Prioridad (VRT):** {bf.vrt_priority} — {bf.vrt_category}\n"
            f"- **CVSS 3.1:** {bf.cvss_vector or 'n/d'} (score {finding.cvss_score:.1f})\n"
            f"- **CWE:** {finding.cwe} · **OWASP:** {finding.owasp} · **Confianza:** {finding.confidence}"
        ),
        "steps": (
            "1. Enviar la siguiente petición:\n\n```bash\n" + finding.repro_curl + "\n```\n\n"
            f"2. Observar la respuesta: {evidence}."
        ),
        "poc": "\n".join(poc),
        "impact": _impact_text(bf),
        "remediation": finding.remediation,
        "refs": f"- CWE-{cwe_num}: https://cwe.mitre.org/data/definitions/{cwe_num}.html\n- OWASP: {finding.owasp}",
    }


def render_bounty_report(bf: BountyFinding, program: Program | None = None, platform: str = "generic") -> str:
    """Render a Markdown submission draft for a triaged finding, laid out for the given platform."""
    layout = _LAYOUTS.get(platform, _LAYOUTS["generic"])
    sections = _sections(bf)
    lines = [_title(bf, platform), ""]
    if program is not None:
        lines += [
            f"> Programa: **{program.handle}** ({program.platform}). Borrador para revisión — no se envía automáticamente.",
            "",
        ]
    for header, key in layout:
        lines += [f"## {header}", sections[key], ""]
    return "\n".join(lines).rstrip() + "\n"
