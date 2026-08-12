"""Compliance mapping (Module 16).

Each confirmed finding already carries its CWE and an OWASP/WSTG/API reference. This module
adds the *framework control* layer auditors ask for — mapping a finding's vulnerability
category to the relevant controls in PCI-DSS 4.0, OWASP ASVS 4.0.3, ISO/IEC 27001:2022
(Annex A) and SOC 2 (Trust Services Criteria).

The mapping is **indicative**, keyed off the vulnerability family, and deliberately
conservative: it points an assessor at the control a finding bears on, it does not assert a
formal certification verdict. Pure and deterministic — no network, no AI.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dastcore.config import Severity
from dastcore.core.models import Finding
from dastcore.severity import severity_rank

# Which control *category* a vulnerability family belongs to. Unknown families fall back to
# "secure_development" so every finding still carries at least a generic control reference.
_FAMILY_CATEGORY: dict[str, str] = {
    "sqli": "injection",
    "cmdi": "injection",
    "ssti": "injection",
    "xxe": "injection",
    "lfi": "injection",
    "crlf": "injection",
    "xss": "injection",
    "graphql": "injection",
    "llm": "injection",
    "ssrf": "ssrf",
    "authz": "access_control",
    "race": "access_control",
    "jwt": "broken_auth",
    "exposure": "exposure",
    "open_redirect": "validation",
}


@dataclass(frozen=True)
class ControlTag:
    """One control in one framework that a finding bears on."""

    framework: str
    control: str
    title: str


# Control references per category. Kept small and defensible — one control per framework.
_CATEGORY_CONTROLS: dict[str, list[ControlTag]] = {
    "injection": [
        ControlTag("PCI-DSS 4.0", "6.2.4", "Protección frente a ataques de inyección en el software"),
        ControlTag("OWASP ASVS 4.0.3", "V5.3", "Codificación de salida y prevención de inyección"),
        ControlTag("ISO/IEC 27001:2022", "A.8.28", "Codificación segura"),
        ControlTag("SOC 2", "CC7.1", "Identificación y gestión de vulnerabilidades"),
    ],
    "ssrf": [
        ControlTag("PCI-DSS 4.0", "6.2.4", "Protección frente a ataques comunes en el software"),
        ControlTag("OWASP ASVS 4.0.3", "V12.6", "Protección SSRF / validación de destino"),
        ControlTag("ISO/IEC 27001:2022", "A.8.28", "Codificación segura"),
        ControlTag("SOC 2", "CC7.1", "Identificación y gestión de vulnerabilidades"),
    ],
    "access_control": [
        ControlTag("PCI-DSS 4.0", "7.2", "Control de acceso por necesidad de conocer y mínimo privilegio"),
        ControlTag("OWASP ASVS 4.0.3", "V4.1", "Control de acceso a nivel de objeto y función"),
        ControlTag("ISO/IEC 27001:2022", "A.5.15", "Control de acceso"),
        ControlTag("SOC 2", "CC6.1", "Controles de acceso lógico"),
    ],
    "broken_auth": [
        ControlTag("PCI-DSS 4.0", "8.3", "Autenticación fuerte de usuarios y sesiones"),
        ControlTag("OWASP ASVS 4.0.3", "V3.5", "Gestión de tokens/sesión sin estado (JWT)"),
        ControlTag("ISO/IEC 27001:2022", "A.8.5", "Autenticación segura"),
        ControlTag("SOC 2", "CC6.1", "Controles de acceso lógico"),
    ],
    "exposure": [
        ControlTag("PCI-DSS 4.0", "2.2", "Configuraciones seguras de los componentes del sistema"),
        ControlTag("OWASP ASVS 4.0.3", "V14.3", "Configuración: no divulgación de información sensible"),
        ControlTag("ISO/IEC 27001:2022", "A.8.9", "Gestión de la configuración"),
        ControlTag("SOC 2", "CC7.1", "Identificación y gestión de vulnerabilidades"),
    ],
    "validation": [
        ControlTag("PCI-DSS 4.0", "6.2.4", "Protección frente a ataques comunes en el software"),
        ControlTag("OWASP ASVS 4.0.3", "V5.1", "Validación de entrada"),
        ControlTag("ISO/IEC 27001:2022", "A.8.28", "Codificación segura"),
        ControlTag("SOC 2", "CC7.1", "Identificación y gestión de vulnerabilidades"),
    ],
    "secure_development": [
        ControlTag("PCI-DSS 4.0", "6.2.4", "Protección frente a ataques comunes en el software"),
        ControlTag("OWASP ASVS 4.0.3", "V1.1", "Ciclo de desarrollo seguro"),
        ControlTag("ISO/IEC 27001:2022", "A.8.28", "Codificación segura"),
        ControlTag("SOC 2", "CC7.1", "Identificación y gestión de vulnerabilidades"),
    ],
}


def category_for(finding: Finding) -> str:
    """The control category a finding belongs to (from its family)."""
    return _FAMILY_CATEGORY.get(finding.family, "secure_development")


def compliance_tags(finding: Finding) -> list[ControlTag]:
    """The framework control tags a finding maps to (one per framework)."""
    return list(_CATEGORY_CONTROLS[category_for(finding)])


@dataclass
class ControlPosture:
    """A single control and the findings that touch it, worst-severity first."""

    tag: ControlTag
    count: int = 0
    max_severity: Severity = "info"
    finding_ids: list[str] = field(default_factory=list)


@dataclass
class FrameworkPosture:
    """A framework and every control our findings mapped onto it."""

    framework: str
    controls: list[ControlPosture] = field(default_factory=list)

    @property
    def count(self) -> int:
        return sum(c.count for c in self.controls)


def compliance_summary(findings: list[Finding]) -> list[FrameworkPosture]:
    """Group findings by framework → control, with a count and worst severity per control.

    Suppressed findings are excluded — the posture reflects live exposure, not the audit
    trail. Frameworks and controls are ordered by worst impact first.
    """
    by_framework: dict[str, dict[str, ControlPosture]] = {}
    for finding in findings:
        if finding.suppressed:
            continue
        for tag in compliance_tags(finding):
            controls = by_framework.setdefault(tag.framework, {})
            posture = controls.get(tag.control)
            if posture is None:
                posture = ControlPosture(tag=tag)
                controls[tag.control] = posture
            posture.count += 1
            posture.finding_ids.append(finding.id)
            if severity_rank(finding.severity) > severity_rank(posture.max_severity):
                posture.max_severity = finding.severity

    result: list[FrameworkPosture] = []
    for framework, controls in by_framework.items():
        ordered = sorted(controls.values(), key=lambda c: (severity_rank(c.max_severity), c.count), reverse=True)
        result.append(FrameworkPosture(framework=framework, controls=ordered))
    result.sort(
        key=lambda fp: (max((severity_rank(c.max_severity) for c in fp.controls), default=0), fp.count), reverse=True
    )
    return result
