"""Attack-path chaining: correlate independent confirmed findings into exploit chains.

A single scanner reports issues in isolation; an analyst sees how two of them combine into
something worse — an open redirect *plus* a lax OAuth ``redirect_uri`` is account takeover; XSS
*plus* a cookie without ``HttpOnly`` is full session theft. This pass reads the finished set of
**already-confirmed** findings and, whenever a chain's legs are all present, emits an ``AttackChain``
with the compound impact and elevated severity.

It is pure correlation: no new requests, and it never invents a finding — a chain only forms from
findings an oracle already confirmed, so it cannot introduce a false positive. The worst it can do
is not spot a chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from dastcore.config import Severity
from dastcore.core.models import Finding
from dastcore.severity import severity_rank


@dataclass
class ChainLeg:
    """One confirmed finding playing a role in a chain."""

    role: str  # what this finding contributes, e.g. "Redirección abierta"
    rule_id: str
    name: str
    severity: Severity
    location: str


@dataclass
class AttackChain:
    """Two or more findings that combine into a higher-impact attack path."""

    id: str
    name: str
    severity: Severity  # the compound severity, usually above any single leg
    summary: str  # how the legs combine and why it's worse
    legs: list[ChainLeg] = field(default_factory=list)


@dataclass(frozen=True)
class _ChainRule:
    """A declarative chain: it fires when every leg is matched by a distinct finding."""

    id: str
    name: str
    severity: Severity
    summary: str
    # each leg matches a finding whose rule_id is in `rule_ids` OR whose family is in `families`.
    legs: tuple[tuple[str, frozenset[str], frozenset[str]], ...]


# Ordered most-severe first; each rule yields at most one chain per scan.
_CHAIN_RULES: tuple[_ChainRule, ...] = (
    _ChainRule(
        id="account-takeover-oauth",
        name="Apropiación de cuenta (open redirect + OAuth laxo)",
        severity="critical",
        summary=(
            "Un redirect_uri de OAuth poco validado combinado con una redirección abierta permite desviar el "
            "código/token de autorización a un dominio del atacante: apropiación completa de la cuenta de la víctima."
        ),
        legs=(
            ("Redirección abierta", frozenset({"open-redirect"}), frozenset()),
            ("OAuth redirect_uri laxo", frozenset({"oauth-redirect-uri-validation"}), frozenset()),
        ),
    ),
    _ChainRule(
        id="privilege-escalation-authz-token",
        name="Escalada de privilegios (autorización rota + token forjable)",
        severity="critical",
        summary=(
            "Con un token forjable (alg=none o secreto débil) o un endpoint sin autenticación, el atacante se "
            "autentica como otro usuario y usa el fallo de autorización a nivel de objeto/función (BOLA/BFLA) para "
            "acceder a datos o acciones de otras cuentas: toma de control multi-tenant."
        ),
        legs=(
            (
                "Autorización rota",
                frozenset({"authz-bola", "authz-bfla", "graphql-bola", "graphql-field-authz", "mass-assignment"}),
                frozenset(),
            ),
            (
                "Token forjable / sin auth",
                frozenset({"jwt-alg-none", "jwt-weak-secret", "authz-missing-auth"}),
                frozenset(),
            ),
        ),
    ),
    _ChainRule(
        id="session-hijack-xss-cookie",
        name="Robo de sesión (XSS + cookie/token expuestos)",
        severity="critical",
        summary=(
            "El XSS ejecuta JavaScript que lee la cookie de sesión (sin HttpOnly) o el token de sesión filtrado en "
            "la URL y lo exfiltra al atacante: secuestro completo de la sesión de la víctima."
        ),
        legs=(
            ("Ejecución de JavaScript (XSS)", frozenset({"dom-xss"}), frozenset({"xss"})),
            (
                "Sesión accesible por script",
                frozenset({"passive-insecure-cookie", "session-token-in-url"}),
                frozenset(),
            ),
        ),
    ),
    _ChainRule(
        id="ssrf-internal-pivot",
        name="Pivot interno vía SSRF (SSRF + superficie interna expuesta)",
        severity="critical",
        summary=(
            "El SSRF permite alcanzar la red interna (p. ej. el endpoint de metadatos cloud 169.254.169.254); "
            "junto con secretos/ficheros internos ya expuestos o servicios internos vulnerables conocidos, habilita "
            "el robo de credenciales y el movimiento lateral."
        ),
        legs=(
            ("Petición del lado servidor (SSRF)", frozenset({"ssrf-oob"}), frozenset({"ssrf"})),
            (
                "Superficie interna expuesta",
                frozenset(
                    {"active-sensitive-file", "secret-exposure", "known-vulnerable-version", "host-header-injection"}
                ),
                frozenset(),
            ),
        ),
    ),
    _ChainRule(
        id="persistent-xss-via-cache",
        name="XSS persistente para todos vía cache poisoning",
        severity="critical",
        summary=(
            "Envenenando la caché con la respuesta que contiene el XSS reflejado, el payload se sirve desde la "
            "caché a todos los usuarios: un XSS reflejado se convierte en almacenado y masivo, sin interacción."
        ),
        legs=(
            ("XSS reflejado", frozenset({"xss-reflected", "dom-xss"}), frozenset({"xss"})),
            ("Envenenamiento de caché", frozenset({"web-cache-poisoning"}), frozenset()),
        ),
    ),
    _ChainRule(
        id="lfi-to-secrets",
        name="Lectura de secretos vía LFI (path traversal + secretos)",
        severity="high",
        summary=(
            "El path traversal permite leer ficheros del servidor; combinado con secretos ya expuestos (o leyendo "
            "directamente ficheros de configuración/.env), el atacante obtiene credenciales de BD/API para moverse "
            "lateralmente."
        ),
        legs=(
            ("Lectura de ficheros (LFI)", frozenset(), frozenset({"lfi"})),
            (
                "Secretos / config expuestos",
                frozenset(
                    {"secret-exposure", "js-secret-exposure", "active-sensitive-file", "serialized-object-exposure"}
                ),
                frozenset(),
            ),
        ),
    ),
)


def _location(finding: Finding) -> str:
    path = urlsplit(finding.request.url).path or "/"
    point = finding.injection_point
    return f"{finding.request.method} {path} ({point.location}:{point.name})"


def _match_leg(
    rule_ids: frozenset[str], families: frozenset[str], pool: list[Finding], used: set[str]
) -> Finding | None:
    """The most severe still-unused finding satisfying this leg, or None."""
    candidates = [
        f for f in pool if f.id not in used and (f.rule_id in rule_ids or (f.family and f.family in families))
    ]
    return max(candidates, key=lambda f: severity_rank(f.severity)) if candidates else None


def correlate_chains(findings: list[Finding]) -> list[AttackChain]:
    """Emit an ``AttackChain`` for every chain rule whose legs are all present in ``findings``.

    Each rule yields at most one chain (its most-severe matching instance per leg), and a single
    finding is used at most once within a given chain.
    """
    active = [f for f in findings if not f.suppressed]
    chains: list[AttackChain] = []
    for rule in _CHAIN_RULES:
        used: set[str] = set()
        legs: list[ChainLeg] = []
        for role, rule_ids, families in rule.legs:
            match = _match_leg(rule_ids, families, active, used)
            if match is None:
                break
            used.add(match.id)
            legs.append(
                ChainLeg(
                    role=role,
                    rule_id=match.rule_id,
                    name=match.name,
                    severity=match.severity,
                    location=_location(match),
                )
            )
        if len(legs) == len(rule.legs):
            chains.append(
                AttackChain(id=rule.id, name=rule.name, severity=rule.severity, summary=rule.summary, legs=legs)
            )
    return sorted(chains, key=lambda c: severity_rank(c.severity), reverse=True)
