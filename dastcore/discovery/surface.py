"""Unified attack-surface model + prioritisation scoring.

Discovery scatters what it finds across many places — subdomains, ports, dirbust paths, JS endpoints,
DNS records, favicons, findings. This module folds all of it into **one host-centric model** and scores
each host by how *interesting to attack* it is, so a human (or the report/dashboard) sees the surface
ranked instead of as a flat list: the Jenkins box with an exposed ``/admin`` and a parametrised API
floats to the top; a static marketing page sinks.

The score is an **attack-surface interest** score, deliberately separate from the per-finding
exploitability score (``triage/scoring.py``) — it ranks *where to look*, from signals that exist even
before a single vulnerability is confirmed:

- parametrised endpoints (ready-made injection points),
- high-signal paths (``/admin``, ``/login``, ``/api``, ``/actuator``, ``/.git``, ``/.env``…),
- risky technology (admin panels / dev tooling: Jenkins, GitLab, Grafana, Spring Boot…),
- confirmed findings already sitting on the host, and
- services on non-standard ports.

Pure and deterministic — no network, no AI. Fully unit-testable from plain inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from dastcore.core.models import Finding, HttpRequest

# Path substrings that mark a high-value endpoint, grouped so each *category* scores once (so ten
# ``/api/*`` routes don't dwarf a single ``/.git``). Lowercased comparison.
_HOT_PATH_GROUPS: dict[str, tuple[str, ...]] = {
    "admin": ("/admin", "/administrator", "/wp-admin", "/manage", "/dashboard", "/console"),
    "auth": ("/login", "/signin", "/sign-in", "/auth", "/oauth", "/sso", "/register"),
    "api": ("/api/", "/api?", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql", "/rpc"),
    "ops": ("/actuator", "/metrics", "/health", "/status", "/debug", "/__debug__", "/server-status"),
    "vcs-secrets": ("/.git", "/.env", "/.svn", "/.hg", "/config", "/backup", "/dump", "/.aws"),
    "upload": ("/upload", "/import", "/files", "/media", "/attachment"),
    "docs": ("/swagger", "/api-docs", "/openapi", "/redoc"),
}

# Technology names (as fingerprinted / favicon-identified) whose mere presence raises attack interest.
_RISKY_TECH = {
    "jenkins", "gitlab", "grafana", "spring boot", "apache tomcat", "phpmyadmin", "kibana",
    "argo cd", "portainer", "adminer", "elasticsearch", "rabbitmq", "jira", "confluence",
}

# Per-severity contribution of a confirmed finding already on the host (capped in aggregate below).
_SEVERITY_WEIGHT: dict[str, float] = {"critical": 30.0, "high": 20.0, "medium": 8.0, "low": 2.0, "info": 0.0}

# Aggregate caps per signal, so one dimension can't run away with the whole score.
_CAP_PARAMS = 20.0
_CAP_HOTPATHS = 25.0
_CAP_TECH = 20.0
_CAP_FINDINGS = 40.0
_CAP_PORT = 8.0


@dataclass
class Endpoint:
    """One discovered request on a host: its path, method, and how many injectable parameters it has."""

    url: str
    method: str = "GET"
    param_count: int = 0


@dataclass
class HostSurface:
    """Everything known about one host, plus its computed attack-surface score and the reasons for it."""

    host: str  # netloc (host or host:port)
    roots: list[str] = field(default_factory=list)
    tech: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    finding_severities: list[str] = field(default_factory=list)
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)

    @property
    def param_endpoints(self) -> int:
        return sum(1 for e in self.endpoints if e.param_count > 0)


@dataclass
class ScoredSurface:
    """The whole discovered surface as hosts ranked by attack-surface interest (highest first)."""

    hosts: list[HostSurface] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "hosts": [
                {
                    "host": h.host,
                    "score": round(h.score, 1),
                    "reasons": h.reasons,
                    "tech": h.tech,
                    "endpoints": len(h.endpoints),
                    "param_endpoints": h.param_endpoints,
                    "findings": len(h.finding_severities),
                }
                for h in self.hosts
            ]
        }


def _param_count(request: HttpRequest) -> int:
    total = len(request.params or {})
    body = getattr(request, "json_body", None)
    if isinstance(body, dict):
        total += len(body)
    total += len(getattr(request, "data", None) or {})
    return total


def _hot_path_categories(paths: list[str]) -> list[str]:
    """Which high-value path categories appear across the host's endpoints (order-stable)."""
    low = [p.lower() for p in paths]
    found: list[str] = []
    for category, markers in _HOT_PATH_GROUPS.items():
        if any(marker in path for marker in markers for path in low):
            found.append(category)
    return found


def score_host(host: HostSurface) -> None:
    """Compute ``host.score`` (0–100) and ``host.reasons`` in place from its signals. Deterministic."""
    score = 0.0
    reasons: list[str] = []

    param_endpoints = host.param_endpoints
    if param_endpoints:
        contribution = min(param_endpoints * 4.0, _CAP_PARAMS)
        score += contribution
        reasons.append(f"{param_endpoints} endpoint(s) con parámetros (superficie de inyección)")

    paths = [urlsplit(e.url).path for e in host.endpoints]
    categories = _hot_path_categories(paths)
    if categories:
        score += min(len(categories) * 6.0, _CAP_HOTPATHS)
        reasons.append("rutas de alto valor: " + ", ".join(categories))

    risky = sorted({t for t in host.tech if t.lower() in _RISKY_TECH})
    if risky:
        score += min(len(risky) * 12.0, _CAP_TECH)
        reasons.append("tecnología sensible: " + ", ".join(risky))

    if host.finding_severities:
        raw = sum(_SEVERITY_WEIGHT.get(s.lower(), 0.0) for s in host.finding_severities)
        if raw > 0:
            score += min(raw, _CAP_FINDINGS)
            worst = min(host.finding_severities, key=lambda s: -_SEVERITY_WEIGHT.get(s.lower(), 0.0))
            reasons.append(f"{len(host.finding_severities)} hallazgo(s) confirmado(s) (peor: {worst})")

    # Any root on a non-standard port is extra attack surface (a distinct service).
    if any((urlsplit(r).port not in (None, 80, 443)) for r in host.roots):
        score += _CAP_PORT
        reasons.append("servicio en puerto no estándar")

    host.score = min(score, 100.0)
    host.reasons = reasons


def build_scored_surface(
    roots: list[str],
    requests: list[HttpRequest],
    findings: list[Finding],
    *,
    host_tech: dict[str, list[str]] | None = None,
) -> ScoredSurface:
    """Fold roots + discovered requests + findings into per-host surfaces, scored and ranked.

    ``host_tech`` maps a host (netloc) to its identified technologies (from fingerprint/favicon).
    Grouping is by netloc, so ``example.com`` and ``example.com:8443`` are distinct services.
    """
    hosts: dict[str, HostSurface] = {}

    def _host_for(url: str) -> HostSurface | None:
        netloc = urlsplit(url).netloc.lower()
        if not netloc:
            return None
        return hosts.setdefault(netloc, HostSurface(host=netloc))

    for root in roots:
        host = _host_for(root)
        if host is not None and root not in host.roots:
            host.roots.append(root)

    seen_endpoints: dict[str, set[str]] = {}
    for request in requests:
        host = _host_for(request.url)
        if host is None:
            continue
        key = f"{request.method} {urlsplit(request.url).path}"
        if key in seen_endpoints.setdefault(host.host, set()):
            continue
        seen_endpoints[host.host].add(key)
        host.endpoints.append(
            Endpoint(url=request.url, method=request.method, param_count=_param_count(request))
        )

    for finding in findings:
        url = finding.request.url if finding.request else ""
        host = _host_for(url) if url else None
        if host is not None:
            host.finding_severities.append(finding.severity)

    for netloc, tech in (host_tech or {}).items():
        host = hosts.get(netloc.lower())
        if host is not None:
            host.tech = list(dict.fromkeys(tech))

    for host in hosts.values():
        score_host(host)

    ranked = sorted(hosts.values(), key=lambda h: (-h.score, h.host))
    return ScoredSurface(hosts=ranked)
