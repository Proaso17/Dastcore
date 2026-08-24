"""Unified surface model + attack-surface scoring — pure, deterministic, offline."""

from __future__ import annotations

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.discovery.surface import HostSurface as HS
from dastcore.discovery.surface import build_scored_surface, score_host


def _req(url: str, method: str = "GET", params: dict | None = None, json_body: dict | None = None) -> HttpRequest:
    return HttpRequest(method=method, url=url, params=params or {}, json_body=json_body)


def _finding(url: str, severity: str) -> Finding:
    request = HttpRequest(method="GET", url=url)
    point = InjectionPoint(location="query", name="x", base_value="", request_template=request)
    return Finding(
        id=f"f:{url}:{severity}", rule_id="r", name="n", severity=severity, cwe="CWE-1", owasp="",
        injection_point=point, evidence=[Evidence(type="response_match", data="d")],
        request=request, response=HttpResponse(status_code=200, url=url), remediation="",
    )


def test_param_endpoints_and_hot_paths_raise_score() -> None:
    host = HS(
        host="app.acme.com",
        roots=["https://app.acme.com/"],
        endpoints=[],
    )
    from dastcore.discovery.surface import Endpoint

    host.endpoints = [
        Endpoint(url="https://app.acme.com/api/users?id=1", method="GET", param_count=1),
        Endpoint(url="https://app.acme.com/admin/login", method="GET", param_count=0),
    ]
    score_host(host)
    assert host.score > 0
    joined = " ".join(host.reasons)
    assert "parámetros" in joined and "alto valor" in joined


def test_ranking_puts_richer_host_first() -> None:
    requests = [
        _req("https://api.acme.com/api/v1/orders", params={"id": "1"}),
        _req("https://api.acme.com/admin/login"),
        _req("https://static.acme.com/index.html"),
    ]
    findings = [_finding("https://api.acme.com/api/v1/orders", "high")]
    surface = build_scored_surface(
        ["https://api.acme.com/", "https://static.acme.com/"], requests, findings,
        host_tech={"api.acme.com": ["Jenkins"], "static.acme.com": ["nginx"]},
    )
    hosts = [h.host for h in surface.hosts]
    assert hosts[0] == "api.acme.com"  # params + hot paths + risky tech + a finding -> ranked first
    top = surface.hosts[0]
    assert top.score > surface.hosts[1].score
    assert "Jenkins" in " ".join(top.reasons)
    assert top.finding_severities == ["high"]


def test_non_standard_port_and_dedup() -> None:
    requests = [
        _req("https://acme.com:8443/api/x", params={"a": "1"}),
        _req("https://acme.com:8443/api/x", params={"a": "1"}),  # duplicate endpoint (method+path)
    ]
    surface = build_scored_surface(["https://acme.com:8443/"], requests, [])
    host = surface.hosts[0]
    assert host.host == "acme.com:8443"
    assert len(host.endpoints) == 1  # deduped by method+path
    assert any("puerto no estándar" in r for r in host.reasons)


def test_to_dict_shape() -> None:
    surface = build_scored_surface(["https://acme.com/"], [_req("https://acme.com/api/x", params={"a": "1"})], [])
    d = surface.to_dict()
    assert d["hosts"][0]["host"] == "acme.com" and "score" in d["hosts"][0] and "reasons" in d["hosts"][0]


def test_empty_surface() -> None:
    assert build_scored_surface([], [], []).hosts == []
