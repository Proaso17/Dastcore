"""Coverage for additional vulnerability classes — common (SSTI, NoSQLi, CORS,
sensitive files, GraphQL introspection) and obscure (Log4Shell/JNDI, Host header)."""
from __future__ import annotations

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.active_checks import (
    check_cors_reflection,
    check_graphql_introspection,
    probe_sensitive_files,
)
from dastcore.engine.oast import LocalOastServer
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner

_SCOPE = ScopeConfig(allow_domains=["127.0.0.1"])


def _rule(rule_id: str):
    return [r for r in load_rules() if r.id == rule_id]


async def test_ssti_in_band_detected(vuln_app_url: str) -> None:
    request = HttpRequest(method="GET", url=f"{vuln_app_url}/render", params={"name": "guest"})
    async with HttpClient(_SCOPE) as client:
        findings = await Scanner(client, _rule("ssti-inband")).scan([request])
    assert any(f.rule_id == "ssti-inband" for f in findings), [f.rule_id for f in findings]


async def test_nosql_injection_detected(vuln_app_url: str) -> None:
    request = HttpRequest(method="GET", url=f"{vuln_app_url}/api/nosql", params={"filter": "x"})
    async with HttpClient(_SCOPE) as client:
        findings = await Scanner(client, _rule("nosqli-error")).scan([request])
    assert any(f.rule_id == "nosqli-error" for f in findings)


async def test_host_header_injection_detected(vuln_app_url: str) -> None:
    request = HttpRequest(method="GET", url=f"{vuln_app_url}/reset")
    async with HttpClient(_SCOPE) as client:
        findings = await Scanner(client, _rule("host-header-injection")).scan([request])
    host = [f for f in findings if f.rule_id == "host-header-injection"]
    assert host, [f.rule_id for f in findings]
    assert host[0].injection_point.name == "Host"


async def test_log4shell_confirmed_via_oob(vuln_app_url: str) -> None:
    server = LocalOastServer()
    await server.start()
    try:
        request = HttpRequest(method="GET", url=f"{vuln_app_url}/api/log", params={"msg": "seed"})
        async with HttpClient(_SCOPE) as client:
            findings = await Scanner(client, _rule("log4shell-jndi"), oast=server, oob_poll_attempts=6).scan([request])
    finally:
        await server.stop()
    log4 = [f for f in findings if f.rule_id == "log4shell-jndi"]
    assert log4, [f.rule_id for f in findings]
    assert log4[0].severity == "critical"


async def test_cors_reflected_origin_detected(vuln_app_url: str) -> None:
    request = HttpRequest(method="GET", url=f"{vuln_app_url}/api/cors")
    async with HttpClient(_SCOPE) as client:
        findings = await check_cors_reflection(client, request)
    assert len(findings) == 1
    assert findings[0].rule_id == "active-cors-reflected-origin"
    assert findings[0].severity == "high"


async def test_cors_reflection_not_flagged_on_normal_endpoint(vuln_app_url: str) -> None:
    request = HttpRequest(method="GET", url=f"{vuln_app_url}/health")
    async with HttpClient(_SCOPE) as client:
        findings = await check_cors_reflection(client, request)
    assert findings == []


async def test_sensitive_files_exposed(vuln_app_url: str) -> None:
    async with HttpClient(_SCOPE) as client:
        findings = await probe_sensitive_files(client, vuln_app_url)
    names = {f.rule_id for f in findings}
    assert names == {"active-sensitive-file"}
    paths = {f.request.url.rsplit("/", 1)[-1] or f.request.url for f in findings}
    assert any(".env" in f.request.url for f in findings)
    assert any(".git" in f.request.url for f in findings)


async def test_graphql_introspection_flagged(vuln_app_url: str) -> None:
    async with HttpClient(_SCOPE) as client:
        findings = await check_graphql_introspection(client, f"{vuln_app_url}/graphql")
    assert len(findings) == 1
    assert findings[0].rule_id == "active-graphql-introspection"


async def test_graphql_introspection_not_flagged_on_non_graphql(vuln_app_url: str) -> None:
    async with HttpClient(_SCOPE) as client:
        findings = await check_graphql_introspection(client, f"{vuln_app_url}/health")
    assert findings == []
