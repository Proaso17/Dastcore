"""Cross-tenant leakage through the assistant (BOLA via the LLM), end-to-end against the
multi-tenant chatbot fixture. Confirms the boundary crossing with a victim-planted canary,
and stays silent when the two identities are actually the same tenant (no FP)."""

from __future__ import annotations

import pytest

from dastcore.ai.client import AiChatClient
from dastcore.ai.cross_tenant import CrossTenantScanner, TenantProbe
from dastcore.ai.stored_injection import WriteEndpoint
from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient

_A = {"Authorization": "Bearer tok-a"}  # tenant alice, unit 4A
_B = {"Authorization": "Bearer tok-b"}  # tenant bob, unit 4B


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _probe(base_url: str, client: HttpClient, auth: dict, name: str, refs: list[str]) -> TenantProbe:
    return TenantProbe(
        name=name,
        chat_client=AiChatClient(client, f"{base_url}/api/chat", prompt_field="message", headers=auth),
        write=WriteEndpoint(url=f"{base_url}/api/messages", field="text", headers=auth),
        references=refs,
    )


@pytest.mark.asyncio
async def test_cross_tenant_leak_is_confirmed(chatbot_app_url: str) -> None:
    async with HttpClient(_scope()) as client:
        attacker = _probe(chatbot_app_url, client, _A, "alice", refs=[])
        victim = _probe(chatbot_app_url, client, _B, "bob", refs=["unit 4B"])
        findings = await CrossTenantScanner(client, attacker, victim).scan()
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "llm-cross-tenant-leak" and f.severity == "critical"
    assert len(f.attack_chain) == 3 and f.attack_chain[0].actor.startswith("Victim")


@pytest.mark.asyncio
async def test_same_tenant_is_not_flagged(chatbot_app_url: str) -> None:
    # Attacker and victim are the same tenant → asking about "your own" data isn't a leak.
    async with HttpClient(_scope()) as client:
        alice_attacker = _probe(chatbot_app_url, client, _A, "alice", refs=[])
        alice_victim = _probe(chatbot_app_url, client, _A, "alice", refs=["unit 4A"])
        findings = await CrossTenantScanner(client, alice_attacker, alice_victim).scan()
    assert findings == []


@pytest.mark.asyncio
async def test_unknown_victim_reference_stays_silent(chatbot_app_url: str) -> None:
    # The attacker doesn't know how to name the victim → the boundary is never crossed.
    async with HttpClient(_scope()) as client:
        attacker = _probe(chatbot_app_url, client, _A, "alice", refs=[])
        victim = _probe(chatbot_app_url, client, _B, "bob", refs=["unit 9Z"])
        findings = await CrossTenantScanner(client, attacker, victim).scan()
    assert findings == []


@pytest.mark.asyncio
async def test_discover_flow_wires_cross_tenant_with_a_second_identity(chatbot_app_url: str, monkeypatch) -> None:
    """`ai --discover --victim-bearer ... --victim-ref ...` end-to-end: with the endpoints
    the headless crawler would capture, the flow reports the cross-tenant leak too."""
    import dastcore.cli as cli
    from dastcore.config import RateLimitConfig, ScanConfig
    from dastcore.core.models import HttpRequest

    candidates = [
        HttpRequest(method="POST", url=f"{chatbot_app_url}/api/chat", headers=_A, json_body={"message": "hola"}),
        HttpRequest(method="POST", url=f"{chatbot_app_url}/api/messages", headers=_A, json_body={"text": "nota"}),
    ]

    class _FakeCrawler:
        def __init__(self, client, max_pages=200):
            pass

        async def crawl(self, start_url):
            return candidates

    monkeypatch.setattr(cli, "HttpCrawler", _FakeCrawler)
    config = ScanConfig(target=chatbot_app_url, rate_limit=RateLimitConfig(requests_per_second=50))
    _, findings = await cli._run_ai_discover_scan(
        config, chatbot_app_url, dict(_A), "", 50, victim_headers=dict(_B), victim_refs=["unit 4B"]
    )
    assert any(f.rule_id == "llm-cross-tenant-leak" for f in findings)
