"""Unauthorized cross-tenant action through the assistant (excessive agency / BFLA via LLM),
end-to-end against the multi-tenant chatbot fixture. It must confirm the boundary crossing
via an out-of-band read of the victim's state, and stay silent when the assistant refuses
or when the action targets the attacker's own account (no false positive)."""

from __future__ import annotations

import pytest

from dastcore.ai.agency import ActionAgencyScanner, ReadBack
from dastcore.ai.client import AiChatClient
from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient

_A = {"Authorization": "Bearer tok-a"}  # attacker: tenant alice, unit 4A
_B = {"Authorization": "Bearer tok-b"}  # victim: tenant bob, unit 4B


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _attacker_chat(base_url: str, client: HttpClient, path: str = "/api/chat") -> AiChatClient:
    return AiChatClient(client, f"{base_url}{path}", prompt_field="message", headers=_A)


def _victim_readback(base_url: str) -> ReadBack:
    return ReadBack(url=f"{base_url}/api/messages", headers=_B)


@pytest.mark.asyncio
async def test_cross_tenant_action_is_confirmed(chatbot_app_url: str) -> None:
    async with HttpClient(_scope()) as client:
        scanner = ActionAgencyScanner(
            client, _attacker_chat(chatbot_app_url, client), _victim_readback(chatbot_app_url), "unit 4B"
        )
        findings = await scanner.scan()
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "llm-cross-tenant-action" and f.severity == "critical"


@pytest.mark.asyncio
async def test_hardened_assistant_that_refuses_is_not_flagged(chatbot_app_url: str) -> None:
    async with HttpClient(_scope()) as client:
        scanner = ActionAgencyScanner(
            client,
            _attacker_chat(chatbot_app_url, client, "/api/chat_safe"),
            _victim_readback(chatbot_app_url),
            "unit 4B",
        )
        findings = await scanner.scan()
    assert findings == []


@pytest.mark.asyncio
async def test_action_on_own_unit_does_not_touch_the_victim(chatbot_app_url: str) -> None:
    # Targeting the attacker's own unit writes to the attacker, not the victim → the
    # victim's state never gains the canary, so this is not reported as cross-tenant.
    async with HttpClient(_scope()) as client:
        scanner = ActionAgencyScanner(
            client, _attacker_chat(chatbot_app_url, client), _victim_readback(chatbot_app_url), "unit 4A"
        )
        findings = await scanner.scan()
    assert findings == []


@pytest.mark.asyncio
async def test_discover_flow_wires_the_action_check(chatbot_app_url: str, monkeypatch) -> None:
    """`ai --discover` with a second identity also runs the cross-tenant action check."""
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
    assert any(f.rule_id == "llm-cross-tenant-action" for f in findings)
