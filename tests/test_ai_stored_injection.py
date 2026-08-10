"""Stored / second-order indirect prompt injection, end-to-end against the multi-tenant
chatbot fixture. The two things that matter: it *finds* the planted instruction executed
on retrieval, and it stays silent against the hardened assistant (no false positive)."""

from __future__ import annotations

import pytest

from dastcore.ai.client import AiChatClient
from dastcore.ai.stored_injection import StoredInjectionScanner, WriteEndpoint, infer_write_endpoints
from dastcore.config import ScanConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest

_AUTH = {"Authorization": "Bearer tok-a"}


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


@pytest.mark.asyncio
async def test_stored_injection_is_found_via_the_chatbot(chatbot_app_url: str) -> None:
    sink = WriteEndpoint(url=f"{chatbot_app_url}/api/messages", field="text", headers=_AUTH)
    async with HttpClient(_scope()) as client:
        chat = AiChatClient(client, f"{chatbot_app_url}/api/chat", prompt_field="message", headers=_AUTH)
        findings = await StoredInjectionScanner(client, chat, [sink]).scan()
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "llm-stored-injection" and f.family == "llm"
    assert "text" in f.injection_point.name


@pytest.mark.asyncio
async def test_hardened_assistant_is_not_flagged(chatbot_app_url: str) -> None:
    # Same plant, but the assistant that treats retrieved notes strictly as data.
    sink = WriteEndpoint(url=f"{chatbot_app_url}/api/messages", field="text", headers=_AUTH)
    async with HttpClient(_scope()) as client:
        chat = AiChatClient(client, f"{chatbot_app_url}/api/chat_safe", prompt_field="message", headers=_AUTH)
        findings = await StoredInjectionScanner(client, chat, [sink]).scan()
    assert findings == []


@pytest.mark.asyncio
async def test_wrong_sink_field_does_not_persist_and_stays_silent(chatbot_app_url: str) -> None:
    # Planting into a field the store ignores never reaches retrieval → no finding.
    sink = WriteEndpoint(url=f"{chatbot_app_url}/api/messages", field="unused_field", headers=_AUTH)
    async with HttpClient(_scope()) as client:
        chat = AiChatClient(client, f"{chatbot_app_url}/api/chat", prompt_field="message", headers=_AUTH)
        findings = await StoredInjectionScanner(client, chat, [sink]).scan()
    assert findings == []


@pytest.mark.asyncio
async def test_discover_flow_finds_both_direct_and_stored_llm_issues(chatbot_app_url: str, monkeypatch) -> None:
    """The whole `ai --discover` wiring: with the chat + write endpoints the headless
    crawler would capture, it detects the assistant and reports the stored injection."""
    import dastcore.cli as cli
    from dastcore.config import RateLimitConfig

    candidates = [
        HttpRequest(method="GET", url=f"{chatbot_app_url}/"),
        HttpRequest(method="POST", url=f"{chatbot_app_url}/api/chat", headers=_AUTH, json_body={"message": "hola"}),
        HttpRequest(method="POST", url=f"{chatbot_app_url}/api/messages", headers=_AUTH, json_body={"text": "nota"}),
    ]

    class _FakeCrawler:
        def __init__(self, client, max_pages=200):
            pass

        async def crawl(self, start_url):
            return candidates

    monkeypatch.setattr(cli, "HttpCrawler", _FakeCrawler)

    config = ScanConfig(target=chatbot_app_url, rate_limit=RateLimitConfig(requests_per_second=50))
    profile, findings = await cli._run_ai_discover_scan(config, chatbot_app_url, dict(_AUTH), "", 50)
    assert profile is not None and profile.url.endswith("/api/chat")
    assert any(f.rule_id == "llm-stored-injection" for f in findings)


def test_infer_write_endpoints_skips_the_chat_and_non_string_fields() -> None:
    requests = [
        HttpRequest(method="POST", url="https://app.test/api/chat", json_body={"message": "hi"}),
        HttpRequest(method="POST", url="https://app.test/api/messages", json_body={"text": "x", "pinned": True}),
        HttpRequest(method="GET", url="https://app.test/api/messages", json_body=None),
    ]
    sinks = infer_write_endpoints(requests, exclude_urls=["https://app.test/api/chat"])
    assert len(sinks) == 1
    assert sinks[0].url.endswith("/api/messages") and sinks[0].field == "text"  # bool field skipped
