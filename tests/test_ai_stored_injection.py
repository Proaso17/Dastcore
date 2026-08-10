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
    # multi-stage narrative: plant → execute on retrieval → confirm
    assert [s.action for s in f.attack_chain] == ["Plant", "Execute on retrieval", "Confirm"]


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


@pytest.mark.asyncio
async def test_discover_flow_does_not_auto_attack_a_low_confidence_candidate(chatbot_app_url, monkeypatch) -> None:
    """An ambiguous (low-confidence) endpoint is reported but never auto-attacked, so the
    flow can't fuzz a translate/search API that merely looks chat-shaped."""
    import dastcore.cli as cli
    from dastcore.ai.discovery import ChatEndpointProfile
    from dastcore.config import RateLimitConfig

    class _FakeCrawler:
        def __init__(self, client, max_pages=200):
            pass

        async def crawl(self, start_url):
            return []

    low = ChatEndpointProfile(url=f"{chatbot_app_url}/api/translate", prompt_field="text", confidence="low")

    async def _fake_probe(client, requests):
        return [low]

    monkeypatch.setattr(cli, "HttpCrawler", _FakeCrawler)
    monkeypatch.setattr(cli, "probe_chat_endpoints", _fake_probe)
    config = ScanConfig(target=chatbot_app_url, rate_limit=RateLimitConfig(requests_per_second=50))
    profile, findings = await cli._run_ai_discover_scan(config, chatbot_app_url, dict(_AUTH), "", 50)
    assert profile is low and findings == []  # reported, not attacked


@pytest.mark.asyncio
async def test_injection_lands_against_a_bot_obeying_a_different_phrasing() -> None:
    """The stacked-phrasing payload catches a bot that follows one wording ("include the
    exact text …") a single-phrasing payload would have missed — recall, still canary-gated."""
    import re

    from dastcore.ai.stored_injection import StoredInjectionScanner, WriteEndpoint
    from dastcore.core.models import HttpRequest, HttpResponse

    store: list[str] = []
    obey = re.compile(r"include the exact text (DCSTORED[0-9A-F]+)", re.IGNORECASE)

    class _FakeHttp:
        async def request(self, method, url, *, headers=None, json=None, **kw):
            store.append(str(json.get("text", "")))
            return HttpResponse(status_code=200, text="{}")

    class _FakeChat:
        async def ask(self, prompt):
            # This bot only obeys the "include the exact text X" instruction (latest wins).
            hit = next((m.group(1) for note in reversed(store) for m in [obey.search(note)] if m), "")
            req = HttpRequest(method="POST", url="https://app.test/api/chat", json_body={"message": prompt})
            return (f"Sure: {hit}" if hit else "How can I help?"), req, HttpResponse(status_code=200, text="ok")

    sink = WriteEndpoint(url="https://app.test/api/messages", field="text")
    findings = await StoredInjectionScanner(_FakeHttp(), _FakeChat(), [sink]).scan()  # type: ignore[arg-type]
    assert len(findings) == 1 and findings[0].rule_id == "llm-stored-injection"


def test_infer_write_endpoints_skips_the_chat_and_non_string_fields() -> None:
    requests = [
        HttpRequest(method="POST", url="https://app.test/api/chat", json_body={"message": "hi"}),
        HttpRequest(method="POST", url="https://app.test/api/messages", json_body={"text": "x", "pinned": True}),
        HttpRequest(method="GET", url="https://app.test/api/messages", json_body=None),
    ]
    sinks = infer_write_endpoints(requests, exclude_urls=["https://app.test/api/chat"])
    assert len(sinks) == 1
    assert sinks[0].url.endswith("/api/messages") and sinks[0].field == "text"  # bool field skipped
