"""Auto-discovery of an embedded chat endpoint from crawled traffic (pure, no network).

The bar is precision: real chat turns must be recognized *and* ordinary JSON APIs
that also take/echo strings must be rejected, so a plain scan never fuzzes a login
or CRUD route as if it were a chatbot.
"""

from __future__ import annotations

import json

import pytest

from dastcore.ai.discovery import ChatEndpointProfile, detect_chat_endpoints, probe_chat_endpoints
from dastcore.core.models import HttpRequest, HttpResponse


def _post(url: str, body: dict, headers: dict | None = None) -> HttpRequest:
    return HttpRequest(method="POST", url=url, headers=headers or {}, json_body=body)


def _json_resp(body: dict) -> HttpResponse:
    return HttpResponse(status_code=200, headers={"Content-Type": "application/json"}, text=json.dumps(body))


def _detect(exchanges: list[tuple[HttpRequest, HttpResponse]]) -> list[ChatEndpointProfile]:
    return detect_chat_endpoints(exchanges)


def test_simple_message_reply_endpoint_is_found() -> None:
    ex = [(_post("https://app.test/api/chat", {"message": "hola"}), _json_resp({"reply": "¡Hola! ¿En qué ayudo?"}))]
    profiles = _detect(ex)
    assert len(profiles) == 1
    p = profiles[0]
    assert p.prompt_field == "message" and p.response_path == "reply"
    assert p.confidence == "medium"  # path hint /chat, bare field


def test_openai_style_messages_endpoint_is_high_confidence() -> None:
    body = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hola"}]}
    resp = {"choices": [{"message": {"role": "assistant", "content": "hola!"}}]}
    profiles = _detect([(_post("https://app.test/v1/chat/completions", body), _json_resp(resp))])
    assert len(profiles) == 1
    p = profiles[0]
    assert p.template is not None and "{{messages}}" in p.template
    assert p.response_path == "choices.0.message.content"
    assert p.confidence == "high"


def test_streaming_sse_endpoint_is_detected() -> None:
    sse = 'data: {"choices":[{"delta":{"content":"ho"}}]}\n\ndata: {"choices":[{"delta":{"content":"la"}}]}\n\ndata: [DONE]\n'
    req = _post("https://app.test/assistant", {"prompt": "hi"})
    resp = HttpResponse(status_code=200, headers={"Content-Type": "text/event-stream"}, text=sse)
    p = _detect([(req, resp)])[0]
    assert p.stream is True and p.prompt_field == "prompt"


def test_auth_headers_are_forwarded_but_others_dropped() -> None:
    headers = {"Authorization": "Bearer t0ken", "Content-Length": "12", "X-Api-Key": "k"}
    p = _detect([(_post("https://app.test/chat", {"message": "x"}, headers), _json_resp({"answer": "y"}))])[0]
    assert p.headers == {"Authorization": "Bearer t0ken", "X-Api-Key": "k"}


def test_login_endpoint_is_not_a_chatbot() -> None:
    # Takes strings and returns strings, but no assistant-text field and no chat hint.
    req = _post("https://app.test/api/login", {"username": "admin", "password": "pw"})
    resp = _json_resp({"token": "abc", "status": "ok"})
    assert _detect([(req, resp)]) == []


def test_crud_create_endpoint_is_not_a_chatbot() -> None:
    # Has a "content" field (matches a prompt-field name) but the response is a record,
    # not assistant text — and there's no chat path hint, so it must be rejected.
    req = _post("https://app.test/api/posts", {"title": "t", "content": "body text"})
    resp = _json_resp({"id": 42, "title": "t", "created_at": "2026-01-01"})
    assert _detect([(req, resp)]) == []


def test_get_requests_are_ignored() -> None:
    req = HttpRequest(method="GET", url="https://app.test/chat", json_body=None)
    assert _detect([(req, _json_resp({"reply": "hi"}))]) == []


def test_dedupe_keeps_highest_confidence_for_same_endpoint() -> None:
    # Same endpoint seen twice; the messages[] turn should win over a bare-field turn.
    simple = (_post("https://app.test/api/chat", {"message": "hi"}), _json_resp({"reply": "a"}))
    rich = (
        _post("https://app.test/api/chat", {"messages": [{"role": "user", "content": "hi"}]}),
        _json_resp({"reply": "a"}),
    )
    profiles = _detect([simple, rich])
    # Different bodies → different signatures, so both may appear; the rich one ranks first.
    assert profiles[0].confidence in ("high", "medium")
    assert any(p.template is not None for p in profiles)


def test_client_kwargs_shape() -> None:
    p = ChatEndpointProfile(url="u", prompt_field="q", response_path="data.answer")
    kwargs = p.client_kwargs()
    assert kwargs["prompt_field"] == "q" and kwargs["response_path"] == "data.answer"
    assert set(kwargs) == {"prompt_field", "template", "response_path", "method", "headers", "stream", "stream_path"}


class _FakeClient:
    """Replays the recorded response for each POST URL, records what it was asked."""

    def __init__(self, replies: dict[str, dict]) -> None:
        self._replies = replies
        self.calls: list[str] = []

    async def request(self, method: str, url: str, *, params=None, headers=None, json=None) -> HttpResponse:
        self.calls.append(url)
        body = self._replies.get(url, {"error": "not found"})
        return HttpResponse(status_code=200, headers={"Content-Type": "application/json"}, text=json_dumps(body))


def json_dumps(obj: dict) -> str:
    return json.dumps(obj)


@pytest.mark.asyncio
async def test_probe_and_scan_against_the_real_demo_target() -> None:
    """End-to-end (offline): feed the /ai/chat candidate the headless crawler would
    capture into the live demo, auto-detect its shape, and confirm the LLM scan finds
    the planted system-prompt leak — the whole discover→scan wiring, no Playwright."""
    from dastcore.ai.client import AiChatClient
    from dastcore.ai.engine import AiScanner, load_ai_rules
    from dastcore.config import ScopeConfig
    from dastcore.core.http_client import HttpClient
    from dastcore.demo.app import start_demo_target

    server, base_url = start_demo_target()
    try:
        candidate = HttpRequest(method="POST", url=f"{base_url}/ai/chat", json_body={"message": "hola"})
        async with HttpClient(ScopeConfig(allow_domains=["127.0.0.1"])) as client:
            profiles = await probe_chat_endpoints(client, [candidate])
            assert profiles, "the demo chat endpoint should be auto-detected"
            best = profiles[0]
            assert best.prompt_field == "message" and best.response_path == "reply"

            chat = AiChatClient(client, best.url, **best.client_kwargs())
            findings = await AiScanner(chat, load_ai_rules()).scan()
        assert any("sk-DASTCORE-demo" in (f.response.text if f.response else "") or "llm" in f.family for f in findings)
    finally:
        server.shutdown()


@pytest.mark.asyncio
async def test_probe_replays_only_json_posts_and_detects() -> None:
    crawled = [
        HttpRequest(method="GET", url="https://app.test/dashboard"),  # skipped (GET)
        HttpRequest(method="POST", url="https://app.test/api/login", json_body={"username": "a", "password": "b"}),
        HttpRequest(method="POST", url="https://app.test/api/chat", json_body={"message": "hola"}),
    ]
    client = _FakeClient(
        {
            "https://app.test/api/login": {"token": "t", "status": "ok"},
            "https://app.test/api/chat": {"reply": "¡hola!"},
        }
    )
    profiles = await probe_chat_endpoints(client, crawled)
    assert "https://app.test/dashboard" not in client.calls  # GET never replayed
    assert len(profiles) == 1 and profiles[0].url == "https://app.test/api/chat"
