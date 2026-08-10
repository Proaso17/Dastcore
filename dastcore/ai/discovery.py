"""Auto-discover an embedded chatbot endpoint from crawled traffic.

A chat/assistant widget in a web app is just an XHR/fetch call, but its request
and response shapes vary. This module looks at the requests the crawler captured
(and their responses) and, for the ones that *look like* a chat turn, produces a
``ChatEndpointProfile`` — the exact shape the ``AiChatClient`` needs (prompt field
or a ``{{prompt}}`` template, the dot-path to the answer, streaming). That lets a
plain ``dastcore`` run also exercise the embedded assistant without hand-config.

Detection is deliberately conservative: an endpoint is only accepted when it shows
a **request** signal (a user-text field, or an OpenAI-style ``messages`` array) AND
a **response** signal (a decodable assistant-text field, or an SSE/NDJSON stream).
Requiring both keeps ordinary CRUD/JSON APIs — which also take and echo strings —
from being mistaken for a chatbot.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from dastcore.ai.client import (
    _AUTO_RESPONSE_PATHS,
    _AUTO_STREAM_PATHS,
    _walk_path,
    extract_response_text,
    reassemble_stream,
)
from dastcore.core.models import HttpRequest, HttpResponse

# Body fields that plausibly carry the user's message (checked in order).
_PROMPT_FIELDS = (
    "message",
    "prompt",
    "query",
    "text",
    "input",
    "question",
    "content",
    "msg",
    "q",
    "user_input",
    "userMessage",
)

# Path fragments that hint at a conversational endpoint (a soft, corroborating signal).
_PATH_HINTS = (
    "chat",
    "message",
    "assistant",
    "chatbot",
    "bot",
    "completion",
    "converse",
    "conversation",
    "ask",
    "copilot",
    "agent",
    "llm",
    "ai",
)

_STREAM_CONTENT_TYPES = ("text/event-stream", "application/x-ndjson", "application/stream+json")


@dataclass
class ChatEndpointProfile:
    """Everything ``AiChatClient`` needs to talk to a discovered chat endpoint."""

    url: str
    method: str = "POST"
    prompt_field: str = "message"
    template: str | None = None
    response_path: str | None = None
    stream: bool = False
    stream_path: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    confidence: str = "medium"
    evidence: str = ""

    def client_kwargs(self) -> dict:
        """Keyword args for ``AiChatClient(http_client, url, **kwargs)``."""
        return {
            "prompt_field": self.prompt_field,
            "template": self.template,
            "response_path": self.response_path,
            "method": self.method,
            "headers": dict(self.headers),
            "stream": self.stream,
            "stream_path": self.stream_path,
        }


def _messages_array(body: object) -> list | None:
    """Return an OpenAI-style ``messages`` list if the body carries one."""
    if isinstance(body, dict):
        msgs = body.get("messages")
        if isinstance(msgs, list) and any(isinstance(m, dict) and "content" in m for m in msgs):
            return msgs
    return None


def _prompt_field_of(body: object) -> str | None:
    """Name of the field holding a non-empty user string, if the body has one."""
    if not isinstance(body, dict):
        return None
    for name in _PROMPT_FIELDS:
        value = body.get(name)
        if isinstance(value, str) and value.strip():
            return name
    return None


def _template_from_messages(body: dict) -> str | None:
    """Build a ``{{messages}}`` template from an observed body.

    We serialize the observed body but swap the messages array for the placeholder,
    so the scanner can inject its own single- or multi-turn payloads through it,
    preserving any sibling fields (``model``, ``temperature``, …).
    """
    try:
        skeleton = json.dumps({**body, "messages": "@@MSGS@@"})
    except (TypeError, ValueError):
        return None
    return skeleton.replace('"@@MSGS@@"', "{{messages}}")


def _looks_streamed(response: HttpResponse) -> tuple[bool, str | None]:
    """Detect an SSE/NDJSON answer and, if so, the delta path that reassembles it."""
    ctype = response.headers.get("Content-Type", "").lower()
    if not (any(s in ctype for s in _STREAM_CONTENT_TYPES) or response.text.lstrip().startswith("data:")):
        return False, None
    for path in _AUTO_STREAM_PATHS:
        if reassemble_stream(response.text, path).strip():
            return True, path
    # It streams, but none of the known delta paths matched — still usable via auto-detect.
    return bool(reassemble_stream(response.text, None).strip()), None


def _answer_path(response: HttpResponse) -> str | None:
    """Return the dot-path to the assistant text in a JSON response, or None.

    Prefers an explicit known path so the profile is stable across turns; None means
    either "let the client auto-detect" or "no assistant text here" (the caller
    disambiguates with a follow-up ``extract_response_text`` check).
    """
    try:
        payload = json.loads(response.text)
    except (json.JSONDecodeError, ValueError):
        return None
    for path in _AUTO_RESPONSE_PATHS:
        value = _walk_path(payload, path)
        if isinstance(value, str) and value.strip():
            return path
    # No known path matched; None lets the client auto-detect (or signals "no answer").
    return None


def detect_chat_endpoints(
    exchanges: list[tuple[HttpRequest, HttpResponse]],
) -> list[ChatEndpointProfile]:
    """Find embedded chat endpoints among crawled (request, response) pairs.

    Returns one profile per distinct endpoint, most-confident first. An endpoint is
    accepted only when it shows both a request-side and a response-side chat signal.
    """
    profiles: dict[str, ChatEndpointProfile] = {}
    for request, response in exchanges:
        if request.method.upper() != "POST" or request.json_body is None:
            continue

        messages = _messages_array(request.json_body)
        prompt_field = _prompt_field_of(request.json_body)
        if messages is None and prompt_field is None:
            continue  # no request-side signal

        streamed, stream_path = _looks_streamed(response)
        answer_path = None if streamed else _answer_path(response)
        if not streamed and answer_path is None:
            # No response-side signal unless the JSON at least yields *some* answer text.
            try:
                payload = json.loads(response.text)
            except (json.JSONDecodeError, ValueError):
                continue
            if not extract_response_text(payload, None):
                continue

        path_hint = any(hint in request.url.lower() for hint in _PATH_HINTS)
        # Message-array or an explicit path hint make it a confident chat endpoint;
        # a bare prompt-field on an unhinted URL is accepted but only "low" confidence.
        confidence = "high" if (messages is not None and path_hint) else "medium" if path_hint else "low"

        if messages is not None and isinstance(request.json_body, dict):
            template = _template_from_messages(request.json_body)
            profile = ChatEndpointProfile(
                url=request.url,
                method=request.method.upper(),
                template=template,
                response_path=answer_path,
                stream=streamed,
                stream_path=stream_path,
                headers=_forwardable_headers(request.headers),
                confidence=confidence,
                evidence="OpenAI-style messages[] request with an assistant reply",
            )
        else:
            profile = ChatEndpointProfile(
                url=request.url,
                method=request.method.upper(),
                prompt_field=prompt_field or "message",
                response_path=answer_path,
                stream=streamed,
                stream_path=stream_path,
                headers=_forwardable_headers(request.headers),
                confidence=confidence,
                evidence=f"chat-shaped JSON: field {prompt_field!r} in, assistant text out",
            )

        signature = f"{profile.method} {request.signature()}"
        existing = profiles.get(signature)
        if existing is None or _rank(profile.confidence) > _rank(existing.confidence):
            profiles[signature] = profile

    return sorted(profiles.values(), key=lambda p: _rank(p.confidence), reverse=True)


# Auth/content headers worth carrying onto the attack requests; hop-by-hop and
# length headers are recomputed by the client, so they are dropped.
_FORWARD_HEADERS = ("authorization", "cookie", "x-api-key", "api-key", "x-csrf-token", "x-xsrf-token")


def _forwardable_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() in _FORWARD_HEADERS}


def _rank(confidence: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(confidence, 0)


async def probe_chat_endpoints(http_client: object, requests: list[HttpRequest]) -> list[ChatEndpointProfile]:
    """Replay each candidate POST once to capture its response, then run detection.

    ``requests`` are the crawler's discovered requests (the headless engine captures
    the chat widget's XHR/fetch). Only JSON POSTs are replayed — a benign, read-only
    turn to observe the response shape — and out-of-scope/over-budget replays are
    skipped rather than aborting discovery.
    """
    from dastcore.core.http_client import BudgetExceededError, OutOfScopeError

    exchanges: list[tuple[HttpRequest, HttpResponse]] = []
    for request in requests:
        if request.method.upper() != "POST" or request.json_body is None:
            continue
        try:
            response = await http_client.request(  # type: ignore[attr-defined]
                request.method,
                request.url,
                params=request.params or None,
                headers=request.headers or None,
                json=request.json_body,
            )
        except (OutOfScopeError, BudgetExceededError):
            continue
        exchanges.append((request, response))
    return detect_chat_endpoints(exchanges)
