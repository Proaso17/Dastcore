"""Adapter for talking to an arbitrary chat / completion endpoint.

Chat APIs vary wildly in request and response shape, so the prompt placement and
the answer extraction are both configurable:

* prompt: either a single JSON field (`--ai-prompt-field message`) or a full JSON
  request template with a `{{prompt}}` placeholder (`--ai-template`), which covers
  OpenAI-style `{"messages":[{"role":"user","content":"{{prompt}}"}]}` bodies.
* response: a dot-path (`--ai-response-path choices.0.message.content`) or, if
  omitted, auto-detection of the most common answer fields.
"""
from __future__ import annotations

import json
import secrets

from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest, HttpResponse

# Response fields tried, in order, when no explicit path is configured.
_AUTO_RESPONSE_PATHS = (
    "reply",
    "response",
    "answer",
    "message",
    "output",
    "text",
    "content",
    "choices.0.message.content",
    "choices.0.text",
    "data.reply",
    "data.answer",
    "result",
)


def _walk_path(data: object, path: str) -> object | None:
    current = data
    for part in path.split("."):
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def extract_response_text(payload: object, response_path: str | None) -> str | None:
    """Pull the assistant's text out of a decoded JSON response body."""
    if response_path:
        value = _walk_path(payload, response_path)
        return value if isinstance(value, str) else None
    for path in _AUTO_RESPONSE_PATHS:
        value = _walk_path(payload, path)
        if isinstance(value, str):
            return value
    if isinstance(payload, str):
        return payload
    return None


class AiChatClient:
    """Sends prompts to a chat endpoint and returns the model's text answer."""

    def __init__(
        self,
        http_client: HttpClient,
        url: str,
        *,
        prompt_field: str = "message",
        template: str | None = None,
        response_path: str | None = None,
        conversation_field: str = "conversation_id",
        method: str = "POST",
        headers: dict[str, str] | None = None,
    ) -> None:
        self._http = http_client
        self._url = url
        self._prompt_field = prompt_field
        self._template = template
        self._response_path = response_path
        self._conversation_field = conversation_field
        self._method = method.upper()
        self._headers = headers or {}

    def _build_body(
        self,
        message: str,
        *,
        vector_field: str | None = None,
        vector_value: str | None = None,
        conversation_id: str | None = None,
        messages: list[dict] | None = None,
    ) -> dict | list:
        if self._template:
            if "{{messages}}" in self._template and messages is not None:
                return json.loads(self._template.replace("{{messages}}", json.dumps(messages)))
            escaped = json.dumps(message)[1:-1]  # JSON-escape so quotes/newlines don't break it
            return json.loads(self._template.replace("{{prompt}}", escaped))
        body: dict = {self._prompt_field: message}
        if vector_field and vector_value is not None:
            body[vector_field] = vector_value
        if conversation_id is not None:
            body[self._conversation_field] = conversation_id
        return body

    def _request(self, body: dict | list) -> HttpRequest:
        return HttpRequest(method=self._method, url=self._url, headers=dict(self._headers), json_body=body)  # type: ignore[arg-type]

    async def _send(self, request: HttpRequest) -> tuple[str, HttpRequest, HttpResponse]:
        response = await self._http.request(
            request.method, request.url, headers=request.headers or None, json=request.json_body
        )
        try:
            payload = json.loads(response.text)
        except (json.JSONDecodeError, ValueError):
            return "", request, response
        return (extract_response_text(payload, self._response_path) or ""), request, response

    async def ask(self, prompt: str) -> tuple[str, HttpRequest, HttpResponse]:
        """Single-turn: send `prompt` in the configured field/template."""
        return await self._send(self._request(self._build_body(prompt)))

    async def ask_via(
        self, field: str, payload: str, *, base_message: str = "Please summarize the provided document."
    ) -> tuple[str, HttpRequest, HttpResponse]:
        """Indirect injection: benign user message + malicious content in another field (e.g. `context`)."""
        return await self._send(self._request(self._build_body(base_message, vector_field=field, vector_value=payload)))

    async def converse(self, turns: list[str]) -> tuple[str, HttpRequest, HttpResponse]:
        """Multi-turn: send `turns` in order, returning the last turn's (answer, request, response).

        Uses the message-history array when the template supports `{{messages}}`, otherwise a
        stable conversation id (for stateful/thread-based endpoints).
        """
        conversation_id = "dast-" + secrets.token_hex(4)
        messages: list[dict] = []
        last: tuple[str, HttpRequest, HttpResponse] | None = None
        for turn in turns:
            if self._template and "{{messages}}" in self._template:
                messages.append({"role": "user", "content": turn})
                body = self._build_body(turn, messages=messages)
            else:
                body = self._build_body(turn, conversation_id=conversation_id)
            answer, request, response = await self._send(self._request(body))
            messages.append({"role": "assistant", "content": answer})
            last = (answer, request, response)
        assert last is not None
        return last
