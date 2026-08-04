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
        method: str = "POST",
        headers: dict[str, str] | None = None,
    ) -> None:
        self._http = http_client
        self._url = url
        self._prompt_field = prompt_field
        self._template = template
        self._response_path = response_path
        self._method = method.upper()
        self._headers = headers or {}

    def _build_body(self, prompt: str) -> dict | list:
        if self._template:
            # JSON-escape the prompt so quotes/newlines don't break the template.
            escaped = json.dumps(prompt)[1:-1]
            return json.loads(self._template.replace("{{prompt}}", escaped))
        return {self._prompt_field: prompt}

    def build_request(self, prompt: str) -> HttpRequest:
        return HttpRequest(
            method=self._method,  # type: ignore[arg-type]
            url=self._url,
            headers=dict(self._headers),
            json_body=self._build_body(prompt),
        )

    async def ask(self, prompt: str) -> tuple[str, HttpRequest, HttpResponse]:
        """Send `prompt`; return (answer_text, request, response). Answer is '' if unparseable."""
        request = self.build_request(prompt)
        response = await self._http.request(
            request.method,
            request.url,
            headers=request.headers or None,
            json=request.json_body,
        )
        try:
            payload = json.loads(response.text)
        except (json.JSONDecodeError, ValueError):
            return "", request, response
        text = extract_response_text(payload, self._response_path)
        return (text or ""), request, response
