"""Ready-to-use presets for common chat / completion APIs.

A preset removes the need to hand-write --ai-template / --ai-response-path /
auth headers for the usual providers. `resolve_preset` turns a preset name (+ an
optional model and API key) into the concrete `(template, response_path, headers)`
the AiChatClient needs.

The template uses `{{messages}}` where the provider expects a chat history array
(the client wraps a single prompt into a one-message array automatically) or
`{{prompt}}` for single-string bodies.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AiPreset:
    template: str
    response_path: str
    auth_header: str | None = None
    auth_prefix: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)
    default_model: str = ""
    note: str = ""


AI_PRESETS: dict[str, AiPreset] = {
    # OpenAI Chat Completions — also covers the many OpenAI-compatible servers
    # (vLLM, LM Studio, LocalAI, Together, Groq, Mistral, DeepSeek, ...).
    "openai": AiPreset(
        template='{"model":"{{model}}","messages":{{messages}}}',
        response_path="choices.0.message.content",
        auth_header="Authorization",
        auth_prefix="Bearer ",
        default_model="gpt-4o-mini",
        note="OpenAI y compatibles (vLLM, LM Studio, Groq, Together, Mistral…).",
    ),
    "azure-openai": AiPreset(
        template='{"messages":{{messages}}}',
        response_path="choices.0.message.content",
        auth_header="api-key",
        default_model="",
        note="Azure OpenAI (el modelo/deployment va en la URL).",
    ),
    "anthropic": AiPreset(
        template='{"model":"{{model}}","max_tokens":1024,"messages":{{messages}}}',
        response_path="content.0.text",
        auth_header="x-api-key",
        extra_headers={"anthropic-version": "2023-06-01"},
        default_model="claude-3-5-sonnet-latest",
    ),
    "ollama": AiPreset(
        template='{"model":"{{model}}","messages":{{messages}},"stream":false}',
        response_path="message.content",
        default_model="llama3",
        note="Ollama local (/api/chat). Sin auth por defecto.",
    ),
    "cohere": AiPreset(
        template='{"model":"{{model}}","message":"{{prompt}}"}',
        response_path="text",
        auth_header="Authorization",
        auth_prefix="Bearer ",
        default_model="command-r",
    ),
    "huggingface": AiPreset(
        template='{"inputs":"{{prompt}}"}',
        response_path="0.generated_text",
        auth_header="Authorization",
        auth_prefix="Bearer ",
    ),
    "gemini": AiPreset(
        template='{"contents":[{"parts":[{"text":"{{prompt}}"}]}]}',
        response_path="candidates.0.content.parts.0.text",
        auth_header="x-goog-api-key",
        default_model="gemini-1.5-flash",
        note="Google Gemini (generateContent). El modelo va en la URL.",
    ),
}


def resolve_preset(name: str, *, model: str = "", api_key: str = "") -> tuple[str, str, dict[str, str]]:
    """Return (template, response_path, headers) for a preset."""
    preset = AI_PRESETS[name]
    template = preset.template.replace("{{model}}", model or preset.default_model)
    headers: dict[str, str] = dict(preset.extra_headers)
    if api_key and preset.auth_header:
        headers[preset.auth_header] = f"{preset.auth_prefix}{api_key}"
    return template, preset.response_path, headers
