"""AI-assisted payload generation (Module 15 extension).

The AI proposes candidate payloads tailored to *how* the scanner's marker input was reflected in
a response — breaking out of the exact quoting/tag/attribute it observed. **It never decides
whether the target is vulnerable.** Each suggested payload is validated by the rule's own oracle,
exactly like a declared payload, so the ground truth stays the oracle and the zero-false-positive
guarantee holds: the AI only widens the set of inputs tried.

Without an API key (or the optional ``anthropic`` dependency) the generator yields nothing and a
scan is byte-identical to a run without it — the layer is never on the critical path.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

_MODEL = "claude-opus-5"
_MAX_TOKENS = 1024
_MAX_PAYLOADS = 8

_SYSTEM = (
    "You generate candidate injection payloads for a black-box DAST scanner. You are given a "
    "vulnerability family and a snippet showing exactly how the scanner's unique marker was "
    "reflected in the target's HTTP response. Propose payloads most likely to TRIGGER or EXECUTE "
    "in that specific context — break out of the exact quotes/tag/attribute/JS or SQL context you "
    "see.\n\n"
    "Hard rules:\n"
    "- Output payload strings ONLY — no commentary, no explanation.\n"
    "- You never decide whether the target is vulnerable. A runtime oracle validates every payload "
    "you propose; your only job is to maximise the chance a REAL vulnerability is confirmed by "
    "tailoring to the observed reflection context.\n"
    "- Do not repeat payloads that were already tried."
)

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"payloads": {"type": "array", "items": {"type": "string"}}},
    "required": ["payloads"],
    "additionalProperties": False,
}


def _build_client(api_key: str | None) -> Any | None:
    """Construct an Anthropic client, or return None if no key / SDK is available."""
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    try:
        import anthropic
    except ImportError:
        return None
    return anthropic.Anthropic(api_key=key)


def _extract_payloads(response: Any) -> list[str]:
    if getattr(response, "stop_reason", None) == "refusal":
        return []
    text = next(block.text for block in response.content if getattr(block, "type", None) == "text")
    data = json.loads(text)
    raw = data.get("payloads", []) if isinstance(data, dict) else []
    return [p for p in raw if isinstance(p, str) and p]


class AiPayloadGenerator:
    """Proposes context-aware payloads. Injection seam: ``client`` is any object exposing the
    Anthropic ``messages.create`` shape (a fake is used in tests, no network)."""

    def __init__(self, client: Any, *, model: str = _MODEL, max_tokens: int = _MAX_TOKENS) -> None:
        self._client = client
        self._model = model
        self._max_tokens = max_tokens

    async def suggest(self, family: str, context: str, reflection_excerpt: str, tried: list[str]) -> list[str]:
        """Return candidate payloads for ``family`` given the observed reflection context.

        Best-effort: any error (network, parse, refusal) yields ``[]`` so the scan simply
        proceeds with the declared payloads. The blocking SDK call runs off the event loop.
        """
        prompt = (
            f"Vulnerability family: {family}\n"
            f"Reflection context: {context}\n"
            f"How the marker reflected (verbatim snippet):\n{reflection_excerpt}\n\n"
            f"Already tried (avoid these):\n{json.dumps(tried[:20], ensure_ascii=False)}\n\n"
            f"Propose up to {_MAX_PAYLOADS} payloads tailored to this exact context."
        )
        try:
            response = await asyncio.to_thread(
                lambda: self._client.messages.create(
                    model=self._model,
                    max_tokens=self._max_tokens,
                    system=_SYSTEM,
                    output_config={"format": {"type": "json_schema", "schema": _SCHEMA}},
                    messages=[{"role": "user", "content": prompt}],
                )
            )
            payloads = _extract_payloads(response)
        except Exception:  # noqa: BLE001 — any failure degrades to "no suggestions"
            return []
        seen = set(tried)
        unique: list[str] = []
        for payload in payloads:  # drop duplicates and already-tried payloads
            if payload not in seen:
                seen.add(payload)
                unique.append(payload)
        return unique[:_MAX_PAYLOADS]


def build_payload_generator(api_key: str | None = None) -> AiPayloadGenerator | None:
    """Build a generator from an API key / ``ANTHROPIC_API_KEY``, or None when unavailable."""
    client = _build_client(api_key)
    return AiPayloadGenerator(client) if client is not None else None
