"""Optional LLM layer: polish the WRITING of a bounty draft — never the facts, never the verdict.

The finding was already confirmed by a runtime oracle and the deterministic report (PoC, URL, parameter,
severity, VRT, CVSS, CWE, remediation) is already complete. This layer, when an API key is present and the
operator opts in, rewrites only the prose — a tighter summary, a clearer impact narrative — leaving every
technical fact untouched. The AI never decides whether something is a vulnerability and never submits;
without a key (or on any error) the deterministic draft is returned byte-for-byte, so it is never on the
critical path. Mirrors the payload generator's optional, gated, fail-open shape.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

_MODEL = "claude-opus-5"
_MAX_TOKENS = 2048

_SYSTEM = (
    "You are an editor polishing a bug-bounty vulnerability report whose finding has ALREADY been "
    "confirmed by a runtime oracle. Improve ONLY the writing: a clearer summary and a tighter, more "
    "convincing impact narrative, in the same language as the draft.\n\n"
    "Hard rules — you are an editor, not a researcher:\n"
    "- NEVER change a technical fact: keep the exact URL, HTTP method, parameter, the PoC/curl command "
    "verbatim, the severity, VRT category, CVSS vector, CWE and OWASP reference exactly as given.\n"
    "- NEVER invent impact, steps, or evidence beyond what the draft states, and never remove the "
    "reproduction steps or the PoC.\n"
    "- NEVER decide whether the target is vulnerable; that is already settled by the oracle.\n"
    "- Preserve the Markdown section structure and any warning banners (e.g. a 'NO LISTO PARA ENVIAR' "
    "notice) unchanged.\n"
    "- Output the full polished Markdown report ONLY — no commentary before or after."
)


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


def _extract_text(response: Any) -> str:
    if getattr(response, "stop_reason", None) == "refusal":
        return ""
    for block in response.content:
        if getattr(block, "type", None) == "text":
            return str(block.text)
    return ""


class AiReportWriter:
    """Polishes a deterministic draft's prose. Injection seam: ``client`` exposes the Anthropic
    ``messages.create`` shape (a fake is used in tests, no network)."""

    def __init__(self, client: Any, *, model: str = _MODEL, max_tokens: int = _MAX_TOKENS) -> None:
        self._client = client
        self._model = model
        self._max_tokens = max_tokens

    async def polish_draft(self, draft: str) -> str:
        """Return a prose-polished version of ``draft``. Best-effort: any error (network, parse, refusal)
        or an empty/too-short result returns the original draft, so the facts always survive intact."""
        prompt = (
            "Polish the prose of this confirmed bug-bounty report draft, keeping every technical fact, the "
            "PoC, the section structure and any banners exactly as-is:\n\n" + draft
        )
        try:
            response = await asyncio.to_thread(
                lambda: self._client.messages.create(
                    model=self._model,
                    max_tokens=self._max_tokens,
                    system=_SYSTEM,
                    messages=[{"role": "user", "content": prompt}],
                )
            )
            polished = _extract_text(response).strip()
        except Exception:  # noqa: BLE001 — any failure degrades to the deterministic draft
            return draft
        # A degenerate result (empty, or so short it likely dropped the report) is not trusted.
        return polished if len(polished) >= max(80, len(draft) // 2) else draft


def build_report_writer(api_key: str | None = None) -> AiReportWriter | None:
    """Build a report writer from an API key / ``ANTHROPIC_API_KEY``, or None when unavailable."""
    client = _build_client(api_key)
    return AiReportWriter(client) if client is not None else None
