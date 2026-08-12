"""Optional AI triage layer (Module 15, ``--ai-triage``).

**Non-negotiable contract:** the AI never confirms, creates, or elevates a vulnerability.
The ground truth stays the oracle (differential / time-based / OAST). This layer receives
ONLY findings that an oracle already confirmed, plus their evidence, and produces three
purely *editorial* artefacts, every one tagged ``ai_generated``:

1. an executive narrative summarising the confirmed exposure,
2. root-cause groups (which confirmed findings share one underlying defect), and
3. an advisory *business* severity per finding — a second opinion that sits *beside* the
   finding's oracle-backed technical severity and never overwrites it.

Enforcement is structural, not just prompted: the model only ever sees finding IDs we
sent, and any ID it returns that we didn't send is dropped on parse — so it cannot invent
a finding or attach advice to one that doesn't exist. Without an API key (or the optional
``anthropic`` dependency) the layer degrades gracefully to an empty, ``generated=False``
result; it is never on the critical path of a scan.
"""

from __future__ import annotations

import json
import os
from typing import Any

from pydantic import BaseModel, Field

from dastcore.core.models import Finding

_MODEL = "claude-opus-5"
_MAX_TOKENS = 4096

_SYSTEM = (
    "You are a triage assistant embedded in a black-box DAST scanner. Every finding you "
    "receive has ALREADY been confirmed by a runtime oracle (differential, time-based, or "
    "out-of-band). Your job is strictly editorial: classify, group by root cause, prioritise "
    "for a business audience, and write remediation narrative — working only from the evidence "
    "given.\n\n"
    "Hard rules you must never break:\n"
    "- Never claim a finding is a false positive, unconfirmed, or 'needs verification'. The "
    "oracle already confirmed it; you have no authority to overturn that.\n"
    "- Never invent findings, endpoints, or evidence. Reference only the finding IDs provided.\n"
    "- Your 'business_severity' is an advisory second opinion for prioritisation; it does not "
    "replace the technical severity and must be justified from the evidence given.\n"
    "- Group findings by shared underlying defect (root cause), not by superficial similarity."
)

# Structured-output schema: constrains the model to exactly the editorial fields we consume.
_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string"},
        "root_cause_groups": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "root_cause": {"type": "string"},
                    "finding_ids": {"type": "array", "items": {"type": "string"}},
                    "remediation": {"type": "string"},
                },
                "required": ["title", "root_cause", "finding_ids", "remediation"],
                "additionalProperties": False,
            },
        },
        "business_severity": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "level": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "rationale": {"type": "string"},
                },
                "required": ["finding_id", "level", "rationale"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["executive_summary", "root_cause_groups", "business_severity"],
    "additionalProperties": False,
}


class RootCauseGroup(BaseModel):
    """A cluster of confirmed findings sharing one underlying defect. AI-authored."""

    title: str
    root_cause: str
    finding_ids: list[str] = Field(default_factory=list)
    remediation: str
    ai_generated: bool = True


class BusinessSeverity(BaseModel):
    """An advisory business-impact severity for one finding, beside its technical severity."""

    finding_id: str
    level: str
    rationale: str
    ai_generated: bool = True


class AiTriageResult(BaseModel):
    """The editorial output of the AI triage layer. Empty and ``generated=False`` when the
    layer was unavailable or had nothing to triage — callers can always render it safely."""

    generated: bool = False
    model: str | None = None
    executive_summary: str = ""
    root_cause_groups: list[RootCauseGroup] = Field(default_factory=list)
    business_severity: list[BusinessSeverity] = Field(default_factory=list)
    error: str | None = None
    ai_generated: bool = True


def _confirmed(findings: list[Finding]) -> list[Finding]:
    """Only oracle-backed, non-suppressed findings are eligible — the AI never sees the rest."""
    return [f for f in findings if f.evidence and not f.suppressed]


def build_triage_input(findings: list[Finding]) -> str:
    """Serialise confirmed findings to the compact JSON the model is given.

    Includes only already-public finding metadata and its confirming evidence — never
    scanner internals or fixture source. Pure, so it can be asserted on in tests.
    """
    from urllib.parse import urlsplit

    items = []
    for f in findings:
        point = f.injection_point
        items.append(
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "name": f.name,
                "family": f.family,
                "technical_severity": f.severity,
                "cwe": f.cwe,
                "owasp": f.owasp,
                "cvss_score": f.cvss_score,
                "confidence": f.confidence,
                "location": f"{f.request.method} {urlsplit(f.request.url).path or '/'} ({point.location}:{point.name})",
                "evidence": [{"type": e.type, "confidence": e.confidence, "data": e.data} for e in f.evidence],
                "attack_chain": [{"actor": s.actor, "action": s.action, "detail": s.detail} for s in f.attack_chain],
            }
        )
    return json.dumps(items, ensure_ascii=False, indent=2)


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


def _extract_json(response: Any) -> dict[str, Any]:
    """Pull the structured-output JSON object out of a Messages API response."""
    if getattr(response, "stop_reason", None) == "refusal":
        raise ValueError("model declined the request")
    text = next(block.text for block in response.content if getattr(block, "type", None) == "text")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("triage response was not a JSON object")
    return data


def triage_findings(
    findings: list[Finding],
    *,
    api_key: str | None = None,
    client: Any | None = None,
    model: str = _MODEL,
    max_tokens: int = _MAX_TOKENS,
) -> AiTriageResult:
    """Run the AI triage layer over confirmed findings, degrading gracefully when offline.

    ``client`` is an injection seam for tests; in production it is built from ``api_key`` or
    ``ANTHROPIC_API_KEY``. Returns an ``AiTriageResult`` that never mutates the input findings
    and only references IDs that were actually sent (hallucinated IDs are dropped).
    """
    result = AiTriageResult()
    confirmed = _confirmed(findings)
    if not confirmed:
        return result  # nothing oracle-confirmed to triage

    client = client or _build_client(api_key)
    if client is None:
        result.error = "AI triage skipped: no Anthropic API key (set ANTHROPIC_API_KEY or pass --ai-triage-key)"
        return result

    try:
        payload = build_triage_input(confirmed)
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=_SYSTEM,
            output_config={"format": {"type": "json_schema", "schema": _SCHEMA}},
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Triage the following CONFIRMED findings. Return the executive summary, "
                        "root-cause groups, and advisory business severities as instructed.\n\n"
                        f"{payload}"
                    ),
                }
            ],
        )
        data = _extract_json(response)
    except Exception as exc:  # noqa: BLE001 — any failure degrades to a skipped-triage result
        result.error = f"AI triage unavailable: {exc}"
        return result

    known = {f.id for f in confirmed}
    groups: list[RootCauseGroup] = []
    for raw in data.get("root_cause_groups", []):
        ids = [fid for fid in raw.get("finding_ids", []) if fid in known]  # drop hallucinated IDs
        if not ids:
            continue
        groups.append(
            RootCauseGroup(
                title=str(raw.get("title", "")),
                root_cause=str(raw.get("root_cause", "")),
                finding_ids=ids,
                remediation=str(raw.get("remediation", "")),
            )
        )

    severities: list[BusinessSeverity] = []
    valid_levels = {"critical", "high", "medium", "low", "info"}
    for raw in data.get("business_severity", []):
        fid = raw.get("finding_id")
        level = str(raw.get("level", "")).lower()
        if fid not in known or level not in valid_levels:  # only advise on findings we sent
            continue
        severities.append(BusinessSeverity(finding_id=fid, level=level, rationale=str(raw.get("rationale", ""))))

    result.generated = True
    result.model = model
    result.executive_summary = str(data.get("executive_summary", ""))
    result.root_cause_groups = groups
    result.business_severity = severities
    return result
