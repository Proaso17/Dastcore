"""AI attack engine: runs LLM-specific probes and confirms them with low-noise oracles.

Two oracle types, both designed to avoid false positives against a model that just
echoes text:

* ``canary`` — the payload instructs the model to emit a unique random token. If that
  token appears in the answer, the model followed injected instructions. The token is
  fresh per attempt, so a reproducible hit is strong evidence (analogous to OAST).
* ``response_match`` — regex patterns, but a match only counts if the matched text is
  **not** present in the payload we sent (differential), so echoing the prompt back
  cannot trigger a finding.
"""
from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

from dastcore.ai.client import AiChatClient
from dastcore.config import Severity
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

DEFAULT_AI_RULES_DIR = Path(__file__).resolve().parent.parent / "ai_rules"


class AiOracle(BaseModel):
    type: Literal["canary", "response_match"]
    patterns: list[str] = Field(default_factory=list)


class AiRule(BaseModel):
    id: str
    name: str
    family: str = "llm"
    severity: Severity
    cwe: str
    owasp: str
    payloads: list[str] = Field(default_factory=list)
    oracle: AiOracle
    confirm_reproducible: bool = True
    remediation: str


def load_ai_rules(directory: Path | None = None) -> list[AiRule]:
    directory = directory or DEFAULT_AI_RULES_DIR
    return [AiRule.model_validate(yaml.safe_load(p.read_text(encoding="utf-8"))) for p in sorted(directory.glob("*.yaml"))]


def _new_canary() -> str:
    return f"DASTCORE{secrets.token_hex(8).upper()}"


def _match_response(response_text: str, patterns: list[str], payload: str) -> str | None:
    """Return the matched substring if a pattern hits text that isn't just echoed payload."""
    for pattern in patterns:
        for match in re.finditer(pattern, response_text, re.IGNORECASE):
            fragment = match.group(0)
            if fragment and fragment not in payload:
                return fragment
    return None


class AiScanner:
    """Runs the AI rule set against a single chat endpoint."""

    def __init__(self, chat_client: AiChatClient, rules: list[AiRule]) -> None:
        self._client = chat_client
        self._rules = rules

    async def _attempt(self, rule: AiRule, payload_template: str) -> tuple[Evidence, HttpRequest, HttpResponse] | None:
        canary = _new_canary()
        prompt = payload_template.replace("{{canary}}", canary)
        answer, request, response = await self._client.ask(prompt)

        if rule.oracle.type == "canary":
            if canary in answer:
                return Evidence(type="reflected", data=f"model emitted the injected canary {canary}", confidence="high"), request, response
            return None

        matched = _match_response(answer, rule.oracle.patterns, prompt)
        if matched is not None:
            return Evidence(type="response_match", data=f"model revealed: {matched[:120]}", confidence="high"), request, response
        return None

    async def _try_rule(self, rule: AiRule) -> Finding | None:
        for payload_template in rule.payloads:
            hit = await self._attempt(rule, payload_template)
            if hit is None:
                continue
            evidence, request, response = hit

            if rule.confirm_reproducible:
                confirm = await self._attempt(rule, payload_template)
                if confirm is None:
                    continue
                evidence = [evidence, confirm[0]]
            else:
                evidence = [evidence]

            return Finding(
                id=f"{rule.id}:{request.url}",
                rule_id=rule.id,
                name=rule.name,
                severity=rule.severity,
                cwe=rule.cwe,
                owasp=rule.owasp,
                injection_point=InjectionPoint(location="body", name="prompt", base_value="", request_template=request),
                evidence=evidence,
                request=request,
                response=response,
                remediation=rule.remediation,
            )
        return None

    async def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            finding = await self._try_rule(rule)
            if finding is not None:
                findings.append(finding)
        return findings
