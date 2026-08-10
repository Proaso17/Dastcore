"""Core data model shared across the engine.

Grows incrementally with each phase: Phase 1 needs `HttpRequest`,
`HttpResponse` and `InjectionPoint`. Phase 2 adds `Payload`, `Evidence`
and `Finding` for the rule engine and oracles.
"""

from __future__ import annotations

import json as _json
from typing import Literal
from urllib.parse import urlencode, urlsplit

from pydantic import BaseModel, Field, computed_field

from dastcore.config import Severity

Method = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]
InjectionLocation = Literal["query", "body", "header", "cookie", "path", "json", "fragment"]
EvidenceType = Literal["reflected", "response_match", "differential", "time_based", "oob", "status", "dom_execution"]
Confidence = Literal["low", "medium", "high"]


def _shell_quote(value: str) -> str:
    """POSIX single-quote a value so it survives a shell verbatim."""
    return "'" + value.replace("'", "'\\''") + "'"


class HttpRequest(BaseModel):
    """A request the engine can (re)issue. Mutable copies are made via `model_copy`."""

    method: Method = "GET"
    url: str
    params: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    data: dict[str, str] | None = None
    json_body: dict | list | None = None

    def signature(self) -> str:
        """Identity used for crawl dedup: method + path + the *names* of all params/body keys.

        Deliberately ignores values — two requests to the same endpoint with the same
        parameter names are the same discovered "shape" even if the values differ.
        """
        path = urlsplit(self.url).path or "/"
        json_keys = tuple(sorted(self.json_body.keys())) if isinstance(self.json_body, dict) else ()
        query_keys = tuple(sorted(self.params.keys()))
        body_keys = tuple(sorted((self.data or {}).keys()))
        return f"{self.method} {path} q={query_keys} b={body_keys} j={json_keys}"

    def to_curl(self) -> str:
        """A copy-pasteable `curl` command that reproduces this exact request."""
        url = self.url
        if self.params:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{urlencode(self.params)}"
        parts = ["curl", "-i", "-X", self.method, _shell_quote(url)]
        headers = dict(self.headers)
        if self.json_body is not None:
            headers.setdefault("Content-Type", "application/json")
        for name, value in headers.items():
            parts += ["-H", _shell_quote(f"{name}: {value}")]
        if self.cookies:
            parts += ["-b", _shell_quote("; ".join(f"{k}={v}" for k, v in self.cookies.items()))]
        if self.json_body is not None:
            parts += ["--data", _shell_quote(_json.dumps(self.json_body, ensure_ascii=False))]
        elif self.data:
            parts += ["--data", _shell_quote(urlencode(self.data))]
        return " ".join(parts)


class HttpResponse(BaseModel):
    """A response with timing, used both for normal results and injection oracles."""

    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    text: str = ""
    elapsed_ms: float = 0.0
    url: str = ""


class InjectionPoint(BaseModel):
    """A single mutable parameter on a `request_template`, ready for the rule engine to fuzz."""

    location: InjectionLocation
    name: str
    base_value: str = ""
    request_template: HttpRequest


class Payload(BaseModel):
    """A single value the rule engine will try at an injection point."""

    value: str
    family: str
    oob: bool = False


class Evidence(BaseModel):
    """What convinced an oracle a payload actually worked, not just noise."""

    type: EvidenceType
    data: str
    confidence: Confidence = "medium"


class ChainStep(BaseModel):
    """One step in a multi-stage attack narrative (who did what, and what it proved).

    Populated for findings whose confirmation spans several requests/actors — e.g. a
    stored prompt injection (plant → retrieve → execute) or a cross-tenant leak/action
    (victim plants → attacker reads/writes → out-of-band verification) — so the report
    can tell the story instead of listing disconnected evidence lines."""

    actor: str  # who acts: e.g. "Attacker (tenant A)", "Assistant", "Victim (tenant B)", "dastcore"
    action: str  # short label: e.g. "Plant", "Execute on retrieval", "Confirm"
    detail: str  # human-readable description of the step


class Finding(BaseModel):
    """A confirmed vulnerability: always backed by at least one `Evidence` entry."""

    id: str
    rule_id: str
    name: str
    severity: Severity
    cwe: str
    owasp: str
    injection_point: InjectionPoint
    evidence: list[Evidence] = Field(default_factory=list)
    request: HttpRequest
    response: HttpResponse
    remediation: str
    cvss: str | None = None  # explicit CVSS 3.1 base vector; falls back to a severity default
    suppressed: bool = False  # triaged as accepted/false-positive via a .dastcore-ignore rule
    suppression_reason: str | None = None
    family: str = ""  # vulnerability family (from the rule); groups cross-technique confirmations
    corroborated_by: list[str] = Field(default_factory=list)  # other rules confirming the same scenario
    attack_chain: list[ChainStep] = Field(default_factory=list)  # ordered narrative for multi-stage attacks

    @computed_field  # type: ignore[prop-decorator]
    @property
    def repro_curl(self) -> str:
        """A ready-to-run curl reproducing the request that triggered this finding."""
        return self.request.to_curl()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cvss_vector(self) -> str:
        """The resolved CVSS 3.1 vector (explicit rule vector, else a severity default)."""
        from dastcore.cvss import default_vector

        return self.cvss or default_vector(self.severity)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cvss_score(self) -> float:
        """The CVSS 3.1 base score (0.0–10.0) for this finding."""
        from dastcore.cvss import base_score

        return base_score(self.cvss_vector)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def confidence(self) -> Confidence:
        """How trustworthy this finding is, from the agreement of its evidence signals
        plus any cross-technique corroboration at the same injection point."""
        from dastcore.validation.confidence import score_confidence

        return score_confidence(self.evidence, corroborated=len(self.corroborated_by))[0]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def confidence_score(self) -> float:
        """Numeric confidence (0.0–1.0) backing the `confidence` label."""
        from dastcore.validation.confidence import score_confidence

        return score_confidence(self.evidence, corroborated=len(self.corroborated_by))[1]
