"""Core data model shared across the engine.

Grows incrementally with each phase: Phase 1 needs `HttpRequest`,
`HttpResponse` and `InjectionPoint`. Phase 2 adds `Payload`, `Evidence`
and `Finding` for the rule engine and oracles.
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from dastcore.config import Severity

Method = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
InjectionLocation = Literal["query", "body", "header", "cookie", "path", "json", "fragment"]
EvidenceType = Literal["reflected", "response_match", "differential", "time_based", "oob", "status", "dom_execution"]
Confidence = Literal["low", "medium", "high"]


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
