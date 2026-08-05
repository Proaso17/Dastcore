"""Validation oracles.

An oracle turns a base response, a mutated response, and the payload that
produced it into `Evidence` — or nothing. This is the low-noise guarantee of
the whole project: a rule's payloads only ever produce a `Finding` if one of
its oracle checks actually fires here. No oracle match, no report.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

from dastcore.core.models import Evidence, HttpResponse

OracleCheckType = Literal["reflected", "response_match", "differential", "time_based", "oob"]
OraclePart = Literal["body", "headers"]


class OracleCheck(BaseModel):
    """One test within an `OracleSpec`. Fields not needed by `type` are simply unused."""

    type: OracleCheckType
    part: OraclePart = "body"
    patterns: list[str] = Field(default_factory=list)
    payload: str | None = None
    delay: float | None = None
    threshold_ms: float | None = None


class OracleSpec(BaseModel):
    """`any_of`: the first passing check is enough. `all_of`: every check must pass."""

    type: Literal["any_of", "all_of"] = "any_of"
    checks: list[OracleCheck]


def _headers_haystack(response: HttpResponse) -> str:
    return "\n".join(f"{name}: {value}" for name, value in response.headers.items())


def check_response_match(response: HttpResponse, patterns: list[str], part: OraclePart = "body") -> Evidence | None:
    haystack = response.text if part == "body" else _headers_haystack(response)
    for pattern in patterns:
        match = re.search(pattern, haystack, re.IGNORECASE)
        if match:
            return Evidence(type="response_match", data=match.group(0)[:200], confidence="high")
    return None


def check_reflected(response: HttpResponse, payload: str) -> Evidence | None:
    if payload and payload in response.text:
        return Evidence(type="reflected", data=payload, confidence="medium")
    return None


def check_differential(base: HttpResponse, mutated: HttpResponse) -> Evidence | None:
    """Flags a mutated request that started erroring server-side (2xx/4xx -> 5xx)."""
    if mutated.status_code >= 500 and base.status_code < 500:
        return Evidence(
            type="differential",
            data=f"status {base.status_code} -> {mutated.status_code}",
            confidence="medium",
        )
    return None


def check_time_based(mutated: HttpResponse, threshold_ms: float, baseline_ms: float = 0.0) -> Evidence | None:
    delta = mutated.elapsed_ms - baseline_ms
    if delta >= threshold_ms:
        return Evidence(
            type="time_based",
            data=f"{delta:.0f}ms slower than baseline (threshold {threshold_ms:.0f}ms)",
            confidence="medium",
        )
    return None


def _run_check(
    check: OracleCheck,
    *,
    base_response: HttpResponse,
    mutated_response: HttpResponse,
    payload: str,
) -> Evidence | None:
    if check.type == "response_match":
        return check_response_match(mutated_response, check.patterns, check.part)
    if check.type == "reflected":
        return check_reflected(mutated_response, payload)
    if check.type == "differential":
        return check_differential(base_response, mutated_response)
    if check.type == "time_based":
        return check_time_based(mutated_response, check.threshold_ms or 0.0, baseline_ms=base_response.elapsed_ms)
    if check.type == "oob":
        # OOB confirmation is out-of-band: it can't be judged from this single response.
        # The scanner correlates callbacks against the OAST provider instead.
        return None
    raise ValueError(f"Unknown oracle check type: {check.type}")


def evaluate_oracle(
    oracle: OracleSpec,
    *,
    base_response: HttpResponse,
    mutated_response: HttpResponse,
    payload: str,
) -> list[Evidence]:
    """Runs every check in `oracle` and returns the evidence that confirms the rule.

    `any_of` short-circuits on the first match. `all_of` requires every check to
    produce evidence; if even one doesn't, no evidence is returned at all.
    """
    evidences: list[Evidence] = []
    for check in oracle.checks:
        evidence = _run_check(check, base_response=base_response, mutated_response=mutated_response, payload=payload)
        if evidence is not None:
            evidences.append(evidence)
            if oracle.type == "any_of":
                return evidences

    if oracle.type == "all_of" and len(evidences) == len(oracle.checks):
        return evidences
    if oracle.type == "all_of":
        return []
    return []
