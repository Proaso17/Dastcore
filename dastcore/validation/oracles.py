"""Validation oracles.

An oracle turns a base response, a mutated response, and the payload that
produced it into `Evidence` — or nothing. This is the low-noise guarantee of
the whole project: a rule's payloads only ever produce a `Finding` if one of
its oracle checks actually fires here. No oracle match, no report.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Literal

from pydantic import BaseModel, Field

from dastcore.core.models import Evidence, HttpResponse
from dastcore.validation.baseline import BaselineProfile
from dastcore.validation.reflection import check_reflected_xss

OracleCheckType = Literal[
    "reflected",
    "reflected_xss",
    "response_match",
    "formula_injection",
    "php_filter",
    "differential",
    "time_based",
    "oob",
]
OraclePart = Literal["body", "headers"]

_SPREADSHEET_TYPES = (
    "text/csv",
    "application/csv",
    "text/comma-separated-values",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml",
)
_FORMULA_TRIGGERS = ("=", "+", "-", "@")
# A spreadsheet treats a cell as a formula only when the trigger starts the cell,
# i.e. right after a delimiter/line-start. The standard mitigation neutralizes it
# with a leading apostrophe (or space/tab), which is therefore NOT a cell boundary.
_CELL_BOUNDARY = "[,;\t\r\n]"


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


def check_response_match(
    response: HttpResponse, patterns: list[str], part: OraclePart = "body", payload: str = ""
) -> Evidence | None:
    """Fire when the response carries a server-generated signal (a DB/parse error, a
    disclosure). A match that is merely the *echoed payload* — the app reflecting our
    input, e.g. in a JSON validation error — is skipped: reflection isn't a signal."""
    haystack = response.text if part == "body" else _headers_haystack(response)
    payload_lower = payload.lower()
    for pattern in patterns:
        for match in re.finditer(pattern, haystack, re.IGNORECASE):
            hit = match.group(0)
            # In the body, a match that is only the echoed payload is reflection, not a
            # server signal. In headers it's the opposite: a payload reflected into
            # Location *is* the signal (open redirect), so the guard is body-only.
            if payload and part == "body" and hit.lower() in payload_lower:
                continue
            return Evidence(type="response_match", data=hit[:200], confidence="high")
    return None


def _content_type(response: HttpResponse) -> str:
    for name, value in response.headers.items():
        if name.lower() == "content-type":
            return value.lower()
    return ""


def check_formula_injection(response: HttpResponse, payload: str) -> Evidence | None:
    """Fire when a formula payload is reflected, un-neutralized, at the start of a cell in a
    spreadsheet response (CSV/Excel). Gated on content type so a page that merely echoes
    `=1+1` in HTML isn't flagged, and on the cell boundary so an app that prefixes a `'`
    (the standard mitigation) is correctly treated as safe."""
    if not payload or payload[0] not in _FORMULA_TRIGGERS:
        return None
    if not any(t in _content_type(response) for t in _SPREADSHEET_TYPES):
        return None
    boundary = f"(?:^|{_CELL_BOUNDARY}){re.escape(payload)}"
    if re.search(boundary, response.text):
        return Evidence(
            type="response_match",
            data=f"formula reflected unescaped at a cell boundary in a spreadsheet response: {payload}",
            confidence="high",
        )
    return None


_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_PHP_TAG = re.compile(rb"<\?php|<\?=")


def check_php_filter(response: HttpResponse, payload: str) -> Evidence | None:
    """Fire when a `php://filter` payload made the app return a base64 blob that decodes
    to PHP source — LFI escalated to source-code disclosure. Only runs for that wrapper,
    and only confirms after actually decoding to a `<?php` tag, so it can't false-positive
    on an ordinary long base64 string."""
    if "php://filter" not in payload.lower():
        return None
    for match in _B64_BLOB.finditer(response.text):
        try:
            decoded = base64.b64decode(match.group(0), validate=True)
        except (binascii.Error, ValueError):
            continue
        if _PHP_TAG.search(decoded):
            return Evidence(
                type="response_match",
                data="PHP source disclosed via php://filter wrapper (base64-encoded <?php)",
                confidence="high",
            )
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


def check_time_based(
    mutated: HttpResponse, threshold_ms: float, baseline_ms: float = 0.0, jitter_ms: float = 0.0
) -> Evidence | None:
    """Flags a mutated response slower than baseline by more than the configured
    threshold — *and* by more than the app's natural timing jitter, so network noise
    on a variable target doesn't masquerade as a time-based injection."""
    delta = mutated.elapsed_ms - baseline_ms
    if delta >= threshold_ms and delta >= 3 * jitter_ms:
        note = f" (jitter {jitter_ms:.0f}ms)" if jitter_ms else ""
        return Evidence(
            type="time_based",
            data=f"{delta:.0f}ms slower than baseline (threshold {threshold_ms:.0f}ms){note}",
            confidence="medium",
        )
    return None


def _run_check(
    check: OracleCheck,
    *,
    base_response: HttpResponse,
    mutated_response: HttpResponse,
    payload: str,
    baseline: BaselineProfile | None,
) -> Evidence | None:
    if check.type == "response_match":
        return check_response_match(mutated_response, check.patterns, check.part, payload)
    if check.type == "formula_injection":
        return check_formula_injection(mutated_response, payload)
    if check.type == "php_filter":
        return check_php_filter(mutated_response, payload)
    if check.type == "reflected":
        return check_reflected(mutated_response, payload)
    if check.type == "reflected_xss":
        return check_reflected_xss(mutated_response, payload)
    if check.type == "differential":
        return check_differential(base_response, mutated_response)
    if check.type == "time_based":
        expected = baseline.expected_ms if baseline else base_response.elapsed_ms
        jitter = baseline.jitter_ms if baseline else 0.0
        return check_time_based(mutated_response, check.threshold_ms or 0.0, baseline_ms=expected, jitter_ms=jitter)
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
    baseline: BaselineProfile | None = None,
) -> list[Evidence]:
    """Runs every check in `oracle` and returns the evidence that confirms the rule.

    Every check runs (they all read the same responses, no extra requests), so a
    finding carries *all* the signals that agreed — the raw material for confidence
    scoring. `any_of` fires if at least one matched; `all_of` requires every check to
    match, or returns nothing. When a `baseline` is given, timing checks use its
    median + jitter instead of a single base sample, so they don't fire on noise.
    """
    evidences: list[Evidence] = []
    for check in oracle.checks:
        evidence = _run_check(
            check,
            base_response=base_response,
            mutated_response=mutated_response,
            payload=payload,
            baseline=baseline,
        )
        if evidence is not None:
            evidences.append(evidence)

    if oracle.type == "all_of" and len(evidences) != len(oracle.checks):
        return []
    return evidences
