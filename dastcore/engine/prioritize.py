"""Audit-queue prioritisation — scan the highest-value requests first.

Burp Scanner orders its audit queue so the requests most likely to expose vulnerabilities are tested
first, weighting *attack-surface exposure* against *interest* roughly 80/20. We do the same: under a
``--time-budget`` or ``--max-requests`` cap, whatever budget is left is spent on the juiciest targets
instead of whatever the crawler happened to enqueue first. The active scan gathers requests in list
order (the semaphore admits them in that order), so sorting the list *is* the priority queue.

- **Attack surface (weighted ~80%)**: how much of the app a request exposes. Counted as the sum over its
  injection points of ``1/frequency`` — a parameter seen on many requests is low-signal boilerplate,
  while a parameter unique to this request expands coverage and scores high (Burp's "unique insertion
  points" idea).
- **Interest (weighted ~20%)**: inherent riskiness — state-changing methods (POST/PUT/PATCH/DELETE),
  structured bodies (JSON/XML), and parameters whose names hint at an injectable sink.

Sorting is stable: requests with equal scores keep their original discovery order.
"""

from __future__ import annotations

import re
from collections import Counter

from dastcore.core.models import HttpRequest
from dastcore.engine.injection_points import extract_injection_points

_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Parameter names that hint at a dangerous sink (id/authz, file/path, redirect/ssrf, code/template, …).
_INTERESTING_NAME = re.compile(
    r"(?:^|[_\-.])?(id|uid|user|admin|role|acct|account|file|path|dir|page|include|template|tpl|xml|xslt|"
    r"url|uri|link|redirect|next|return|dest|callback|host|cmd|exec|command|run|query|q|search|filter|"
    r"sort|order|token|key|secret|pass|pwd|email|name|data|import|upload|doc)",
    re.IGNORECASE,
)
_SURFACE_WEIGHT = 4.0  # attack-surface vs interest ≈ 80/20


def _interest(request: HttpRequest, point_names: list[str]) -> float:
    score = 0.0
    if request.method in _STATE_CHANGING:
        score += 3.0
    if request.json_body is not None:
        score += 2.0
    elif request.data:
        score += 1.0
    score += sum(1.0 for name in point_names if _INTERESTING_NAME.search(name))
    return score


def score_requests(requests: list[HttpRequest]) -> list[float]:
    """The priority score of each request (higher = audit sooner). Exposed for testing/inspection."""
    per_request_points = [extract_injection_points(r, include_headers=False) for r in requests]
    frequency: Counter[tuple[str, str]] = Counter()
    for points in per_request_points:
        for p in points:
            frequency[(p.location, p.name)] += 1

    scores: list[float] = []
    for request, points in zip(requests, per_request_points, strict=True):
        surface = sum(1.0 / frequency[(p.location, p.name)] for p in points)
        scores.append(_SURFACE_WEIGHT * surface + _interest(request, [p.name for p in points]))
    return scores


def prioritize_requests(requests: list[HttpRequest]) -> list[HttpRequest]:
    """Return ``requests`` reordered highest-value first (stable on ties). See module docstring."""
    if len(requests) < 2:
        return list(requests)
    scores = score_requests(requests)
    order = sorted(range(len(requests)), key=lambda i: (-scores[i], i))  # high score first; ties keep order
    return [requests[i] for i in order]
