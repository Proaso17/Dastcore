"""Audit-queue prioritisation — scan the highest-value requests first, steered by the target profile.

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
- **Family boost (the adaptive planner's steer)**: when recon has decided what the target IS (PHP →
  SQLi/LFI, an API → authz, …), requests whose parameter names hint at one of those *priority families*
  are pulled forward — and the rules for those families are tried first within each request. So the
  brain doesn't just *describe* the strategy, it reorders the attack to match it. With no profile
  (``priority_families`` empty) scoring and rule order are unchanged — same behaviour as before.

Sorting is stable: requests (and rules) with equal scores keep their original discovery order.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import TYPE_CHECKING

from dastcore.core.models import HttpRequest
from dastcore.engine.injection_points import extract_injection_points

if TYPE_CHECKING:
    from dastcore.engine.rule_engine import Rule

_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Parameter names that hint at a dangerous sink (id/authz, file/path, redirect/ssrf, code/template, …).
_INTERESTING_NAME = re.compile(
    r"(?:^|[_\-.])?(id|uid|user|admin|role|acct|account|file|path|dir|page|include|template|tpl|xml|xslt|"
    r"url|uri|link|redirect|next|return|dest|callback|host|cmd|exec|command|run|query|q|search|filter|"
    r"sort|order|token|key|secret|pass|pwd|email|name|data|import|upload|doc)",
    re.IGNORECASE,
)
_SURFACE_WEIGHT = 4.0  # attack-surface vs interest ≈ 80/20

# Per-family parameter-name hints: when the planner marks a family as a priority for THIS target, a
# request with a point whose name matches that family's hint is the likeliest place that bug lives, so
# it audits sooner. Families the planner may emit but that have no distinctive param-name signal
# (rce/deserialization/proto_pollution) simply get no boost — they ride the generic surface/interest score.
_FAMILY_NAME_HINTS: dict[str, re.Pattern[str]] = {
    "sqli": re.compile(r"(?:^|[_\-.])(id|uid|user|name|email|login|search|q|query|filter|sort|order|"
                       r"select|where|col|column|cat|category|prod|product|item)", re.IGNORECASE),
    "lfi": re.compile(r"(?:^|[_\-.])(file|path|dir|folder|page|include|inc|template|tpl|doc|load|read|"
                      r"download|view|show|display|lang|locale|theme)", re.IGNORECASE),
    "open_redirect": re.compile(r"(?:^|[_\-.])(url|uri|redirect|redir|next|return|returnurl|return_url|"
                                r"dest|destination|continue|goto|go|out|link|target|forward|back)", re.IGNORECASE),
    "ssrf": re.compile(r"(?:^|[_\-.])(url|uri|callback|webhook|target|dest|host|port|fetch|proxy|feed|"
                       r"image|img|load|site|link|source|src|remote|endpoint|api)", re.IGNORECASE),
    "cmdi": re.compile(r"(?:^|[_\-.])(cmd|exec|command|run|ping|host|ip|dns|shell|system|process|"
                       r"action|do|func|op|task|job)", re.IGNORECASE),
    "ssti": re.compile(r"(?:^|[_\-.])(template|tpl|name|greeting|message|msg|preview|render|view|"
                       r"content|body|subject|title)", re.IGNORECASE),
    "xxe": re.compile(r"(?:^|[_\-.])(xml|data|import|upload|doc|feed|body|content|payload|file)", re.IGNORECASE),
    "xss": re.compile(r"(?:^|[_\-.])(q|search|name|message|msg|comment|query|keyword|kw|input|text|"
                      r"content|title|subject|note|bio|desc|description)", re.IGNORECASE),
    "nosqli": re.compile(r"(?:^|[_\-.])(id|uid|user|username|login|filter|where|query|q|search|json|_id)",
                         re.IGNORECASE),
    "xpath": re.compile(r"(?:^|[_\-.])(user|username|name|id|query|q|search|xpath|node|element|value|val)",
                        re.IGNORECASE),
    "ldap": re.compile(r"(?:^|[_\-.])(user|username|uid|cn|dn|ou|search|filter|group|login|account)",
                       re.IGNORECASE),
    "crlf": re.compile(r"(?:^|[_\-.])(url|uri|redirect|next|return|lang|locale|header|location|host)",
                       re.IGNORECASE),
}
_FAMILY_BOOST = 3.0  # top-priority family match ≈ a state-changing method; decays for lower-ranked families
_FAMILY_BOOST_DEPTH = 6  # only the top few priority families steer the queue; below that the signal is noise


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


def _family_boost(point_names: list[str], priority_families: tuple[str, ...]) -> float:
    """Pull forward a request whose point names hint at a priority family. The top family weighs most
    (``_FAMILY_BOOST``) and the boost decays with rank, so the scan leans into what the target IS without
    a single match swamping the surface/interest signal."""
    if not priority_families:
        return 0.0
    boost = 0.0
    for rank, family in enumerate(priority_families[:_FAMILY_BOOST_DEPTH]):
        hint = _FAMILY_NAME_HINTS.get(family)
        if hint is not None and any(hint.search(name) for name in point_names):
            boost += _FAMILY_BOOST / (rank + 1)
    return boost


def score_requests(requests: list[HttpRequest], priority_families: tuple[str, ...] = ()) -> list[float]:
    """The priority score of each request (higher = audit sooner). Exposed for testing/inspection.

    ``priority_families`` (from the adaptive planner) biases the score toward requests that expose the
    families the target is most likely vulnerable to; empty → pure surface/interest scoring."""
    per_request_points = [extract_injection_points(r, include_headers=False) for r in requests]
    frequency: Counter[tuple[str, str]] = Counter()
    for points in per_request_points:
        for p in points:
            frequency[(p.location, p.name)] += 1

    scores: list[float] = []
    for request, points in zip(requests, per_request_points, strict=True):
        surface = sum(1.0 / frequency[(p.location, p.name)] for p in points)
        names = [p.name for p in points]
        scores.append(
            _SURFACE_WEIGHT * surface + _interest(request, names) + _family_boost(names, priority_families)
        )
    return scores


def prioritize_requests(
    requests: list[HttpRequest], priority_families: tuple[str, ...] = ()
) -> list[HttpRequest]:
    """Return ``requests`` reordered highest-value first (stable on ties). See module docstring.

    ``priority_families`` steers the order toward the target's likely vuln classes; empty → unchanged."""
    if len(requests) < 2:
        return list(requests)
    scores = score_requests(requests, priority_families)
    order = sorted(range(len(requests)), key=lambda i: (-scores[i], i))  # high score first; ties keep order
    return [requests[i] for i in order]


def prioritize_rules(rules: list[Rule], priority_families: tuple[str, ...]) -> list[Rule]:
    """Order the rule set so the target's priority families are attacked first within each request.

    The active scan loops ``for point in points: for rule in rules``; putting the priority families'
    rules first means that when a ``--time-budget`` runs out mid-request, the classes the target is most
    likely vulnerable to were already probed. Stable: rules in the same family keep their original order,
    and families not in ``priority_families`` follow in their original order. Empty → unchanged."""
    if not priority_families:
        return list(rules)
    rank = {family: i for i, family in enumerate(priority_families)}
    after = len(rank)
    return sorted(rules, key=lambda rule: rank.get(rule.family, after))  # stable: ties keep original order
