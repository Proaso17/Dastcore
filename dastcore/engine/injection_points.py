"""Injection point extraction.

Given a discovered `HttpRequest`, derives the `InjectionPoint`s the rule
engine (Phase 2) will mutate one at a time. Each point keeps the original
request as its `request_template` so a mutated copy can be rebuilt without
disturbing the other parameters.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from dastcore.core.models import HttpRequest, InjectionPoint

# Request headers worth fuzzing. Server-side logging/routing frameworks trust
# these, which is what enables Log4Shell (User-Agent, Referer) and Host-header
# attacks. Only rules that opt into `inject_into: [header]` ever use these, so
# ordinary in-band rules incur no extra requests.
FUZZABLE_HEADERS = ("User-Agent", "Referer", "X-Forwarded-For")

# Deep-JSON injection is bounded so a huge/recursive body can't explode the point count.
_MAX_JSON_POINTS = 60
_MAX_JSON_DEPTH = 6

# Path segments that are fixed route words (never injected — that would just spray payloads into the
# route name). Anything that looks like an *identifier/value* IS injected (see _injectable_segment).
_STATIC_SEG = frozenset({
    "api", "v1", "v2", "v3", "graphql", "rest", "admin", "user", "users", "auth", "login", "logout",
    "public", "static", "assets", "app", "web", "index", "home", "account", "settings", "profile",
    "dashboard", "search", "list", "new", "edit", "create", "me",
})
_HEXID = re.compile(r"^[0-9a-fA-F][0-9a-fA-F-]{10,}$")  # uuid / object-id / hash-like


def _walk_json(node: object, prefix: str, out: list[tuple[str, object]], depth: int) -> None:
    """Collect (dotted-path, leaf-value) for every scalar leaf in a JSON body — nested objects and
    array elements included, so ``user.address.city`` and ``items.0.id`` become injection points."""
    if len(out) >= _MAX_JSON_POINTS or depth > _MAX_JSON_DEPTH:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            _walk_json(value, f"{prefix}.{key}" if prefix else str(key), out, depth + 1)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk_json(value, f"{prefix}.{index}" if prefix else str(index), out, depth + 1)
    elif isinstance(node, (str, int, float)) and not isinstance(node, bool) and prefix:
        out.append((prefix, node))


def _injectable_segment(seg: str, *, is_last: bool) -> bool:
    """True if a URL path segment looks like an *identifier/value* (id, uuid, slug-with-digit, or the
    trailing resource) rather than a fixed route word — so we probe IDOR/SQLi/traversal on it, not on
    ``/api/users/`` route names."""
    if not seg or seg.lower() in _STATIC_SEG or "." in seg:  # skip route words and file-like segments
        return False
    if seg.isdigit() or _HEXID.match(seg) or any(c.isdigit() for c in seg):
        return True
    return is_last  # a trailing slug (e.g. /posts/my-title) is a candidate; interior words are not


def _path_points(request: HttpRequest) -> list[InjectionPoint]:
    segs = urlsplit(request.url).path.split("/")
    nonempty = [i for i, s in enumerate(segs) if s]
    last = nonempty[-1] if nonempty else -1
    multi = len(nonempty) >= 2  # only treat the trailing segment as a resource in a /collection/resource path
    points: list[InjectionPoint] = []
    for i, seg in enumerate(segs):
        if seg and _injectable_segment(seg, is_last=i == last and multi):
            points.append(InjectionPoint(location="path", name=str(i), base_value=seg, request_template=request))
    return points


def extract_injection_points(request: HttpRequest, *, include_headers: bool = True) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []

    for name, value in request.params.items():
        points.append(InjectionPoint(location="query", name=name, base_value=value, request_template=request))

    if request.data:
        for name, value in request.data.items():
            points.append(InjectionPoint(location="body", name=name, base_value=str(value), request_template=request))

    # JSON body: every scalar leaf, nested objects and arrays included (not just top-level keys).
    if isinstance(request.json_body, (dict, list)):
        leaves: list[tuple[str, object]] = []
        _walk_json(request.json_body, "", leaves, 0)
        for path, value in leaves:
            points.append(InjectionPoint(location="json", name=path, base_value=str(value), request_template=request))

    # Path segments that look like identifiers/values (IDOR, SQLi, traversal on /api/orders/123).
    points.extend(_path_points(request))

    if include_headers:
        for header in FUZZABLE_HEADERS:
            points.append(InjectionPoint(location="header", name=header, base_value="", request_template=request))
        # Host header injection targets routing/password-reset flows specifically.
        points.append(
            InjectionPoint(
                location="header", name="Host", base_value=urlsplit(request.url).netloc, request_template=request
            )
        )

    return points
