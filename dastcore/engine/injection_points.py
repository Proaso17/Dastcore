"""Injection point extraction.

Given a discovered `HttpRequest`, derives the `InjectionPoint`s the rule
engine (Phase 2) will mutate one at a time. Each point keeps the original
request as its `request_template` so a mutated copy can be rebuilt without
disturbing the other parameters.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from dastcore.core.models import HttpRequest, InjectionPoint

# Request headers worth fuzzing. Server-side logging/routing frameworks trust
# these, which is what enables Log4Shell (User-Agent, Referer) and Host-header
# attacks. Only rules that opt into `inject_into: [header]` ever use these, so
# ordinary in-band rules incur no extra requests.
FUZZABLE_HEADERS = ("User-Agent", "Referer", "X-Forwarded-For")


def extract_injection_points(request: HttpRequest, *, include_headers: bool = True) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []

    for name, value in request.params.items():
        points.append(InjectionPoint(location="query", name=name, base_value=value, request_template=request))

    if request.data:
        for name, value in request.data.items():
            points.append(InjectionPoint(location="body", name=name, base_value=str(value), request_template=request))

    if isinstance(request.json_body, dict):
        for name, value in request.json_body.items():
            points.append(InjectionPoint(location="json", name=name, base_value=str(value), request_template=request))

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
