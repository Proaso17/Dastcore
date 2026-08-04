"""Injection point extraction.

Given a discovered `HttpRequest`, derives the `InjectionPoint`s the rule
engine (Phase 2) will mutate one at a time. Each point keeps the original
request as its `request_template` so a mutated copy can be rebuilt without
disturbing the other parameters.
"""
from __future__ import annotations

from dastcore.core.models import HttpRequest, InjectionPoint


def extract_injection_points(request: HttpRequest) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []

    for name, value in request.params.items():
        points.append(InjectionPoint(location="query", name=name, base_value=value, request_template=request))

    if request.data:
        for name, value in request.data.items():
            points.append(
                InjectionPoint(location="body", name=name, base_value=str(value), request_template=request)
            )

    if isinstance(request.json_body, dict):
        for name, value in request.json_body.items():
            points.append(
                InjectionPoint(location="json", name=name, base_value=str(value), request_template=request)
            )

    return points
