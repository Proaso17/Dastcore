from __future__ import annotations

from dastcore.core.models import HttpRequest
from dastcore.engine.injection_points import extract_injection_points


def test_extracts_query_injection_points() -> None:
    request = HttpRequest(method="GET", url="http://x/search", params={"q": "demo"})
    points = extract_injection_points(request)
    assert len(points) == 1
    assert points[0].location == "query"
    assert points[0].name == "q"
    assert points[0].base_value == "demo"
    assert points[0].request_template == request


def test_extracts_body_injection_points() -> None:
    request = HttpRequest(method="POST", url="http://x/login", data={"username": "bob", "password": "bob123"})
    points = extract_injection_points(request)
    assert {p.name for p in points} == {"username", "password"}
    assert all(p.location == "body" for p in points)


def test_extracts_json_injection_points() -> None:
    request = HttpRequest(method="POST", url="http://x/api", json_body={"id": 1, "name": "x"})
    points = extract_injection_points(request)
    assert {p.name for p in points} == {"id", "name"}
    assert all(p.location == "json" for p in points)


def test_no_injection_points_for_bare_request() -> None:
    request = HttpRequest(method="GET", url="http://x/health")
    assert extract_injection_points(request) == []


def test_combines_query_body_and_json_locations() -> None:
    request = HttpRequest(
        method="POST",
        url="http://x/thing",
        params={"a": "1"},
        data={"b": "2"},
        json_body={"c": "3"},
    )
    points = extract_injection_points(request)
    assert {(p.location, p.name) for p in points} == {("query", "a"), ("body", "b"), ("json", "c")}
