from __future__ import annotations

from dastcore.core.models import HttpRequest
from dastcore.engine.injection_points import FUZZABLE_HEADERS, extract_injection_points


def test_extracts_query_injection_points() -> None:
    request = HttpRequest(method="GET", url="http://x/search", params={"q": "demo"})
    points = extract_injection_points(request, include_headers=False)
    assert len(points) == 1
    assert points[0].location == "query"
    assert points[0].name == "q"
    assert points[0].base_value == "demo"
    assert points[0].request_template == request


def test_extracts_body_injection_points() -> None:
    request = HttpRequest(method="POST", url="http://x/login", data={"username": "bob", "password": "bob123"})
    points = extract_injection_points(request, include_headers=False)
    assert {p.name for p in points} == {"username", "password"}
    assert all(p.location == "body" for p in points)


def test_extracts_json_injection_points() -> None:
    request = HttpRequest(method="POST", url="http://x/api", json_body={"id": 1, "name": "x"})
    points = extract_injection_points(request, include_headers=False)
    assert {p.name for p in points} == {"id", "name"}
    assert all(p.location == "json" for p in points)


def test_no_injection_points_for_bare_request() -> None:
    request = HttpRequest(method="GET", url="http://x/health")
    assert extract_injection_points(request, include_headers=False) == []


def test_combines_query_body_and_json_locations() -> None:
    request = HttpRequest(
        method="POST",
        url="http://x/thing",
        params={"a": "1"},
        data={"b": "2"},
        json_body={"c": "3"},
    )
    points = extract_injection_points(request, include_headers=False)
    assert {(p.location, p.name) for p in points} == {("query", "a"), ("body", "b"), ("json", "c")}


def test_header_injection_points_included_by_default() -> None:
    request = HttpRequest(method="GET", url="http://host:8080/x", params={"q": "1"})
    header_points = [p for p in extract_injection_points(request) if p.location == "header"]
    names = {p.name for p in header_points}
    assert set(FUZZABLE_HEADERS) <= names
    assert "Host" in names
    # the Host point is seeded with the request's netloc so a benign replay is possible
    host_point = next(p for p in header_points if p.name == "Host")
    assert host_point.base_value == "host:8080"


# --- deep JSON injection (nested objects + arrays) ---------------------------------------------


def test_extracts_nested_json_leaves() -> None:
    from dastcore.engine.rule_engine import build_mutated_request

    request = HttpRequest(
        method="POST", url="http://x/api",
        json_body={"user": {"id": 5, "profile": {"name": "bob"}}, "items": [{"id": 1}, {"id": 2}], "active": True},
    )
    json_points = {p.name: p for p in extract_injection_points(request, include_headers=False) if p.location == "json"}
    assert set(json_points) == {"user.id", "user.profile.name", "items.0.id", "items.1.id"}  # bool skipped

    mutated = build_mutated_request(json_points["user.profile.name"], "PAYLOAD")
    assert mutated.json_body["user"]["profile"]["name"] == "PAYLOAD"
    assert mutated.json_body["user"]["id"] == 5  # sibling leaves untouched
    assert request.json_body["user"]["profile"]["name"] == "bob"  # original not mutated (deep copy)

    mutated_arr = build_mutated_request(json_points["items.1.id"], "PWN")
    assert mutated_arr.json_body["items"][1]["id"] == "PWN" and mutated_arr.json_body["items"][0]["id"] == 1


# --- path-segment injection (IDOR / SQLi / traversal on identifiers) ---------------------------


def test_extracts_injectable_path_segments_only() -> None:
    request = HttpRequest(method="GET", url="http://x/api/v1/orders/123/items/my-slug")
    path_points = [p for p in extract_injection_points(request, include_headers=False) if p.location == "path"]
    # the numeric id and the trailing slug are candidates; the route words (api/v1/orders/items) are not
    assert {p.base_value for p in path_points} == {"123", "my-slug"}


def test_static_route_only_path_has_no_injection_points() -> None:
    request = HttpRequest(method="GET", url="http://x/api/v1/users")  # all route words, no id/value
    assert [p for p in extract_injection_points(request, include_headers=False) if p.location == "path"] == []


def test_build_mutated_request_replaces_path_segment() -> None:
    from dastcore.engine.rule_engine import build_mutated_request

    request = HttpRequest(method="GET", url="http://x/api/orders/123/status")
    point = next(p for p in extract_injection_points(request, include_headers=False)
                 if p.location == "path" and p.base_value == "123")
    mutated = build_mutated_request(point, "../../etc/passwd")
    assert mutated.url == "http://x/api/orders/../../etc/passwd/status"  # traversal payload keeps its slashes
