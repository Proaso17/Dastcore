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


def test_thorough_off_by_default_no_extra_points() -> None:
    # A base64-looking query param on a POST: plain extraction must NOT add moved/nested points.
    req = HttpRequest(method="POST", url="http://x/a?t=dXNlcmlkLTQy", params={"t": "dXNlcmlkLTQy"})
    plain = extract_injection_points(req, include_headers=False)
    assert all(p.place_in is None and p.wrap == () for p in plain)


def test_thorough_adds_nested_base64_point() -> None:
    import base64

    from dastcore.engine.rule_engine import build_mutated_request

    tok = base64.b64encode(b"userid-42").decode()
    req = HttpRequest(method="GET", url=f"http://x/a?t={tok}", params={"t": tok})
    points = extract_injection_points(req, include_headers=False, thorough=True)
    nested = [p for p in points if p.wrap == ("b64",)]
    assert len(nested) == 1
    assert nested[0].location == "query" and nested[0].name == "t" and nested[0].base_value == "userid-42"
    # Mutating re-encodes: the payload lands base64'd inside the param (fuzzing inside the decoding).
    mutated = build_mutated_request(nested[0], "' OR 1=1-- -")
    assert base64.b64decode(mutated.params["t"]).decode() == "' OR 1=1-- -"


def test_thorough_adds_moved_points_cross_location() -> None:
    from dastcore.engine.rule_engine import build_mutated_request

    req = HttpRequest(method="POST", url="http://x/a?q=hi", params={"q": "hi"}, data={"name": "bob"})
    points = extract_injection_points(req, include_headers=False, thorough=True)
    moved = {(p.name, p.place_in) for p in points if p.place_in is not None}
    assert ("q", "body") in moved   # a query param also tried in the body (body-bearing method)
    assert ("name", "query") in moved  # a body param also tried in the query
    # A moved query->body point places the payload in the body while leaving the original query param.
    qmoved = next(p for p in points if p.name == "q" and p.place_in == "body")
    mutated = build_mutated_request(qmoved, "XSS")
    assert (mutated.data or {}).get("q") == "XSS" and mutated.params.get("q") == "hi"


def test_get_query_param_not_moved_to_body() -> None:
    # Moving a query param into the body only makes sense on body-bearing methods.
    req = HttpRequest(method="GET", url="http://x/a?q=hi", params={"q": "hi"})
    points = extract_injection_points(req, include_headers=False, thorough=True)
    assert not any(p.place_in == "body" for p in points)
