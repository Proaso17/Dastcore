"""Audit-queue prioritisation: the highest-value requests are scanned first so a time/request budget is
spent on the juiciest targets. Higher score = more (rare) attack surface + more inherent interest."""

from __future__ import annotations

from dastcore.core.models import HttpRequest
from dastcore.engine.prioritize import prioritize_requests, score_requests


def test_juicy_requests_sort_before_boilerplate() -> None:
    reqs = [
        HttpRequest(method="GET", url="http://t/style.css"),                                    # no params
        HttpRequest(method="GET", url="http://t/list?page=1", params={"page": "1"}),            # common param
        HttpRequest(method="POST", url="http://t/login", json_body={"user": "a", "password": "b"}),  # juicy
        HttpRequest(method="GET", url="http://t/go?redirect=x&id=5", params={"redirect": "x", "id": "5"}),
    ]
    ordered = [r.url for r in prioritize_requests(reqs)]
    assert ordered[0].endswith("/login")          # state-changing + injectable names first
    assert ordered[-1].endswith("/style.css")     # zero attack surface last
    assert ordered.index("http://t/go?redirect=x&id=5") < ordered.index("http://t/list?page=1")


def test_rare_parameters_outrank_common_ones() -> None:
    # 'page' appears on many requests (boilerplate); 'ssrf_url' is unique (expands attack surface).
    common = [HttpRequest(method="GET", url=f"http://t/p{i}?page=1", params={"page": "1"}) for i in range(5)]
    unique = HttpRequest(method="GET", url="http://t/fetch?ssrf_url=x", params={"ssrf_url": "x"})
    reqs = [*common, unique]
    assert prioritize_requests(reqs)[0] is unique


def test_prioritisation_is_stable_on_ties() -> None:
    # Two identical-shape requests keep their original discovery order.
    a = HttpRequest(method="GET", url="http://t/a?x=1", params={"x": "1"})
    b = HttpRequest(method="GET", url="http://t/b?x=1", params={"x": "1"})
    ordered = prioritize_requests([a, b])
    assert ordered[0] is a and ordered[1] is b


def test_scores_align_with_order() -> None:
    reqs = [
        HttpRequest(method="GET", url="http://t/x"),
        HttpRequest(method="POST", url="http://t/y", data={"cmd": "ls"}),
    ]
    scores = score_requests(reqs)
    assert scores[1] > scores[0]  # the POST with an injectable 'cmd' param scores higher
