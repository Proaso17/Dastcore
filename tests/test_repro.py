"""Repro one-liner: a copy-pasteable curl reproducing each finding's request."""

from __future__ import annotations

import json

from dastcore.core.models import HttpRequest


def test_curl_get_with_query_is_shell_safe() -> None:
    curl = HttpRequest(method="GET", url="http://t/search", params={"q": "a'b"}).to_curl()
    assert curl.startswith("curl -i -X GET '")
    assert "http://t/search?q=a%27b" in curl  # value url-encoded, whole url single-quoted


def test_curl_appends_query_with_ampersand_when_url_has_query() -> None:
    curl = HttpRequest(method="GET", url="http://t/x?a=1", params={"b": "2"}).to_curl()
    assert "http://t/x?a=1&b=2" in curl


def test_curl_post_json_sets_content_type_and_data() -> None:
    curl = HttpRequest(method="POST", url="http://t/ai", json_body={"message": "hi"}).to_curl()
    assert "-X POST" in curl
    assert "Content-Type: application/json" in curl
    assert '--data \'{"message": "hi"}\'' in curl


def test_curl_form_body_and_headers_and_cookies() -> None:
    curl = HttpRequest(
        method="POST",
        url="http://t/login",
        data={"user": "bob"},
        headers={"X-Api": "k"},
        cookies={"sid": "123"},
    ).to_curl()
    assert "-H 'X-Api: k'" in curl
    assert "-b 'sid=123'" in curl
    assert "--data 'user=bob'" in curl


def test_finding_exposes_repro_curl_in_json(sample_finding) -> None:
    data = json.loads(sample_finding.model_dump_json())
    assert data["repro_curl"].startswith("curl -i -X")


def test_sarif_and_html_include_repro(sample_finding) -> None:
    from dastcore.report.html import render_html
    from dastcore.report.sarif import build_sarif

    sarif = build_sarif([sample_finding])
    assert sarif["runs"][0]["results"][0]["properties"]["repro"].startswith("curl")

    html = render_html([sample_finding])
    assert "Reproducir (curl)" in html
    assert "curl -i -X" in html
