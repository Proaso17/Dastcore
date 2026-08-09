"""Reflection-context analysis: executable vs inert reflected XSS."""

from __future__ import annotations

from dastcore.core.models import HttpResponse
from dastcore.validation.reflection import analyze_reflection, check_reflected_xss

SCRIPT = "<script>alert(1)</script>"
ATTR_BREAK = '"><svg onload=alert(1)>'
JS_STRING = "'-alert(1)-'"
JS_URL = "javascript:alert(1)"


def _resp(text: str) -> HttpResponse:
    return HttpResponse(status_code=200, text=text, url="http://x/")


# --- executable reflections (should fire) ------------------------------------------------


def test_raw_script_in_html_text_is_executable() -> None:
    info = analyze_reflection(f"<h1>Hola {SCRIPT}</h1>", SCRIPT)
    assert info.reflected and info.executable and info.context == "text"


def test_attribute_breakout_is_executable() -> None:
    # payload closes the quoted attribute and opens a new tag
    body = f'<input value="{ATTR_BREAK}">'
    info = analyze_reflection(body, ATTR_BREAK)
    assert info.context == "attribute" and info.executable


def test_js_string_breakout_in_script_is_executable() -> None:
    body = f"<script>var msg = '{JS_STRING}';</script>"
    info = analyze_reflection(body, JS_STRING)
    assert info.context == "script" and info.executable


def test_javascript_url_in_href_is_executable() -> None:
    body = f'<a href="{JS_URL}">x</a>'
    info = analyze_reflection(body, JS_URL)
    assert info.context == "attribute" and info.executable


# --- inert reflections (should NOT fire) — the false-positive killers --------------------


def test_escaped_reflection_is_not_reflected() -> None:
    body = "<h1>Hola &lt;script&gt;alert(1)&lt;/script&gt;</h1>"
    info = analyze_reflection(body, SCRIPT)
    assert info.reflected is False and info.escaped is True
    assert check_reflected_xss(_resp(body), SCRIPT) is None


def test_reflection_inside_textarea_needs_matching_close() -> None:
    # Inside <textarea>, a <script> is literal text — only </textarea> breaks out.
    inert = analyze_reflection(f"<textarea>{SCRIPT}</textarea>", SCRIPT)
    assert inert.context == "rawtext" and inert.executable is False
    breakout = "</textarea><script>alert(1)</script>"
    live = analyze_reflection(f"<textarea>{breakout}</textarea>", breakout)
    assert live.context == "rawtext" and live.executable is True


def test_reflection_inside_html_comment_is_inert() -> None:
    body = f"<!-- debug: {SCRIPT} -->"
    info = analyze_reflection(body, SCRIPT)
    assert info.context == "comment" and info.executable is False
    assert check_reflected_xss(_resp(body), SCRIPT) is None


def test_js_url_as_plain_text_is_inert() -> None:
    # javascript:alert(1) echoed into HTML text can't execute
    body = f"<p>Tu búsqueda: {JS_URL}</p>"
    info = analyze_reflection(body, JS_URL)
    assert info.context == "text" and info.executable is False


def test_quoted_attribute_without_breakout_is_inert() -> None:
    # payload reflected in a quoted attribute but contains no matching quote to escape it
    body = '<input value="hello-world-token">'
    info = analyze_reflection(body, "hello-world-token")
    assert info.context == "attribute" and info.executable is False


# --- the oracle ---------------------------------------------------------------------------


def test_oracle_fires_on_executable_and_not_on_inert() -> None:
    assert check_reflected_xss(_resp(f"<h1>{SCRIPT}</h1>"), SCRIPT) is not None
    assert check_reflected_xss(_resp(f"<!-- {SCRIPT} -->"), SCRIPT) is None
    assert check_reflected_xss(_resp("nothing here"), SCRIPT) is None


def test_oracle_ignores_reflection_in_non_html_response() -> None:
    # A script echoed in a JSON body (e.g. an API validation error) can't execute -> not XSS.
    json_resp = HttpResponse(
        status_code=422, headers={"Content-Type": "application/json"}, text=f'{{"input":"{SCRIPT}"}}', url="http://x/"
    )
    assert check_reflected_xss(json_resp, SCRIPT) is None
    # The same body served as text/html would be executable.
    html_resp = HttpResponse(
        status_code=200, headers={"Content-Type": "text/html"}, text=f"<div>{SCRIPT}</div>", url="http://x/"
    )
    assert check_reflected_xss(html_resp, SCRIPT) is not None
