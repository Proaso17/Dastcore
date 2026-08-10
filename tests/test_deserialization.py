"""Serialized-object exposure detector: high-signal magic prefixes only, plain
base64 / JSON must not trip it (the false-positive boundary)."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.deserialization import check_serialized_exposure

_REQ = HttpRequest(method="GET", url="http://t.test/state")


def _resp(text: str) -> HttpResponse:
    return HttpResponse(status_code=200, text=text)


def test_detects_java_serialized_object() -> None:
    findings = check_serialized_exposure(_REQ, _resp('{"state":"rO0ABXNy AAAAAAAAAAAAAAAAAAAAAAAA"}'.replace(" ", "")))
    assert len(findings) == 1
    assert findings[0].rule_id == "serialized-object-exposure"
    assert findings[0].cwe == "CWE-502" and findings[0].family == "deserialization"


def test_detects_php_serialized_object() -> None:
    body = 'session=O:4:"User":2:{s:4:"name";s:3:"bob";}'
    findings = check_serialized_exposure(_REQ, _resp(body))
    assert len(findings) == 1 and "PHP" in findings[0].name


def test_detects_python_pickle_base64() -> None:
    findings = check_serialized_exposure(_REQ, _resp("token=gASVHwAAAAAAAACMCg AAAA".replace(" ", "")))
    assert len(findings) == 1 and "pickle" in findings[0].name.lower()


def test_plain_base64_is_not_flagged() -> None:
    # "Hello world"/ordinary base64 is not a serialization magic prefix
    assert check_serialized_exposure(_REQ, _resp("data=SGVsbG8gd29ybGQhIGRhc3Rjb3Jl")) == []


def test_json_and_html_are_not_flagged() -> None:
    assert check_serialized_exposure(_REQ, _resp('{"user":"bob","role":"admin"}')) == []
    assert check_serialized_exposure(_REQ, _resp("<html><body>O: welcome</body></html>")) == []
