"""is_https: decides Secure-cookie and HSTS, so its edge cases matter."""

from __future__ import annotations

from types import SimpleNamespace

from dastcore.httpsec import is_https


def _request(scheme: str, forwarded_proto: str | None = None):
    headers = {"x-forwarded-proto": forwarded_proto} if forwarded_proto is not None else {}
    return SimpleNamespace(url=SimpleNamespace(scheme=scheme), headers=headers)


def test_direct_https() -> None:
    assert is_https(_request("https")) is True


def test_plain_http() -> None:
    assert is_https(_request("http")) is False


def test_behind_tls_proxy_via_forwarded_proto() -> None:
    assert is_https(_request("http", "https")) is True
    # a proxy chain lists the closest proto first
    assert is_https(_request("http", "https, http")) is True


def test_forwarded_proto_http_is_not_https() -> None:
    assert is_https(_request("http", "http")) is False
    assert is_https(_request("http", "")) is False
