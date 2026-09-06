"""HTTP response splitting: a param reflected into a response header without stripping CR/LF lets us
inject our own header; a param that is sanitized does not. Uses raw WSGI apps because a vulnerable
server is precisely one that emits the attacker's CR/LF as separate headers."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from urllib.parse import parse_qs

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.response_splitting import run_response_splitting_checks


def _vuln_wsgi(environ, start_response):
    # VULNERABLE: reflect `lang` into a header; CR/LF in the value splits into extra headers.
    lang = parse_qs(environ.get("QUERY_STRING", "")).get("lang", ["en"])[0]
    headers = [("Content-Type", "text/plain")]
    parts = lang.split("\r\n")
    headers.append(("X-Language", parts[0]))
    for line in parts[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers.append((key.strip(), value.strip()))
    start_response("200 OK", headers)
    return [b"language updated"]


def _safe_wsgi(environ, start_response):
    # SAFE: strip CR/LF, so the value stays inside a single header.
    lang = parse_qs(environ.get("QUERY_STRING", "")).get("lang", ["en"])[0]
    clean = lang.replace("\r", "").replace("\n", "")
    start_response("200 OK", [("Content-Type", "text/plain"), ("X-Language", clean)])
    return [b"language updated"]


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def vuln_url() -> Iterator[str]:
    url, server = _serve(_vuln_wsgi)
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def safe_url() -> Iterator[str]:
    url, server = _serve(_safe_wsgi)
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _req(base: str) -> HttpRequest:
    return HttpRequest(method="GET", url=f"{base}/set-lang", params={"lang": "en"})


async def test_crlf_reflected_into_header_is_flagged(vuln_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_response_splitting_checks(client, [_req(vuln_url)])
    assert len(findings) == 1
    assert findings[0].rule_id == "http-response-splitting" and findings[0].cwe == "CWE-113"


async def test_sanitized_header_is_not_flagged(safe_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_response_splitting_checks(client, [_req(safe_url)])
    assert findings == []


async def test_undeliverable_crlf_url_does_not_crash_the_phase(safe_url: str) -> None:
    """A path injection point puts the CR/LF payload directly into request.url, and httpx refuses to
    send a URL with a raw CR/LF — raising httpx.InvalidURL, which is NOT an httpx.HTTPError subclass.
    The check must swallow it and return no findings, never let it abort the whole phase (a bare
    'except httpx.HTTPError' would let it escape and falsely mark the scan coverage as partial)."""
    # A trailing numeric path segment yields a `path` injection point; the mutated value lands in the
    # URL, so the raw CR/LF makes httpx reject it. Must not raise; returns no finding.
    req = HttpRequest(method="GET", url=f"{safe_url}/api/user/1")
    async with HttpClient(_scope()) as client:
        findings = await run_response_splitting_checks(client, [req])
    assert findings == []
