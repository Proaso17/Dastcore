"""Subdomain takeover: a host serving a provider's unclaimed-resource page is flagged; a live
host and a plain 404 are silent (the high-specificity provider fingerprints keep it FP-free)."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.takeover import _cname_service, run_subdomain_takeover_check
from dastcore.discovery.dns_records import RecordSet


def _app(body: str, status: int = 200):
    from flask import Flask, Response

    app = Flask(__name__)

    @app.get("/")
    def root() -> Response:
        return Response(body, status=status, mimetype="text/html")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def dangling() -> Iterator[str]:
    url, server = _serve(_app("<html><body>There isn't a GitHub Pages site here.</body></html>", status=404))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def live() -> Iterator[str]:
    url, server = _serve(_app("<html><body><h1>Welcome to our app</h1></body></html>"))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def plain_404() -> Iterator[str]:
    url, server = _serve(_app("<html><body>404 Not Found — page missing</body></html>", status=404))
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


async def test_unclaimed_service_page_is_flagged(dangling: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_subdomain_takeover_check(client, dangling, [])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "subdomain-takeover" and "GitHub Pages" in f.name
    assert f.cwe == "CWE-284" and f.owasp == "WSTG-CONF-10"


async def test_live_host_is_not_flagged(live: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await run_subdomain_takeover_check(client, live, []) == []


async def test_plain_404_is_not_flagged(plain_404: str) -> None:
    async with HttpClient(_scope()) as client:
        assert await run_subdomain_takeover_check(client, plain_404, []) == []


async def test_hosts_are_deduped_from_target_and_requests(dangling: str) -> None:
    # the same host referenced by target and several requests is fingerprinted once
    requests = [HttpRequest(method="GET", url=f"{dangling}/a"), HttpRequest(method="GET", url=f"{dangling}/b")]
    async with HttpClient(_scope()) as client:
        findings = await run_subdomain_takeover_check(client, dangling, requests)
    assert len(findings) == 1


def test_cname_service_matches_takeoverable_providers() -> None:
    assert _cname_service("acme.github.io") == "GitHub Pages"
    assert _cname_service("bucket.s3.amazonaws.com.") == "AWS S3"
    assert _cname_service("app.herokuapp.com") == "Heroku"
    assert _cname_service("www.example.com") is None  # a normal CNAME is not a takeover target


async def test_dangling_cname_is_flagged_without_a_body_match() -> None:
    # A CNAME to a takeover-able provider with no resolving address is a takeover on DNS alone —
    # no HTTP fingerprint needed. Uses an unroutable host so the root fetch simply returns nothing.
    records = {"gone.acme.com": RecordSet(host="gone.acme.com", cname=["gone.github.io"])}
    async with HttpClient(ScopeConfig(allow_domains=["acme.com"])) as client:
        findings = await run_subdomain_takeover_check(client, "https://acme.com", [], dns_records=records)
    assert len(findings) == 1
    f = findings[0]
    assert "GitHub Pages" in f.name and "dangling CNAME" in f.evidence[0].data and "gone.github.io" in f.evidence[0].data


async def test_cname_that_still_resolves_is_not_flagged() -> None:
    # Same provider CNAME, but it resolves (has an A record) -> a live site, not a takeover.
    records = {"live.acme.com": RecordSet(host="live.acme.com", cname=["live.github.io"], a=["185.199.108.153"])}
    async with HttpClient(ScopeConfig(allow_domains=["acme.com"])) as client:
        assert await run_subdomain_takeover_check(client, "https://acme.com", [], dns_records=records) == []


async def test_body_match_evidence_is_enriched_with_cname(dangling: str) -> None:
    # The dangling fixture serves on 127.0.0.1 and matches the GitHub Pages body fingerprint; supplying
    # its CNAME record enriches the evidence with the dangling target.
    records = {"127.0.0.1": RecordSet(host="127.0.0.1", cname=["victim.github.io"], a=["127.0.0.1"])}
    async with HttpClient(_scope()) as client:
        findings = await run_subdomain_takeover_check(client, dangling, [], dns_records=records)
    assert len(findings) == 1
    assert "victim.github.io" in findings[0].evidence[0].data
