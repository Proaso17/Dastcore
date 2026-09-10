"""Auto-pivot to authenticated scanning: when the planner finds default credentials that work, dastcore
logs in with them and scans the surface they unlock — the real blast radius. These tests use a tiny app
with an injectable endpoint reachable ONLY behind the login, and assert the pivot reaches and flags it."""

from __future__ import annotations

import secrets
import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.cli import _Budget, _scan_authenticated_surface, _weak_credentials_and_pivot
from dastcore.config import AuthConfig, FormLoginConfig, ScanConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.detectors.weak_credentials import find_weak_credentials
from dastcore.discovery.crawler_http import HttpCrawler
from dastcore.engine.rule_engine import load_rules


def _app():
    from flask import Flask, Response, redirect, request

    app = Flask(__name__)

    @app.get("/")
    def home() -> str:
        return '<html><body><a href="/dashboard">panel</a></body></html>'

    @app.post("/login")
    def login():
        if request.form.get("username") == "admin" and request.form.get("password") == "admin":
            resp = redirect("/dashboard", code=302)
            resp.set_cookie("sessionid", secrets.token_hex(8))
            return resp
        return Response("invalid credentials", status=200, mimetype="text/html")

    @app.get("/dashboard")
    def dashboard() -> Response:
        if request.cookies.get("sessionid"):  # authenticated: reveal the internal link
            return Response('<a href="/admin/search?q=demo">search</a>', mimetype="text/html")
        return Response("<p>please log in</p>", mimetype="text/html")  # login wall: anon dead-ends here

    @app.get("/admin/search")
    def admin_search() -> Response:
        if not request.cookies.get("sessionid"):
            return Response("unauthorized", status=401)
        q = request.args.get("q", "")
        if "'" in q:  # injectable: a quote breaks the (pretend) SQL query
            return Response("You have an error in your SQL syntax near ''' at line 1", status=500,
                            mimetype="text/html")
        return Response(f"results for {q}", mimetype="text/html")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def pivot_url() -> Iterator[str]:
    url, server = _serve(_app())
    yield url
    server.shutdown()  # type: ignore[attr-defined]


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _form(base: str, creds: dict[str, str] | None = None) -> FormLoginConfig:
    return FormLoginConfig(
        login_url=f"{base}/login",
        credentials=creds if creds is not None else {"username": "x", "password": "y"},
        as_json=False,
    )


def _config(base: str, creds: dict[str, str] | None = None) -> ScanConfig:
    return ScanConfig(
        target=f"{base}/", scope=_scope(),
        auth=AuthConfig(type="form", form=_form(base, creds)), i_have_authorization=True,
    )


async def _anon_known(base: str) -> set[str]:
    """What the unauthenticated discovery sees — the baseline the pivot diffs against."""
    async with HttpClient(_scope()) as anon:
        return {r.signature() for r in await HttpCrawler(anon).crawl(f"{base}/")}


async def test_find_weak_credentials_returns_structured_pair(pivot_url: str) -> None:
    async with HttpClient(_scope()) as client:
        weak = await find_weak_credentials(client, _form(pivot_url))
    assert weak is not None
    assert (weak.user_field, weak.username, weak.pass_field, weak.password) == ("username", "admin", "password", "admin")
    assert weak.finding.rule_id == "default-credentials"


async def test_pivot_scans_authenticated_only_surface(pivot_url: str) -> None:
    known = await _anon_known(pivot_url)
    assert not any("/admin/search" in sig for sig in known)  # anon can't reach it (login wall)

    async with HttpClient(_scope()) as client:
        weak = await find_weak_credentials(client, _form(pivot_url))
    assert weak is not None

    findings = await _scan_authenticated_surface(
        _config(pivot_url), _Budget(None, None), weak,
        scan_roots=[f"{pivot_url}/"], known_signatures=known, rules=load_rules(),
        oast=None, priority_families=("sqli",), max_pages=50, concurrency=4,
    )
    # The pivot logged in, crawled past the login wall, and flagged the SQLi only reachable authenticated.
    assert any(f.family == "sqli" and "/admin/search" in f.request.url for f in findings)
    assert any(f.rule_id == "scan-auth-pivot" for f in findings)  # the advisory documents the pivot


async def test_weak_credentials_and_pivot_end_to_end(pivot_url: str) -> None:
    known = await _anon_known(pivot_url)
    findings = await _weak_credentials_and_pivot(
        _config(pivot_url), _Budget(None, None),
        scan_roots=[f"{pivot_url}/"], known_signatures=known, rules=load_rules(),
        oast=None, priority_families=("sqli",), max_pages=50, concurrency=4, pivot=True,
    )
    rule_ids = {f.rule_id for f in findings}
    assert "default-credentials" in rule_ids       # the weak-cred finding itself
    assert "scan-auth-pivot" in rule_ids           # and the pivot advisory
    assert any(f.family == "sqli" for f in findings)  # plus the authenticated-only injection


async def test_pivot_skipped_when_flag_off(pivot_url: str) -> None:
    known = await _anon_known(pivot_url)
    findings = await _weak_credentials_and_pivot(
        _config(pivot_url), _Budget(None, None),
        scan_roots=[f"{pivot_url}/"], known_signatures=known, rules=load_rules(),
        oast=None, priority_families=("sqli",), max_pages=50, concurrency=4, pivot=False,
    )
    assert {f.rule_id for f in findings} == {"default-credentials"}  # only the finding, no pivot


async def test_pivot_skipped_when_creds_already_used(pivot_url: str) -> None:
    # The main scan already authenticated as admin/admin -> the "discovered" defaults are the same account,
    # so there is no new surface to pivot into and the pivot is skipped (no wasted re-scan).
    known = await _anon_known(pivot_url)
    findings = await _weak_credentials_and_pivot(
        _config(pivot_url, creds={"username": "admin", "password": "admin"}), _Budget(None, None),
        scan_roots=[f"{pivot_url}/"], known_signatures=known, rules=load_rules(),
        oast=None, priority_families=("sqli",), max_pages=50, concurrency=4, pivot=True,
    )
    assert "scan-auth-pivot" not in {f.rule_id for f in findings}
