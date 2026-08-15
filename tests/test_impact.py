"""Proof-of-impact: a confirmed SQLi finding gets enriched with the real DB version banner,
extracted in-band and read-only. A reflecting-but-safe endpoint yields no extraction (our own
payload echoed back is rejected), and the value stays bounded."""

from __future__ import annotations

import re
import socket
import sqlite3
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.analysis import prove_findings_impact
from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint


def _vuln_app():
    from flask import Flask, Response, request

    app = Flask(__name__)
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    db.execute("INSERT INTO products VALUES (1, 'Teclado', 49.99)")

    @app.get("/search")
    def search() -> Response:
        q = request.args.get("q", "")
        sql = f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"  # deliberately vulnerable
        try:
            rows = db.execute(sql).fetchall()
        except sqlite3.OperationalError as exc:
            return Response(f"<h1>Database error</h1><pre>{exc}</pre>", status=500, mimetype="text/html")
        items = "".join(f"<li>{name} - ${price}</li>" for _i, name, price in rows)
        return Response(f"<h1>Results</h1><ul>{items}</ul>", mimetype="text/html")

    return app


def _echo_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/search")
    def search() -> Response:
        # Reflects the raw input but never touches a database — extraction must NOT succeed.
        return Response(f"<p>Buscaste: {request.args.get('q', '')}</p>", mimetype="text/html")

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def vuln_url() -> Iterator[str]:
    url, server = _serve(_vuln_app())
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def echo_url() -> Iterator[str]:
    url, server = _serve(_echo_app())
    yield url
    server.shutdown()


def _sqli_finding(base: str) -> Finding:
    req = HttpRequest(method="GET", url=f"{base}/search", params={"q": "abc"})
    point = InjectionPoint(location="query", name="q", base_value="abc", request_template=req)
    return Finding(
        id="sqli-injection:GET:/search:query:q",
        rule_id="sqli-injection",
        name="SQL Injection",
        severity="high",
        cwe="CWE-89",
        owasp="WSTG-INPV-05",
        injection_point=point,
        evidence=[Evidence(type="response_match", data="SQL error surfaced")],
        request=req,
        response=HttpResponse(status_code=500),
        remediation="Usa consultas parametrizadas.",
        family="sqli",
    )


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


async def test_confirmed_sqli_gets_db_version_extracted(vuln_url: str) -> None:
    finding = _sqli_finding(vuln_url)
    async with HttpClient(_scope()) as client:
        n = await prove_findings_impact(client, [finding])
    assert n == 1
    assert finding.impact is not None
    assert "SQLite" in finding.impact
    assert re.search(r"\d+\.\d+", finding.impact)  # a real version number was read back
    assert "UNION-based" in finding.impact
    assert len(finding.impact) < 400  # bounded, not a data dump


async def test_reflecting_endpoint_yields_no_false_extraction(echo_url: str) -> None:
    finding = _sqli_finding(echo_url)
    async with HttpClient(_scope()) as client:
        n = await prove_findings_impact(client, [finding])
    assert n == 0
    assert finding.impact is None  # our own payload echoed back must be rejected


async def test_non_sqli_family_is_left_untouched(vuln_url: str) -> None:
    finding = _sqli_finding(vuln_url)
    finding.family = "xss"  # not a supported impact family
    async with HttpClient(_scope()) as client:
        n = await prove_findings_impact(client, [finding])
    assert n == 0
    assert finding.impact is None
