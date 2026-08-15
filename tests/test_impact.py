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


# --- LFI / path traversal -------------------------------------------------------------------


def _lfi_app():
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.get("/file")
    def read_file() -> Response:
        name = request.args.get("name", "")
        try:
            with open(name, encoding="utf-8", errors="replace") as fh:  # deliberately vulnerable
                return Response(fh.read(), mimetype="text/plain")
        except OSError:
            return Response("not found", status=404, mimetype="text/plain")

    return app


@pytest.fixture(scope="module")
def lfi_url() -> Iterator[str]:
    url, server = _serve(_lfi_app())
    yield url
    server.shutdown()


def _lfi_finding(base: str, name: str) -> Finding:
    req = HttpRequest(method="GET", url=f"{base}/file", params={"name": name})
    point = InjectionPoint(location="query", name="name", base_value="readme.txt", request_template=req)
    return Finding(
        id="path-traversal-lfi:GET:/file:query:name",
        rule_id="path-traversal-lfi",
        name="Path Traversal / Local File Inclusion",
        severity="high",
        cwe="CWE-22",
        owasp="WSTG-ATHZ-01",
        injection_point=point,
        evidence=[Evidence(type="response_match", data="root:...:0:0:")],
        request=req,
        response=HttpResponse(status_code=200),
        remediation="Resuelve rutas contra un directorio base.",
        family="lfi",
    )


async def test_confirmed_lfi_shows_sensitive_file_snippet(lfi_url: str, tmp_path) -> None:
    secret = tmp_path / "passwd"
    secret.write_text("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
    finding = _lfi_finding(lfi_url, str(secret))
    async with HttpClient(_scope()) as client:
        n = await prove_findings_impact(client, [finding])
    assert n == 1
    assert finding.impact is not None
    assert "path traversal" in finding.impact
    assert "root:x:0:0:" in finding.impact  # the actual file content proves the read


async def test_lfi_on_innocuous_content_is_not_claimed(lfi_url: str, tmp_path) -> None:
    plain = tmp_path / "notes.txt"
    plain.write_text("just some harmless notes, nothing sensitive here\n")
    finding = _lfi_finding(lfi_url, str(plain))
    async with HttpClient(_scope()) as client:
        n = await prove_findings_impact(client, [finding])
    assert n == 0  # no sensitive-file signature → no overclaim
    assert finding.impact is None


# --- SSTI / server-side template injection --------------------------------------------------


def _ssti_app(*, evaluate: bool):
    from flask import Flask, Response, render_template_string, request

    app = Flask(__name__)

    @app.get("/render")
    def render() -> Response:
        name = request.args.get("name", "guest")
        if evaluate:
            return Response(render_template_string("<p>Hello " + name + "</p>"), mimetype="text/html")
        return Response(f"<p>Hello {name}</p>", mimetype="text/html")  # reflect only, no template eval

    return app


@pytest.fixture(scope="module")
def ssti_url() -> Iterator[str]:
    url, server = _serve(_ssti_app(evaluate=True))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def reflect_only_url() -> Iterator[str]:
    url, server = _serve(_ssti_app(evaluate=False))
    yield url
    server.shutdown()


def _ssti_finding(base: str) -> Finding:
    req = HttpRequest(method="GET", url=f"{base}/render", params={"name": "x"})
    point = InjectionPoint(location="query", name="name", base_value="x", request_template=req)
    return Finding(
        id="ssti-inband:GET:/render:query:name",
        rule_id="ssti-inband",
        name="Server-Side Template Injection (in-band)",
        severity="high",
        cwe="CWE-1336",
        owasp="WSTG-INPV-18",
        injection_point=point,
        evidence=[Evidence(type="response_match", data="49")],
        request=req,
        response=HttpResponse(status_code=200),
        remediation="No renderices entrada de usuario como plantilla.",
        family="ssti",
    )


async def test_confirmed_ssti_proves_expression_evaluation(ssti_url: str) -> None:
    finding = _ssti_finding(ssti_url)
    async with HttpClient(_scope()) as client:
        n = await prove_findings_impact(client, [finding])
    assert n == 1
    assert finding.impact is not None
    assert "se evaluó a" in finding.impact
    assert "Jinja2" in finding.impact  # engine fingerprinted via 7*'7'


async def test_ssti_reflect_only_endpoint_is_not_claimed(reflect_only_url: str) -> None:
    finding = _ssti_finding(reflect_only_url)
    async with HttpClient(_scope()) as client:
        n = await prove_findings_impact(client, [finding])
    assert n == 0  # payload reflected but not evaluated → no impact
    assert finding.impact is None
