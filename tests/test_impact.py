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


# --- OS command injection -------------------------------------------------------------------

import re as _re  # noqa: E402


def _cmdi_app(*, execute: bool):
    from flask import Flask, Response, request

    app = Flask(__name__)

    def _fake_shell(host: str) -> str:
        # Faithful mini-simulation of `sh -c "ping " + host`: command substitution then echo.
        s = host.replace("$(id)", "uid=0(root) gid=0(root) groups=0(root)")
        s = s.replace("$(uname -a)", "Linux testhost 6.1.0 x86_64 GNU/Linux")
        m = _re.search(r"echo (\S.*)", s)
        return m.group(1) if m else "PING localhost: 56 data bytes"

    @app.get("/ping")
    def ping() -> Response:
        host = request.args.get("host", "localhost")
        if execute:
            return Response(_fake_shell(host), mimetype="text/plain")
        return Response(f"PING {host}: 56 data bytes", mimetype="text/plain")  # reflect only, no shell

    return app


@pytest.fixture(scope="module")
def cmdi_url() -> Iterator[str]:
    url, server = _serve(_cmdi_app(execute=True))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def cmdi_reflect_url() -> Iterator[str]:
    url, server = _serve(_cmdi_app(execute=False))
    yield url
    server.shutdown()


def _cmdi_finding(base: str) -> Finding:
    req = HttpRequest(method="GET", url=f"{base}/ping", params={"host": "localhost"})
    point = InjectionPoint(location="query", name="host", base_value="localhost", request_template=req)
    return Finding(
        id="cmdi-inband:GET:/ping:query:host",
        rule_id="cmdi-inband",
        name="OS Command Injection (in-band)",
        severity="critical",
        cwe="CWE-78",
        owasp="WSTG-INPV-12",
        injection_point=point,
        evidence=[Evidence(type="response_match", data="uid=")],
        request=req,
        response=HttpResponse(status_code=200),
        remediation="No pases entrada de usuario a una shell.",
        family="cmdi",
    )


async def test_confirmed_cmdi_shows_command_output(cmdi_url: str) -> None:
    finding = _cmdi_finding(cmdi_url)
    async with HttpClient(_scope()) as client:
        n = await prove_findings_impact(client, [finding])
    assert n == 1
    assert finding.impact is not None
    assert "uid=0(root)" in finding.impact  # the real command output was read back
    assert "`id`" in finding.impact


async def test_cmdi_reflect_only_endpoint_is_not_claimed(cmdi_reflect_url: str) -> None:
    finding = _cmdi_finding(cmdi_reflect_url)
    async with HttpClient(_scope()) as client:
        n = await prove_findings_impact(client, [finding])
    assert n == 0  # the payload is echoed but never executed → no impact
    assert finding.impact is None


# --- Code injection (direct eval sink) → proof of RCE ----------------------------------------


def _code_eval_app():
    """A sink that eval()s the value as PHP `echo <code>;` — resolve the proof payloads' function calls
    to canned, realistic output (so the test never runs real commands) while echoing anything else."""
    from flask import Flask, Response, request

    def _fn_output(name: str, arg: str) -> str:
        if name in ("system", "exec", "shell_exec", "passthru"):
            return {"id": "uid=0(root) gid=0(root) groups=0(root)",
                    "uname -a": "Linux testhost 6.1.0 x86_64 GNU/Linux"}.get(arg, "")
        if name == "php_uname":
            return "Linux testhost 6.1.0 x86_64"
        return ""

    def _php_echo_eval(code: str) -> str:
        m = re.fullmatch(r"'([^']*)'\.(\w+)\('([^']*)'\)\.'([^']*)'", code)  # 'L'.fn('arg').'R'
        if m:
            return m.group(1) + _fn_output(m.group(2), m.group(3)) + m.group(4)
        m = re.fullmatch(r"'([^']*)'\.(\w+)\(\)\.'([^']*)'", code)  # 'L'.builtin().'R'
        if m:
            return m.group(1) + _fn_output(m.group(2), "") + m.group(3)
        m = re.fullmatch(r"(\d+)\*(\d+)", code)  # arithmetic (the detection payload)
        if m:
            return str(int(m.group(1)) * int(m.group(2)))
        return code  # anything else: reflect verbatim

    app = Flask(__name__)

    @app.get("/eval")
    def ev() -> Response:
        return Response(f"<p><i>{_php_echo_eval(request.args.get('code', ''))}</i></p>", mimetype="text/html")

    return app


@pytest.fixture(scope="module")
def code_eval_url() -> Iterator[str]:
    url, server = _serve(_code_eval_app())
    yield url
    server.shutdown()


def _code_injection_finding(base: str) -> Finding:
    req = HttpRequest(method="GET", url=f"{base}/eval", params={"code": "1"})
    point = InjectionPoint(location="query", name="code", base_value="1", request_template=req)
    return Finding(
        id="code-injection:GET:/eval:query:code",
        rule_id="code-injection",
        name="Server-side code injection (eval directo)",
        severity="critical",
        cwe="CWE-94",
        owasp="A03:2021",
        injection_point=point,
        evidence=[Evidence(type="reflected", data="arithmetic evaluated")],
        request=req,
        response=HttpResponse(status_code=200),
        remediation="No evalúes entrada como código.",
        family="code-injection",
    )


async def test_confirmed_code_injection_is_escalated_to_rce(code_eval_url: str) -> None:
    finding = _code_injection_finding(code_eval_url)
    async with HttpClient(_scope()) as client:
        n = await prove_findings_impact(client, [finding])
    assert n == 1
    assert finding.impact is not None
    assert "uid=0(root)" in finding.impact  # real command output read back, not the reflected payload
    assert "RCE" in finding.impact
    assert len(finding.impact) < 400


async def test_code_injection_on_reflecting_endpoint_is_not_overclaimed(echo_url: str) -> None:
    # /search echoes the raw payload but never executes it → no command output → no impact claimed.
    finding = _code_injection_finding(echo_url)
    finding.injection_point.request_template = HttpRequest(
        method="GET", url=f"{echo_url}/search", params={"q": "1"}
    )
    finding.injection_point.name = "q"
    finding.request = finding.injection_point.request_template
    async with HttpClient(_scope()) as client:
        n = await prove_findings_impact(client, [finding])
    assert n == 0 and finding.impact is None


# --- XPath injection → proof of record disclosure --------------------------------------------


def _xpath_app():
    """Simulates an injectable XPath filter [login='$lg' and password='$pw']: an always-true OR term
    discloses a hidden record, an always-false AND matches nothing, a normal value matches only a hero."""
    from flask import Flask, Response, request

    SECRET = "MATRIX-SEEKRIT-42"
    app = Flask(__name__)

    @app.get("/login")
    def login() -> Response:
        lg = request.args.get("login", "")
        if re.search(r"or\s+'?1'?\s*=\s*'?1", lg) or re.search(r"\bor\s+1=1", lg):
            body = f"<p>Welcome <b>Neo</b>, how are you?</p><p>Your secret: <b>{SECRET}</b></p>"
        elif lg == "neo":
            body = "<p>Welcome <b>Neo</b>, how are you?</p><p>Your secret: <b>own</b></p>"
        else:
            body = "<p>No hero found</p>"
        return Response(f"<html><body><nav>Menu Home About Contact</nav>{body}</body></html>", mimetype="text/html")

    return app


@pytest.fixture(scope="module")
def xpath_url() -> Iterator[str]:
    url, server = _serve(_xpath_app())
    yield url
    server.shutdown()


def _xpath_finding(base: str, path: str = "/login", name: str = "login") -> Finding:
    req = HttpRequest(method="GET", url=f"{base}{path}", params={name: "neo", "password": "x"})
    point = InjectionPoint(location="query", name=name, base_value="neo", request_template=req)
    return Finding(
        id=f"xpath-injection:GET:{path}:query:{name}",
        rule_id="xpath-injection",
        name="XPath Injection",
        severity="high",
        cwe="CWE-643",
        owasp="WSTG-INPV-09",
        injection_point=point,
        evidence=[Evidence(type="response_match", data="XPath error surfaced")],
        request=req,
        response=HttpResponse(status_code=200),
        remediation="Usa XPath parametrizado.",
        family="xpath",
    )


async def test_confirmed_xpath_discloses_hidden_record(xpath_url: str) -> None:
    finding = _xpath_finding(xpath_url)
    async with HttpClient(_scope()) as client:
        n = await prove_findings_impact(client, [finding])
    assert n == 1
    assert finding.impact is not None
    assert "MATRIX-SEEKRIT-42" in finding.impact  # the hidden record leaked by the always-true predicate
    assert "Menu Home About Contact" not in finding.impact  # shared chrome cancels out, not reported as leak
    assert len(finding.impact) < 400


async def test_xpath_on_reflecting_endpoint_is_not_overclaimed(echo_url: str) -> None:
    # /search returns the same regardless of the predicate → no differential → nothing "disclosed".
    finding = _xpath_finding(echo_url, path="/search", name="q")
    async with HttpClient(_scope()) as client:
        n = await prove_findings_impact(client, [finding])
    assert n == 0 and finding.impact is None
