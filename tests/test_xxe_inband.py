"""In-band XXE: a parser that resolves an external SYSTEM entity and reflects it leaks server files. A
vulnerable endpoint (lxml with entity resolution on) is flagged when /etc/passwd comes back; a hardened
one (entities disabled) is not. A resolver serves fake passwd content, so the test never reads a real
file and runs the same on any OS."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.detectors.xxe_inband import run_xxe_inband_checks

_FAKE_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _parse(body: str, *, vulnerable: bool) -> str:
    from lxml import etree

    if vulnerable:
        class _Passwd(etree.Resolver):  # type: ignore[misc]
            def resolve(self, url, pubid, context):  # noqa: A002 - lxml signature
                return self.resolve_string(_FAKE_PASSWD, context)

        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True)
        parser.resolvers.add(_Passwd())
    else:
        parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
    try:
        root = etree.fromstring(body.encode(), parser)
    except etree.XMLSyntaxError:
        return "invalid xml"
    return (root.text or "") if root is not None else ""


def _app(*, vulnerable: bool):
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.post("/xml")
    def xml() -> Response:
        parsed = _parse(request.get_data(as_text=True), vulnerable=vulnerable)
        return Response(f"<html><body><result>{parsed}</result></body></html>", mimetype="text/html")

    return app


def _app_variants():
    """Endpoints that isolate the DOCTYPE-free and encoding-bypass techniques.

    Both simulate the relevant parser/filter behaviour deterministically (no real filesystem read),
    so the test exercises the detector's delivery strategies on any OS."""
    from flask import Flask, Response, request

    app = Flask(__name__)

    @app.post("/xinclude")
    def xinclude() -> Response:
        # A parser that FORBIDS DOCTYPE (so classic SYSTEM-entity XXE fails) but processes XInclude.
        body = request.get_data(as_text=True)
        if "<!DOCTYPE" in body or "<!ENTITY" in body:
            return Response("<result>DOCTYPE forbidden</result>", mimetype="text/html", status=400)
        if 'parse="text"' in body and "XInclude" in body and 'href="file://' in body:
            return Response(f"<html><result>{_FAKE_PASSWD}</result></html>", mimetype="text/html")
        return Response("<result></result>", mimetype="text/html")

    @app.post("/utf16")
    def utf16() -> Response:
        # A naive signature WAF blocks the ASCII DOCTYPE/ENTITY bytes; a UTF-16 body slips past it and
        # the parser auto-detects the encoding from the BOM and resolves the SYSTEM entity.
        raw = request.get_data()
        if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
            return Response("<result>blocked</result>", mimetype="text/html", status=403)
        try:
            text = raw.decode("utf-16")
        except (UnicodeDecodeError, ValueError):
            text = raw.decode("utf-8", "ignore")
        if "SYSTEM" in text and "file://" in text:
            return Response(f"<html><result>{_FAKE_PASSWD}</result></html>", mimetype="text/html")
        return Response("<result></result>", mimetype="text/html")

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
    url, server = _serve(_app(vulnerable=True))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def safe_url() -> Iterator[str]:
    url, server = _serve(_app(vulnerable=False))
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def variants_url() -> Iterator[str]:
    url, server = _serve(_app_variants())
    yield url
    server.shutdown()


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def _xml_request(base: str) -> HttpRequest:
    # An XML-speaking endpoint: the Content-Type is what tells the detector to try a raw XXE body.
    return HttpRequest(method="POST", url=f"{base}/xml", headers={"Content-Type": "application/xml"})


async def test_inband_xxe_file_read_is_flagged(vuln_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_xxe_inband_checks(client, [_xml_request(vuln_url)])
    assert len(findings) == 1
    assert findings[0].rule_id == "xxe-inband" and findings[0].cwe == "CWE-611"
    assert "passwd" in findings[0].evidence[0].data.lower()


async def test_hardened_xml_parser_is_not_flagged(safe_url: str) -> None:
    async with HttpClient(_scope()) as client:
        findings = await run_xxe_inband_checks(client, [_xml_request(safe_url)])
    assert findings == []


async def test_non_xml_endpoint_is_left_alone(vuln_url: str) -> None:
    # A plain form/JSON request (no XML content type, no XML-valued body) is never probed.
    req = HttpRequest(method="GET", url=f"{vuln_url}/xml", params={"q": "1"})
    async with HttpClient(_scope()) as client:
        findings = await run_xxe_inband_checks(client, [req])
    assert findings == []


async def test_xinclude_file_read_without_doctype(variants_url: str) -> None:
    """DOCTYPE is forbidden (classic XXE blocked), but XInclude reads the file → flagged via XInclude."""
    req = HttpRequest(method="POST", url=f"{variants_url}/xinclude", headers={"Content-Type": "application/xml"})
    async with HttpClient(_scope()) as client:
        findings = await run_xxe_inband_checks(client, [req])
    assert len(findings) == 1
    assert findings[0].rule_id == "xxe-inband"
    assert "xinclude" in findings[0].evidence[0].data.lower()


async def test_utf16_encoding_bypasses_signature_filter(variants_url: str) -> None:
    """A UTF-8 DOCTYPE is blocked by a signature WAF; the UTF-16 variant slips through → flagged."""
    req = HttpRequest(method="POST", url=f"{variants_url}/utf16", headers={"Content-Type": "application/xml"})
    async with HttpClient(_scope()) as client:
        findings = await run_xxe_inband_checks(client, [req])
    assert len(findings) == 1
    assert "utf-16" in findings[0].evidence[0].data.lower()
