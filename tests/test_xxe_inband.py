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
