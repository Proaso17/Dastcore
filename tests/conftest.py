from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from tests.targets.vuln_app.app import create_app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _ServerThread(threading.Thread):
    def __init__(self, app, host: str, port: int) -> None:
        super().__init__(daemon=True)
        self._server = make_server(host, port, app)

    def run(self) -> None:
        self._server.serve_forever()

    def shutdown(self) -> None:
        self._server.shutdown()


@pytest.fixture(scope="session")
def vuln_app_url() -> Iterator[str]:
    """Serves the deliberately-vulnerable Flask fixture on a free local port for the test session."""
    host = "127.0.0.1"
    port = _free_port()
    app = create_app()
    thread = _ServerThread(app, host, port)
    thread.start()
    yield f"http://{host}:{port}"
    thread.shutdown()
    thread.join(timeout=5)


@pytest.fixture
def sample_finding() -> Finding:
    """A representative Finding for report / evidence tests (no network needed)."""
    request = HttpRequest(method="GET", url="http://target.test/search", params={"q": "1' OR '1'='1"})
    point = InjectionPoint(location="query", name="q", request_template=request)
    return Finding(
        id="sqli-injection:GET:/search:query:q",
        rule_id="sqli-injection",
        name="SQL Injection",
        severity="high",
        cwe="CWE-89",
        owasp="WSTG-INPV-05",
        injection_point=point,
        evidence=[Evidence(type="response_match", data="SQL syntax", confidence="high")],
        request=request,
        response=HttpResponse(status_code=500, text="SQL syntax error"),
        remediation="Use parameterized queries.",
    )
