from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

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
