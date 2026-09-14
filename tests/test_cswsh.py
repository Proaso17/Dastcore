"""Cross-Site WebSocket Hijacking. A WS endpoint that accepts a handshake from a foreign Origin the
same as from its own is flagged (Origin not validated); one that validates Origin is silent. Uses a
tiny raw-asyncio WS handshake server (no dependency) in vulnerable and origin-validating modes."""

from __future__ import annotations

import asyncio
import base64
import hashlib

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.detectors.cswsh import check_ws_origin, extract_ws_urls

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + _GUID).encode()).digest()).decode()  # noqa: S324 - WS spec


async def _start_ws_server(mode: str):
    """mode='vuln' accepts any Origin; mode='safe' only accepts its own same-origin."""
    state: dict[str, str | None] = {"origin": None}

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readline()  # request line
        headers: dict[str, str] = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            name, _, value = line.decode("latin-1").partition(":")
            headers[name.strip().lower()] = value.strip()
        key = headers.get("sec-websocket-key", "")
        origin = headers.get("origin", "")
        ok = bool(key) and (mode == "vuln" or origin == state["origin"])
        if ok:
            resp = (
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Accept: {_accept(key)}\r\n\r\n"
            )
        else:
            resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
        writer.write(resp.encode())
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    state["origin"] = f"http://127.0.0.1:{port}"
    return server, port


def _scope() -> ScopeConfig:
    return ScopeConfig(allow_domains=["127.0.0.1"])


def test_extract_ws_urls_absolute_and_relative() -> None:
    text = 'x=new WebSocket("wss://x.test/socket");y=new WebSocket("/live");z="ws://y.test/a"'
    urls = extract_ws_urls(text, "https://x.test/page")
    assert "wss://x.test/socket" in urls
    assert "wss://x.test/live" in urls  # relative resolved against base, https -> wss
    assert "ws://y.test/a" in urls


async def test_cswsh_flagged_when_origin_not_validated() -> None:
    server, port = await _start_ws_server("vuln")
    async with server:
        async with HttpClient(_scope()) as client:
            finding = await check_ws_origin(client, f"ws://127.0.0.1:{port}/chat")
    assert finding is not None
    assert finding.rule_id == "cswsh" and finding.cwe == "CWE-346"
    assert "origin" in finding.evidence[0].data.lower()


async def test_no_cswsh_when_origin_is_validated() -> None:
    server, port = await _start_ws_server("safe")
    async with server:
        async with HttpClient(_scope()) as client:
            finding = await check_ws_origin(client, f"ws://127.0.0.1:{port}/chat")
    assert finding is None


async def test_cswsh_out_of_scope_host_is_skipped() -> None:
    server, port = await _start_ws_server("vuln")
    async with server:
        async with HttpClient(ScopeConfig(allow_domains=["example.test"])) as client:
            finding = await check_ws_origin(client, f"ws://127.0.0.1:{port}/chat")
    assert finding is None
