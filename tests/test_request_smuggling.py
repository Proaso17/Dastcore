"""HTTP request smuggling (CL.TE timing): a server that honours Transfer-Encoding and stalls on an
incomplete chunked body is flagged; one that always answers fast is not. Uses raw asyncio TCP servers
so the framing behaviour is exercised for real."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from dastcore.core.models import HttpRequest
from dastcore.detectors.request_smuggling import run_smuggling_checks

_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


async def _respond(writer: asyncio.StreamWriter) -> None:
    try:
        writer.write(_OK)
        await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


async def _vuln_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3)
    except (TimeoutError, asyncio.IncompleteReadError, OSError):
        writer.close()
        return
    if b"transfer-encoding: chunked" in headers.lower():
        buf = b""
        try:
            while b"0\r\n\r\n" not in buf:  # wait for the chunked terminator (like a TE back-end)
                data = await asyncio.wait_for(reader.read(64), timeout=1.5)
                if not data:
                    break
                buf += data
        except TimeoutError:
            await asyncio.sleep(6)  # incomplete -> keep the connection open so the client's read stalls
            writer.close()
            return
    await _respond(writer)  # baseline or a complete chunked body -> fast


async def _safe_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3)
    except (TimeoutError, asyncio.IncompleteReadError, OSError):
        pass
    await _respond(writer)  # always answers immediately, never stalls


async def _run(handler: Callable) -> list:
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        request = HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/")
        return await run_smuggling_checks(None, [request])  # type: ignore[arg-type]  # client unused (raw sockets)
    finally:
        server.close()
        await server.wait_closed()


async def test_clte_desync_stall_is_flagged() -> None:
    findings = await _run(_vuln_handler)
    assert len(findings) == 1
    assert findings[0].rule_id == "http-request-smuggling" and findings[0].cwe == "CWE-444"


async def test_responsive_server_is_not_flagged() -> None:
    findings = await _run(_safe_handler)
    assert findings == []  # attack answers as fast as control -> no differential
