"""Cross-Site WebSocket Hijacking (CSWSH). CWE-346 (Origin Validation Error) / OWASP WSTG-CLNT-10.

A WebSocket endpoint that authenticates via ambient cookies but does **not** validate the ``Origin``
header on the handshake can be opened from any attacker page in the victim's browser (cookies are sent
automatically), letting the attacker read and send messages as the victim.

Detection is a handshake **Origin differential**, dependency-free (a raw asyncio WS handshake, TLS-aware
for ``wss://``):

1. discover WebSocket URLs from crawled HTML/JS (``new WebSocket("…")`` and literal ``ws(s)://`` URLs);
2. handshake once with a *legitimate same-origin* ``Origin`` — it must return ``101`` (a working WS);
3. handshake again with a *foreign* ``Origin`` — if that is **also** accepted (``101``), the server
   ignores ``Origin`` → hijackable. If the foreign origin is rejected (non-101 / closed), the endpoint
   validates it → secure, nothing reported. The hit is reproduced.

Only in-scope hosts are contacted. Read-only: it performs the handshake and closes immediately without
exchanging frames.
"""

from __future__ import annotations

import asyncio
import base64
import re
import secrets
import ssl
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_MAX_PAGES = 60
_MAX_WS_ENDPOINTS = 15
_FOREIGN_ORIGIN = "https://dcattacker.example"
_HANDSHAKE_TIMEOUT = 8.0

_WS_LITERAL = re.compile(r"""(wss?://[^\s"'`)<>\\]+)""", re.IGNORECASE)
_NEW_WEBSOCKET = re.compile(r"""new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE)


def _to_ws_scheme(http_scheme: str) -> str:
    return "wss" if http_scheme == "https" else "ws"


def extract_ws_urls(text: str, base_url: str) -> set[str]:
    """Absolute ws(s):// URLs referenced by a page: literal URLs and ``new WebSocket(...)`` args
    (relative and scheme-relative args resolved against ``base_url``)."""
    base = urlsplit(base_url)
    urls: set[str] = set()
    for m in _WS_LITERAL.finditer(text):
        urls.add(m.group(1).rstrip('",;)'))
    for m in _NEW_WEBSOCKET.finditer(text):
        val = m.group(1).strip()
        if val.lower().startswith(("ws://", "wss://")):
            urls.add(val)
        elif val.startswith("//"):
            urls.add(f"{_to_ws_scheme(base.scheme)}:{val}")
        elif val.startswith("/"):
            urls.add(f"{_to_ws_scheme(base.scheme)}://{base.netloc}{val}")
        # a bare relative path (no leading slash) is too ambiguous to resolve -> skip
    return urls


async def _handshake(url: str, origin: str, cookies: dict[str, str]) -> int | None:
    """Perform a raw WebSocket handshake and return the HTTP status (101 = accepted), or None on error."""
    parts = urlsplit(url)
    host = parts.hostname
    if host is None:
        return None
    secure = parts.scheme == "wss"
    port = parts.port or (443 if secure else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    host_hdr = f"{host}:{port}" if parts.port else host
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host_hdr}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        f"Origin: {origin}",
    ]
    if cookies:
        lines.append("Cookie: " + "; ".join(f"{k}={v}" for k, v in cookies.items()))
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "ignore")

    ssl_ctx: ssl.SSLContext | None = None
    if secure:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE  # scanner leniency: reach self-signed staging endpoints too

    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=_HANDSHAKE_TIMEOUT
        )
        writer.write(raw)
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), timeout=_HANDSHAKE_TIMEOUT)
        upgrade = False
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=_HANDSHAKE_TIMEOUT)
            if line in (b"\r\n", b"\n", b""):
                break
            name, _, value = line.decode("latin-1").partition(":")
            if name.strip().lower() == "upgrade" and "websocket" in value.strip().lower():
                upgrade = True
        parts_line = status_line.split()
        if len(parts_line) < 2:
            return None
        status = int(parts_line[1])
        return 101 if (status == 101 and upgrade) else status
    except (TimeoutError, OSError, ssl.SSLError, ValueError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (TimeoutError, OSError):
                pass


def _finding(ws_url: str, authed: bool) -> Finding:
    path = urlsplit(ws_url).path or "/"
    request = HttpRequest(method="GET", url=ws_url)
    detail = (
        f"el endpoint WebSocket {ws_url} acepta el handshake desde un Origin ajeno "
        f"({_FOREIGN_ORIGIN}) igual que desde el propio → no valida Origin"
    )
    if authed:
        detail += (
            ". La sesión envía cookies, así que una página atacante puede abrir el WebSocket en el "
            "navegador de la víctima y actuar como ella (Cross-Site WebSocket Hijacking)"
        )
    cvss = (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"
        if authed
        else "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
    )
    return Finding(
        id=f"cswsh:{path}",
        rule_id="cswsh",
        name="Cross-Site WebSocket Hijacking (Origin no validado)",
        severity="medium" if authed else "low",
        cwe="CWE-346",
        owasp="WSTG-CLNT-10",
        cvss=cvss,
        family="cswsh",
        injection_point=InjectionPoint(location="header", name="Origin", base_value="", request_template=request),
        evidence=[Evidence(type="differential", data=detail[:220], confidence="high")],
        request=request,
        response=HttpResponse(status_code=101, text=""),
        remediation=(
            "Valida el header Origin en el handshake del WebSocket contra una allowlist estricta y "
            "rechaza los orígenes no permitidos. No confíes solo en cookies para autenticar el WS: usa "
            "un token anti-CSRF/por-conexión que el atacante no pueda obtener desde otro origen."
        ),
    )


async def check_ws_origin(client: HttpClient, ws_url: str) -> Finding | None:
    """Origin-differential CSWSH check for one in-scope WebSocket URL."""
    parts = urlsplit(ws_url)
    host = parts.hostname
    if host is None or not client.is_asset_in_scope(host):
        return None
    http_scheme = "https" if parts.scheme == "wss" else "http"
    same_origin = f"{http_scheme}://{parts.netloc}"
    try:
        cookies = dict(client.cookies)
    except (TypeError, ValueError, AttributeError):
        cookies = {}

    if await _handshake(ws_url, same_origin, cookies) != 101:
        return None  # not a working WS from its own origin -> can't run the differential
    if await _handshake(ws_url, _FOREIGN_ORIGIN, cookies) != 101:
        return None  # foreign origin rejected -> Origin is validated -> secure
    if await _handshake(ws_url, _FOREIGN_ORIGIN, cookies) != 101:
        return None  # not reproducible -> noise
    return _finding(ws_url, authed=bool(cookies))


async def _fetch(client: HttpClient, url: str) -> HttpResponse | None:
    try:
        return await client.request("GET", url)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


async def run_cswsh_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Discover WebSocket endpoints from crawled pages and flag those that don't validate Origin."""
    findings: list[Finding] = []
    ws_urls: set[str] = set()
    fetched: set[str] = set()
    pages = 0
    for request in requests:
        if request.method.upper() != "GET" or request.url in fetched:
            continue
        fetched.add(request.url)
        if pages >= _MAX_PAGES:
            break
        response = await _fetch(client, request.url)
        if response is None or response.status_code >= 400:
            continue
        pages += 1
        ws_urls |= extract_ws_urls(response.text, request.url)

    tested = 0
    seen: set[str] = set()
    for ws_url in ws_urls:
        key = urlsplit(ws_url)._replace(query="").geturl()
        if key in seen:
            continue
        seen.add(key)
        if tested >= _MAX_WS_ENDPOINTS:
            break
        tested += 1
        found = await check_ws_origin(client, ws_url)
        if found is not None:
            findings.append(found)
    return findings
