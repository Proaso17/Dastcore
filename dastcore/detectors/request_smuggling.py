"""HTTP request smuggling — CL.TE desync, timing-confirmed. CWE-444, OWASP A05:2021.

The safest, false-positive-resistant smuggling signal is a **timing differential** over a raw socket:

- an **attack** probe advertises ``Content-Length`` *and* ``Transfer-Encoding: chunked`` with a chunked
  body that is deliberately incomplete. A chain that prefers ``Transfer-Encoding`` waits for the missing
  chunk terminator, so *our own* connection stalls until the read timeout;
- a **control** probe sends the *same* headers but a complete chunked body — any chain answers it fast;
- a **baseline** plain request confirms the server is responsive to begin with.

Only when the attack stalls while control **and** baseline stay fast — and it reproduces — is it
reported. A server that's simply slow stalls on all three (no differential); one that always answers
fast never stalls. The probe only makes *our* connection wait for bytes we never send (it never injects
a request into another client's stream), and it is bounded by a short read timeout. Delicate, so it is
behind ``--test-smuggling`` and off in ``quick``.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from urllib.parse import urlsplit

from dastcore.core.http_client import HttpClient
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_TIMEOUT = 4.0  # seconds; also how long the attack probe is allowed to stall
_FAST_MS = 1500.0  # baseline and control must return under this
_MAX_HOSTS = 4
_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE


def _baseline(host: str) -> bytes:
    return f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()


def _attack(host: str) -> bytes:
    body = "1\r\nZ"  # chunk size 1, one byte, then *nothing* — no terminator
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{body}"
    ).encode()


def _control(host: str) -> bytes:
    body = "1\r\nZ\r\n0\r\n\r\n"  # a complete chunked body -> nobody waits
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{body}"
    ).encode()


async def _probe(host: str, port: int, use_tls: bool, payload: bytes) -> tuple[bool, float] | None:
    """Send raw bytes and time the first response byte. Returns (timed_out, elapsed_ms), or None on a
    connection-level failure."""
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=_TLS_CTX if use_tls else None), timeout=_TIMEOUT
        )
    except (TimeoutError, OSError, ssl.SSLError):
        return None
    timed_out = False
    try:
        writer.write(payload)
        await writer.drain()
        try:
            await asyncio.wait_for(reader.read(1), timeout=_TIMEOUT)
        except TimeoutError:
            timed_out = True
    except (OSError, ssl.SSLError):
        return None
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except (TimeoutError, OSError, ssl.SSLError):
            pass
    return timed_out, (time.monotonic() - start) * 1000.0


def _finding(request: HttpRequest, attack_ms: float, control_ms: float, baseline_ms: float) -> Finding:
    return Finding(
        id=f"http-request-smuggling:{urlsplit(request.url).netloc}",
        rule_id="http-request-smuggling",
        name="HTTP request smuggling (CL.TE, confirmado por temporización)",
        severity="high",
        cwe="CWE-444",
        owasp="A05:2021",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L",
        family="smuggling",
        injection_point=InjectionPoint(
            location="header", name="Transfer-Encoding", base_value="", request_template=request
        ),
        evidence=[
            Evidence(
                type="time_based",
                data=(
                    f"un chunked incompleto (Content-Length + Transfer-Encoding) colgó la conexión {attack_ms:.0f}ms "
                    f"mientras un chunked completo respondió en {control_ms:.0f}ms y una petición normal en "
                    f"{baseline_ms:.0f}ms — discrepancia CL.TE en el framing, potencial desincronización explotable"
                )[:200],
                confidence="high",
            )
        ],
        request=request,
        response=HttpResponse(status_code=0, elapsed_ms=attack_ms),
        remediation=(
            "Haz que front-end y back-end acuerden el framing del mensaje: rechaza peticiones con Content-Length y "
            "Transfer-Encoding a la vez, normaliza/rechaza Transfer-Encoding ofuscado, y prefiere HTTP/2 extremo a "
            "extremo. Cierra la conexión ante cualquier ambigüedad de longitud."
        ),
    )


async def _check_host(request: HttpRequest) -> Finding | None:
    parts = urlsplit(request.url)
    host = parts.hostname
    if host is None:
        return None
    use_tls = parts.scheme == "https"
    port = parts.port or (443 if use_tls else 80)

    baseline = await _probe(host, port, use_tls, _baseline(host))
    control = await _probe(host, port, use_tls, _control(host))
    if baseline is None or control is None:
        return None
    base_to, base_ms = baseline
    ctrl_to, ctrl_ms = control
    if base_to or ctrl_to or base_ms >= _FAST_MS or ctrl_ms >= _FAST_MS:
        return None  # server not cleanly responsive -> can't trust the differential

    attack = await _probe(host, port, use_tls, _attack(host))
    if attack is None or not attack[0]:
        return None  # attack didn't stall -> no CL.TE discrepancy
    again = await _probe(host, port, use_tls, _attack(host))  # reproducible
    if again is None or not again[0]:
        return None
    return _finding(request, attack[1], ctrl_ms, base_ms)


async def run_smuggling_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """One CL.TE timing differential per in-scope host; report reproducible attack-only stalls."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for request in requests:
        netloc = urlsplit(request.url).netloc
        if not netloc or netloc in seen:
            continue
        seen.add(netloc)
        if len(seen) > _MAX_HOSTS:
            break
        hit = await _check_host(request)
        if hit is not None:
            findings.append(hit)
    return findings
