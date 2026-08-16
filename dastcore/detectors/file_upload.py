"""Unrestricted upload of a file with a dangerous type. CWE-434, OWASP A05:2021.

Uploads a benign-but-dangerous file to an upload endpoint, finds where it was stored, retrieves it,
and confirms the impact from what comes back:

- a ``.php`` whose body ``echo``es a unique arithmetic result — if the retrieval returns the computed
  *product* (not the literal ``<?php`` source), the server executed it: remote code execution;
- an ``.html`` / ``.svg`` carrying a unique marker served back with an active content-type — stored
  XSS / content injection via upload.

Only ever fires when our own uploaded marker is retrieved back, so it can't false-positive on an
endpoint that accepts the upload but never serves it. Intrusive (it writes a file to the server), so
it is behind ``--test-upload`` and off in the ``quick`` profile.
"""

from __future__ import annotations

import json
import re
import secrets
from urllib.parse import urljoin, urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_FILE_FIELD = re.compile(r"(file|upload|attach|avatar|image|photo|picture|document|media|import)", re.I)
_UPLOAD_PATH = re.compile(r"(upload|import|avatar|attachment|/file|media)", re.I)
_UPLOAD_DIRS = ["/uploads/", "/upload/", "/files/", "/file/", "/media/", "/static/uploads/", "/img/", "/images/"]
_MAX_ENDPOINTS = 12


async def _upload(client: HttpClient, request: HttpRequest, other: dict[str, str], files: dict) -> HttpResponse | None:
    try:
        return await client.request(
            "POST",
            request.url,
            params=request.params or None,
            headers=request.headers or None,
            data=other or None,
            files=files,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


async def _get(client: HttpClient, url: str) -> HttpResponse | None:
    try:
        return await client.request("GET", url)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _content_type(response: HttpResponse) -> str:
    for key, value in response.headers.items():
        if key.lower() == "content-type":
            return value.lower()
    return ""


def _json_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _json_strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _json_strings(v)]
    return []


def _locate(response: HttpResponse, base: str, filename: str) -> list[str]:
    """Candidate URLs where the uploaded file may now be served."""
    found: list[str] = []
    try:
        for s in _json_strings(json.loads(response.text)):
            if filename in s:
                found.append(s)
    except (ValueError, TypeError):
        pass
    for match in re.finditer(r"""[^\s"'<>()]*""" + re.escape(filename), response.text):
        found.append(match.group(0))
    for key, value in response.headers.items():
        if key.lower() == "location":
            found.append(value)
    found += [d + filename for d in _UPLOAD_DIRS]  # common fallbacks
    seen: set[str] = set()
    urls: list[str] = []
    for candidate in found:
        absolute = urljoin(base, candidate)
        if absolute not in seen:
            seen.add(absolute)
            urls.append(absolute)
    return urls[:8]


def _finding(request: HttpRequest, response: HttpResponse, field: str, detail: str, severity: str) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"unrestricted-file-upload:{severity}:{path}:{field}",
        rule_id="unrestricted-file-upload",
        name="Unrestricted file upload (subida de fichero peligroso)",
        severity=severity,  # type: ignore[arg-type]
        cwe="CWE-434",
        owasp="A05:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        family="upload",
        injection_point=InjectionPoint(location="body", name=field, base_value="", request_template=request),
        evidence=[Evidence(type="reflected", data=detail[:200], confidence="high")],
        request=request,
        response=response,
        remediation=(
            "Valida las subidas por allowlist de tipo/extensión (no por blocklist), reescribe el nombre, guarda "
            "fuera del webroot o en un almacén sin ejecución, y sírvelas con Content-Type fijo y "
            "Content-Disposition: attachment. Nunca ejecutes/interpretes los ficheros subidos."
        ),
    )


async def _probe_endpoint(client: HttpClient, request: HttpRequest, field: str) -> Finding | None:
    base = urlsplit(request.url)._replace(path="/", query="", fragment="").geturl()
    other = {k: "dc" for k in (request.data or {}) if k != field}
    tok = secrets.token_hex(5)
    left, right = f"ul{tok}", f"ur{tok}"
    a, b = 100 + secrets.randbelow(900), 100 + secrets.randbelow(900)
    product = str(a * b)
    marker = f"{left}dcup{right}"

    payloads = [
        (f"dc{tok}.php", f'<?php echo "{left}".({a}*{b})."{right}"; ?>'.encode(), "image/jpeg", "exec"),
        (f"dc{tok}.html", f"<html>{marker}</html>".encode(), "text/html", "served"),
        (f"dc{tok}.svg", f'<svg xmlns="http://www.w3.org/2000/svg">{marker}</svg>'.encode(), "image/svg+xml", "served"),
    ]
    for filename, content, ctype, kind in payloads:
        upload = await _upload(client, request, other, {field: (filename, content, ctype)})
        if upload is None:
            continue
        for url in _locate(upload, base, filename):
            got = await _get(client, url)
            if got is None:
                continue
            body, ct = got.text, _content_type(got)
            if kind == "exec" and re.search(re.escape(left) + re.escape(product) + re.escape(right), body):
                return _finding(
                    request,
                    got,
                    field,
                    f"un .php subido se ejecutó al recuperarlo en {url} (devolvió {left}{product}{right}) — "
                    "ejecución remota de código vía subida sin restricciones",
                    "critical",
                )
            if kind == "served" and marker in body and ("html" in ct or "svg" in ct or "xml" in ct):
                return _finding(
                    request,
                    got,
                    field,
                    f"un {filename.rsplit('.', 1)[-1]} subido se sirve en {url} como '{ct}' con contenido "
                    "controlado por el atacante — XSS almacenado / inyección de contenido vía subida",
                    "high",
                )
    return None


async def run_file_upload_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Probe upload endpoints for unrestricted upload of executable/servable files."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for request in requests:
        if request.method != "POST":
            continue
        data = request.data or {}
        field = next((k for k in data if _FILE_FIELD.search(k)), None)
        path = urlsplit(request.url).path or "/"
        if field is None and not _UPLOAD_PATH.search(path):
            continue
        field = field or "file"
        sig = (path, field)
        if sig in seen:
            continue
        seen.add(sig)
        if len(seen) > _MAX_ENDPOINTS:
            break
        hit = await _probe_endpoint(client, request, field)
        if hit is not None:
            findings.append(hit)
    return findings
