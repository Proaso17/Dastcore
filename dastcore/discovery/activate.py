"""Endpoint activation — turn discovered API endpoints into active injection targets.

Discovery (JS bundles, historical archives, dirbusting) surfaces endpoint *paths*, but the
crawler only knows how to issue them as ``GET``. A modern SPA's real attack surface is its JSON
API: ``POST``/``PUT``/``PATCH`` endpoints that take a JSON body, whose fields are the injection
points. Issued as ``GET`` they just 404/405, so the active scanner never tests them.

This module probes each discovered API-looking endpoint for the methods it actually accepts
(``OPTIONS`` ``Allow`` header, plus a cheap empty-body ``POST``) and, when it speaks JSON, builds
a request with an inferred body so the scanner derives JSON injection points and fuzzes it.

Body field names are inferred, in order, from: (1) the field names the server itself names in a
JSON validation error (e.g. ``{"error":"email and password are required"}`` — bilingual), (2) any
body/param names already seen on the endpoint, (3) a compact set of common injectable field names.
Every request goes through the scope-enforced client — nothing here can leave scope.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import HttpClient, OutOfScopeError
from dastcore.core.models import HttpRequest
from dastcore.discovery.crawler_http import _is_logout  # don't activate a logout endpoint (drops the session)

# Path markers that mark a URL as an API endpoint worth probing for non-GET verbs.
_API_MARKERS = ("/api/", "/api", "/v1/", "/v2/", "/v3/", "/rest/", "/rpc/", "/graphql", "/gql")

# Canonical body field -> the (bilingual) tokens whose presence in a server error implies it.
_FIELD_HINTS: dict[str, tuple[str, ...]] = {
    "email": ("email", "e-mail", "correo"),
    "password": ("password", "passwd", "pwd", "contraseña", "contrasena", "clave"),
    "username": ("username", "usuario", "login"),
    "name": ("name", "nombre"),
    "phone": ("phone", "telefono", "teléfono", "movil", "móvil"),
    "token": ("token",),
    "code": ("code", "codigo", "código", "otp"),
    "message": ("message", "mensaje", "body", "content", "contenido", "text", "texto"),
    "title": ("title", "titulo", "título", "subject", "asunto"),
    "query": ("query", "search", "busqueda", "búsqueda"),
    "url": ("url", "uri", "link", "redirect", "callback"),
    "id": ("id", "identifier", "identificador"),
}

# Placeholder base values — syntactically plausible so the request reaches server logic; the rule
# engine replaces each with its payloads, so these are only the seed values of the injection points.
_PLACEHOLDERS: dict[str, str] = {
    "email": "probe@example.com",
    "password": "Probe-Passw0rd1",
    "username": "probeuser",
    "name": "probe",
    "phone": "5551234567",
    "token": "probe-token",
    "code": "123456",
    "message": "probe",
    "title": "probe",
    "query": "probe",
    "url": "https://example.com/",
    "id": "1",
}

# Fallback body when nothing better can be inferred: the field names most likely to be injectable.
_DEFAULT_FIELDS = ("email", "password", "username", "id", "query", "message")


def _looks_like_api(url: str) -> bool:
    """Whether ``url``'s path looks like an API endpoint (worth probing for POST/PUT/PATCH)."""
    path = urlsplit(url).path.lower()
    return any(marker in path for marker in _API_MARKERS)


def _endpoint_key(url: str) -> str:
    """Dedup key: scheme+host+path, ignoring query — one activation per distinct endpoint."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"


def _allowed_methods(allow_header: str) -> set[str]:
    return {m.strip().upper() for m in allow_header.split(",") if m.strip()}


def _infer_fields_from_error(text: str) -> list[str]:
    """Field names the server names in a (JSON) validation error — bilingual, order-stable.

    Matches whole words only (``\\bhint\\b``), so 'id' is not mined from 'inval**id**' nor 'name'
    from 'user**name**' — substring matching would invent fields the server never asked for.
    """
    lowered = text.lower()
    found: list[str] = []
    for field, hints in _FIELD_HINTS.items():
        if any(re.search(rf"\b{re.escape(hint)}\b", lowered) for hint in hints) and field not in found:
            found.append(field)
    return found


def _looks_jsonish(response_headers: dict[str, str], text: str) -> bool:
    ctype = response_headers.get("content-type", "").lower()
    if "application/json" in ctype:
        return True
    body = text.strip()
    return body.startswith("{") or body.startswith("[")


def _build_body(fields: list[str]) -> dict[str, str]:
    return {name: _PLACEHOLDERS.get(name, "probe") for name in fields}


async def activate_endpoints(
    client: HttpClient,
    requests: list[HttpRequest],
    *,
    max_endpoints: int = 40,
    extra_fields: tuple[str, ...] = (),
) -> list[HttpRequest]:
    """Probe discovered API endpoints and return JSON ``POST``/``PUT``/``PATCH`` injection requests.

    For each distinct API-looking endpoint (capped at ``max_endpoints``), sends an ``OPTIONS`` and a
    cheap empty-body ``POST``; when the endpoint accepts a body verb or answers in JSON, emits a
    request whose JSON body carries inferred, benignly-seeded fields (the injection points). Deduped
    by request signature; scope violations and network errors on one endpoint are skipped, never fatal.
    """
    seen_keys: set[str] = set()
    candidates: list[str] = []
    for req in requests:
        if req.method == "GET" and not req.json_body and _looks_like_api(req.url):
            key = _endpoint_key(req.url)
            if key not in seen_keys:
                seen_keys.add(key)
                candidates.append(req.url)
    candidates = candidates[:max_endpoints]

    activated: dict[str, HttpRequest] = {}
    for url in candidates:
        if _is_logout(url):  # a POST/OPTIONS to a logout endpoint would drop the authenticated session
            continue
        try:
            options = await client.request("OPTIONS", url, timeout=8.0, retries=0)
            allow = _allowed_methods(options.headers.get("allow", ""))
        except (OutOfScopeError, httpx.HTTPError, OSError):
            allow = set()

        method = next((m for m in ("POST", "PUT", "PATCH") if m in allow), None)

        error_text = ""
        if method is None:
            # No usable Allow header — probe with an empty JSON POST to see if it's a JSON API.
            try:
                probe = await client.request("POST", url, json={}, timeout=8.0, retries=0)
            except (OutOfScopeError, httpx.HTTPError, OSError):
                continue
            # A JSON API rejects an empty body with a 4xx and a JSON/structured error — that's our cue.
            if 400 <= probe.status_code < 500 and _looks_jsonish(probe.headers, probe.text):
                method = "POST"
                error_text = probe.text
            else:
                continue
        else:
            # Method is allowed; grab the validation error to mine field names.
            try:
                probe = await client.request(method, url, json={}, timeout=8.0, retries=0)
                error_text = probe.text
            except (OutOfScopeError, httpx.HTTPError, OSError):
                error_text = ""

        fields = _infer_fields_from_error(error_text)
        for extra in extra_fields:
            if extra not in fields:
                fields.append(extra)
        if not fields:
            fields = list(_DEFAULT_FIELDS)

        activated_req = HttpRequest(
            method=method,
            url=url,
            headers={"Content-Type": "application/json"},
            json_body=_build_body(fields),
        )
        activated.setdefault(activated_req.signature(), activated_req)

    return list(activated.values())
