"""Active detector: mass assignment / over-posting.

APIs that bind a whole request body onto a model — ``User(**request.json)`` — let a client set
fields it was never meant to control: ``role``, ``is_admin``, ``verified``, ``owner``,
``balance``. Send one of those with a value the server has no reason to produce, and if the
create/update binds it, the field was over-posted.

Two complementary, false-positive-free oracles confirm the bind:

* **Reflection differential** (create or update) — inject one extra privileged field carrying a
  unique random sentinel; the *attack* write must succeed (HTTP < 400) AND echo the sentinel,
  while the *control* write (original body) must not contain it. Reflecting a field the client
  injected, on a successful write, is the signature.
* **Read-back** (update only, PUT/PATCH) — many APIs bind a field server-side but never echo it
  (they return ``{"status":"ok"}`` or the object without the field), so reflection misses them.
  So after the attack write we *re-read the object* (GET same URL) and confirm the value
  persisted: a unique sentinel absent from the pre-write read but present in the post-write read
  (or a boolean privileged flag that was false/absent and is now true). The bind is proven by
  persisted state, not by an echo. Best-effort restore of the field follows.

A server that ignores or rejects the unexpected field is never flagged. Read-back performs writes
(this is an authenticated active check) and attempts to restore the field afterwards.

CWE-915 (Improperly Controlled Modification of Object Attributes) / OWASP API3:2023.
"""

from __future__ import annotations

import json as _json
import secrets
from copy import deepcopy
from typing import Any
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# Fields a client should never be able to set on itself/its objects. Probed only if absent
# from the request already (we inject what the client didn't send).
_PRIVILEGED_FIELDS = (
    "role",
    "is_admin",
    "isAdmin",
    "admin",
    "is_staff",
    "is_superuser",
    "verified",
    "is_verified",
    "approved",
    "active",
    "owner",
    "owner_id",
    "user_id",
    "account_id",
    "balance",
    "credits",
    "plan",
)

# Privileged flags whose meaningful value is boolean true. For read-back we inject `true` and
# confirm the persisted value flipped from false/absent to true (a string sentinel can't bind
# to a boolean column, so these need the flip differential instead).
_BOOLEAN_FIELDS = frozenset(
    {"is_admin", "isAdmin", "admin", "is_staff", "is_superuser", "verified", "is_verified", "approved", "active"}
)

# High-impact fields worth the extra writes of a read-back probe when reflection didn't fire.
_READBACK_FIELDS = frozenset(
    {"role", "is_admin", "isAdmin", "admin", "is_staff", "is_superuser", "verified", "approved",
     "owner_id", "balance", "credits", "plan"}
)

# NB: in Python `True == 1` and `False == 0`, so the bool literals already match the ints 1/0 on
# membership; listing 1/0 too would be redundant set members.
_TRUE_VALUES = frozenset({True, "true", "True", "1"})
_FALSEY: frozenset[Any] = frozenset({False, "false", "False", "0", "", None})
_MISSING = object()


def _point(request: HttpRequest, name: str) -> InjectionPoint:
    return InjectionPoint(location="json", name=name, base_value="", request_template=request)


async def _send(client: HttpClient, request: HttpRequest) -> HttpResponse | None:
    try:
        return await client.request(
            request.method,
            request.url,
            params=request.params or None,
            headers=request.headers or None,
            cookies=request.cookies or None,
            data=request.data,
            json=request.json_body,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


async def _get(client: HttpClient, request: HttpRequest) -> HttpResponse | None:
    """Read the object back from the same URL (with the same session) — no body."""
    try:
        return await client.request(
            "GET", request.url, params=request.params or None, cookies=request.cookies or None
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _with_field(request: HttpRequest, field: str, value: Any) -> HttpRequest:
    body = deepcopy(request.json_body)
    assert isinstance(body, dict)
    body[field] = value
    return request.model_copy(update={"json_body": body})


def _safe_json(text: str) -> Any:
    try:
        return _json.loads(text)
    except (ValueError, TypeError):
        return None


def _find_value(doc: Any, field: str, depth: int = 0) -> Any:
    """The value of `field` anywhere in a decoded JSON document (bounded depth), or `_MISSING`."""
    if depth > 5:
        return _MISSING
    if isinstance(doc, dict):
        if field in doc:
            return doc[field]
        for value in doc.values():
            found = _find_value(value, field, depth + 1)
            if found is not _MISSING:
                return found
    elif isinstance(doc, list):
        for item in doc:
            found = _find_value(item, field, depth + 1)
            if found is not _MISSING:
                return found
    return _MISSING


def _finding(request: HttpRequest, field: str, response: HttpResponse, *, mode: str) -> Finding:
    path = urlsplit(request.url).path or "/"
    if mode == "readback":
        detail = (
            f"the update bound an unexpected '{field}' field: after injecting it, a fresh read of "
            f"the object showed the value persisted (it was absent/false before the write) — the "
            "server mass-assigned a client-controlled attribute even though the write response did "
            "not echo it"
        )
    else:
        detail = (
            f"the write bound an unexpected '{field}' field: a unique sentinel injected into the "
            f"body was echoed in the successful response (HTTP {response.status_code}) and absent "
            "from the control write — the server mass-assigned a client-controlled attribute"
        )
    return Finding(
        id=f"mass-assignment:{request.method}:{path}:{field}",
        rule_id="mass-assignment",
        name="Mass assignment / over-posting",
        severity="high",
        cwe="CWE-915",
        owasp="API3:2023",
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
        family="mass_assignment",
        injection_point=_point(request, field),
        evidence=[Evidence(type="differential", data=detail[:220], confidence="high")],
        request=request,
        response=response,
        remediation=(
            "Usa una allowlist explícita de campos asignables (DTO / esquema de entrada) en vez de "
            "volcar el body entero al modelo. Marca los campos sensibles (`role`, `is_admin`, `owner`, "
            "`balance`) como no asignables desde la petición y asígnalos solo en el servidor."
        ),
    )


async def _reflection_probe(
    client: HttpClient, request: HttpRequest, field: str, control: HttpResponse
) -> Finding | None:
    """Fire if injecting `field` with a unique sentinel is echoed on a successful write."""
    sentinel = "dc" + secrets.token_hex(6)
    if sentinel in control.text:  # astronomically unlikely, but keep the differential honest
        return None
    attack = await _send(client, _with_field(request, field, sentinel))
    if attack is None or attack.status_code >= 400 or sentinel not in attack.text:
        return None
    repro = await _send(client, _with_field(request, field, sentinel))
    if repro is None or repro.status_code >= 400 or sentinel not in repro.text:
        return None  # not stably reflected → treat as noise
    return _finding(_with_field(request, field, sentinel), field, attack, mode="reflection")


async def _readback_probe(client: HttpClient, request: HttpRequest, field: str) -> Finding | None:
    """Fire if injecting `field` on a PUT/PATCH persists — confirmed by re-reading the object.

    Catches binds that never reflect in the write response. Zero-FP: for value fields a unique
    sentinel must be absent from the pre-write read and present in the post-write read; for boolean
    flags the persisted value must flip from false/absent to true, so the change is attributable to
    our write. Restores the field afterwards on a best-effort basis.
    """
    baseline = await _get(client, request)
    if baseline is None or baseline.status_code >= 400:
        return None  # can't read the object back → can't prove persistence

    is_bool = field in _BOOLEAN_FIELDS
    base_value: Any = _MISSING
    if is_bool:
        base_value = _find_value(_safe_json(baseline.text), field)
        if base_value not in _FALSEY:
            return None  # already true (or unreadable) → a later `true` isn't attributable to us
        injected: Any = True
    else:
        injected = "dc" + secrets.token_hex(6)
        if injected in baseline.text:
            return None

    attack = await _send(client, _with_field(request, field, injected))
    if attack is None or attack.status_code >= 400:
        return None

    readback = await _get(client, request)
    confirmed = False
    if readback is not None and readback.status_code < 400:
        if is_bool:
            confirmed = _find_value(_safe_json(readback.text), field) in _TRUE_VALUES
        else:
            confirmed = injected in readback.text

    # Best-effort restore so the scan doesn't leave the injected value behind.
    if base_value is not _MISSING:
        await _send(client, _with_field(request, field, base_value))
    else:
        await _send(client, request)

    if not confirmed:
        return None
    return _finding(_with_field(request, field, injected), field, readback, mode="readback")  # type: ignore[arg-type]


async def check_mass_assignment(client: HttpClient, request: HttpRequest) -> list[Finding]:
    """Probe one JSON write for over-posting: inject a privileged field, confirm it's bound."""
    if request.method.upper() not in ("POST", "PUT", "PATCH"):
        return []
    if not isinstance(request.json_body, dict):
        return []  # needs a JSON object to inject into / echo back

    control = await _send(client, request)
    if control is None:
        return []

    can_readback = request.method.upper() in ("PUT", "PATCH")
    findings: list[Finding] = []
    for field in _PRIVILEGED_FIELDS:
        if field in request.json_body:
            continue  # only inject fields the client didn't already send
        finding = await _reflection_probe(client, request, field, control)
        if finding is None and can_readback and field in _READBACK_FIELDS:
            finding = await _readback_probe(client, request, field)
        if finding is not None:
            findings.append(finding)
    return findings


async def run_mass_assignment_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Run the mass-assignment check over every JSON write, deduplicated by request shape."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for request in requests:
        signature = request.signature()
        if signature in seen:
            continue
        seen.add(signature)
        findings.extend(await check_mass_assignment(client, request))
    return findings
