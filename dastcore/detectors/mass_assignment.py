"""Active detector: mass assignment / over-posting.

APIs that bind a whole request body onto a model — ``User(**request.json)`` — let a client set
fields it was never meant to control: ``role``, ``is_admin``, ``verified``, ``owner``,
``balance``. Send one of those with a value the server has no reason to produce, and if the
create/update reflects it back, the field was bound.

The oracle is a **reflection differential** with a unique sentinel, kept false-positive-free:

- a *control* write (the original body) must NOT contain the sentinel, and
- an *attack* write (body + one extra privileged field = a random sentinel) must succeed
  (HTTP < 400) AND echo the sentinel back.

Reflecting a field the client injected, on a successful write, is the mass-assignment
signature. A server that ignores or rejects the unexpected field (sentinel never echoed, or
the write fails) is never flagged, and the sentinel is absent from the control by
construction so an error page that echoes the body can't cause a false positive.

CWE-915 (Improperly Controlled Modification of Object Attributes) / OWASP API3:2023.
"""

from __future__ import annotations

import secrets
from copy import deepcopy
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


def _with_field(request: HttpRequest, field: str, value: str) -> HttpRequest:
    body = deepcopy(request.json_body)
    assert isinstance(body, dict)
    body[field] = value
    return request.model_copy(update={"json_body": body})


async def check_mass_assignment(client: HttpClient, request: HttpRequest) -> list[Finding]:
    """Probe one JSON write for over-posting: inject a privileged field, confirm it's bound."""
    if request.method.upper() not in ("POST", "PUT", "PATCH"):
        return []
    if not isinstance(request.json_body, dict):
        return []  # reflection-based readback needs a JSON object to echo back

    control = await _send(client, request)
    if control is None:
        return []

    findings: list[Finding] = []
    for field in _PRIVILEGED_FIELDS:
        if field in request.json_body:
            continue  # only inject fields the client didn't already send
        sentinel = "dc" + secrets.token_hex(6)
        if sentinel in control.text:  # astronomically unlikely, but keep the differential honest
            continue
        attack = await _send(client, _with_field(request, field, sentinel))
        if attack is None or attack.status_code >= 400 or sentinel not in attack.text:
            continue
        repro = await _send(client, _with_field(request, field, sentinel))
        if repro is None or repro.status_code >= 400 or sentinel not in repro.text:
            continue  # not stably reflected → treat as noise

        path = urlsplit(request.url).path or "/"
        findings.append(
            Finding(
                id=f"mass-assignment:{request.method}:{path}:{field}",
                rule_id="mass-assignment",
                name="Mass assignment / over-posting",
                severity="high",
                cwe="CWE-915",
                owasp="API3:2023",
                cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
                family="mass_assignment",
                injection_point=_point(request, field),
                evidence=[
                    Evidence(
                        type="differential",
                        data=(
                            f"the write bound an unexpected '{field}' field: a unique sentinel injected into the "
                            f"body was echoed in the successful response (HTTP {attack.status_code}) and absent "
                            "from the control write — the server mass-assigned a client-controlled attribute"
                        )[:200],
                        confidence="high",
                    )
                ],
                request=_with_field(request, field, sentinel),
                response=attack,
                remediation=(
                    "Usa una allowlist explícita de campos asignables (DTO / esquema de entrada) en vez de "
                    "volcar el body entero al modelo. Marca los campos sensibles (`role`, `is_admin`, `owner`, "
                    "`balance`) como no asignables desde la petición y asígnalos solo en el servidor."
                ),
            )
        )
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
