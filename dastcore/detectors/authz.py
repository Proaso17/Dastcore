"""Authorization detectors: BOLA/IDOR, BFLA, and missing authentication.

These are differential, multi-session checks — the hardest class for scanners to
get right and the highest-value to find. The signal always comes from *comparing*
who can reach what:

* **BOLA/IDOR** — the same object-scoped endpoint returns the *same object* to two
  different users. A correctly-authorized resource is visible only to its owner;
  identical success across users means object-level authorization is missing.
* **BFLA** — a lower-privilege identity successfully invokes a privileged
  (admin/management) function.
* **Missing authentication** — a sensitive endpoint returns success with no
  credentials at all.

Each check requires a real difference in access to fire, which keeps false
positives near zero.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from dastcore.core.http_client import HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

PRIVILEGED_ROLES = {"staff", "manager", "admin", "administrator", "superadmin", "root"}

_PRIVILEGED_PATH = re.compile(r"(^|/)(admin|administrator|manage|management|internal)(/|$)", re.IGNORECASE)
_SENSITIVE_PATH = re.compile(r"(admin|internal|config|secret|token|password|private|credential)", re.IGNORECASE)
_OBJECT_SEGMENT = re.compile(r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,})$")
_ID_PARAM = re.compile(r"(^|_)(id|uuid|guid)$", re.IGNORECASE)


@dataclass
class Identity:
    """An authenticated actor, with a role label and its own HTTP client (session)."""

    name: str
    role: str
    client: HttpClient


def _is_success(status: int) -> bool:
    return 200 <= status < 300


def _normalize_body(text: str) -> str:
    return " ".join(text.split())[:4000]


def _looks_object_scoped(request: HttpRequest) -> bool:
    segments = urlsplit(request.url).path.strip("/").split("/")
    if any(_OBJECT_SEGMENT.match(seg) for seg in segments):
        return True
    keys = list(request.params) + list((request.json_body or {}) if isinstance(request.json_body, dict) else [])
    return any(_ID_PARAM.search(key) for key in keys)


def _authz_point(request: HttpRequest, name: str) -> InjectionPoint:
    return InjectionPoint(location="path", name=name, base_value="", request_template=request)


async def _send(client: HttpClient, request: HttpRequest) -> HttpResponse | None:
    try:
        return await client.request(
            request.method,
            request.url,
            params=request.params,
            headers=request.headers or None,
            cookies=request.cookies or None,
            data=request.data,
            json=request.json_body,
        )
    except OutOfScopeError:
        return None


def _bola_finding(request: HttpRequest, response: HttpResponse, identities: list[str]) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"authz-bola:{request.method}:{path}",
        rule_id="authz-bola",
        name="Broken Object Level Authorization (BOLA/IDOR)",
        severity="high",
        cwe="CWE-639",
        owasp="OWASP API1:2023 - BOLA",
        injection_point=_authz_point(request, "object-id"),
        evidence=[
            Evidence(
                type="differential",
                data=f"identical object returned to multiple identities: {', '.join(identities)}",
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "Enforce object-level authorization on every request: verify the authenticated "
            "subject owns or may access the specific object id, server-side, for each call."
        ),
    )


def _bfla_finding(request: HttpRequest, response: HttpResponse, identity: Identity) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"authz-bfla:{request.method}:{path}",
        rule_id="authz-bfla",
        name="Broken Function Level Authorization (BFLA)",
        severity="high",
        cwe="CWE-285",
        owasp="OWASP API5:2023 - BFLA",
        injection_point=_authz_point(request, "function"),
        evidence=[
            Evidence(
                type="status",
                data=f"identity '{identity.name}' (role '{identity.role}') invoked a privileged function (HTTP {response.status_code})",
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation=(
            "Enforce function-level authorization: check the caller's role/permission on every "
            "privileged endpoint server-side, denying by default."
        ),
    )


def _missing_auth_finding(request: HttpRequest, response: HttpResponse) -> Finding:
    path = urlsplit(request.url).path or "/"
    return Finding(
        id=f"authz-missing-auth:{request.method}:{path}",
        rule_id="authz-missing-auth",
        name="Sensitive endpoint accessible without authentication",
        severity="high",
        cwe="CWE-306",
        owasp="OWASP API2:2023 - Broken Authentication",
        injection_point=_authz_point(request, "-"),
        evidence=[
            Evidence(
                type="status",
                data=f"unauthenticated request returned HTTP {response.status_code}",
                confidence="high",
            )
        ],
        request=request,
        response=response,
        remediation="Require authentication (and authorization) on this endpoint; deny by default.",
    )


async def run_authz_checks(
    identities: list[Identity],
    probes: list[HttpRequest],
    *,
    unauth_client: HttpClient | None = None,
) -> list[Finding]:
    """Run BOLA/BFLA/missing-auth differential checks over `probes` across `identities`."""
    findings: list[Finding] = []

    for probe in probes:
        successful: list[tuple[Identity, HttpResponse, str]] = []
        for identity in identities:
            response = await _send(identity.client, probe)
            if response is not None and _is_success(response.status_code):
                successful.append((identity, response, _normalize_body(response.text)))

        unauth_response = await _send(unauth_client, probe) if unauth_client is not None else None
        unauth_ok = unauth_response is not None and _is_success(unauth_response.status_code)

        # BOLA: an object-scoped endpoint returns the identical object to two different users.
        if _looks_object_scoped(probe) and len(successful) >= 2:
            by_body: dict[str, list[Identity]] = {}
            resp_by_body: dict[str, HttpResponse] = {}
            for identity, response, body in successful:
                by_body.setdefault(body, []).append(identity)
                resp_by_body.setdefault(body, response)
            for body, ids in by_body.items():
                if len(ids) >= 2:
                    findings.append(_bola_finding(probe, resp_by_body[body], [i.name for i in ids]))
                    break

        # Missing authentication: a sensitive endpoint succeeds with no credentials at all.
        if unauth_ok and _SENSITIVE_PATH.search(probe.url):
            findings.append(_missing_auth_finding(probe, unauth_response))  # type: ignore[arg-type]

        # BFLA: a non-privileged identity reached a privileged function that is genuinely
        # auth-gated. If the endpoint is reachable unauthenticated, the root cause is missing
        # authentication (reported above), not a function-level authorization bypass — so we
        # don't double-report it here.
        if _PRIVILEGED_PATH.search(urlsplit(probe.url).path) and not unauth_ok:
            for identity, response, _ in successful:
                if identity.role.lower() not in PRIVILEGED_ROLES:
                    findings.append(_bfla_finding(probe, response, identity))
                    break

    return findings
