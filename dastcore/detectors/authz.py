"""Authorization detectors: BOLA/IDOR, BFLA, and missing authentication.

These are differential, multi-session checks — the hardest class for scanners to
get right and the highest-value to find. The signal always comes from *comparing*
who can reach what:

* **BOLA/IDOR** — an object-scoped endpoint returns the *same owned record* to two
  different users. A correctly-authorized resource is visible only to its owner, so a
  second reader means object-level authorization is missing. Two confirmation paths:
  (1) identical owned body across identities; (2) the same owned record (matched by a
  principal id — owner_id/user_id/account_id value or email) reaches ≥2 identities even
  when the surrounding body differs (per-session chrome), gated on a privacy proof that
  the object is access-controlled (unauth or another identity is denied 401/403/404).
* **BFLA** — a lower-privilege identity successfully invokes a privileged
  (admin/management) function.
* **Missing authentication** — a sensitive endpoint returns success with no
  credentials at all.

Each check requires a real difference in access to fire, which keeps false
positives near zero.

The checks in ``run_authz_checks`` are *observational* — they replay already-crawled
requests across sessions. ``run_bola_enumeration_checks`` is *active*: a single session
walks neighbouring integer ids to reach objects the crawler never saw (the classic manual
IDOR test), gated on an access-control proof + strong per-user PII + owner diversity so a
legitimately member-shared resource (e.g. a forum) can't trip it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from dastcore.core.http_client import HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

PRIVILEGED_ROLES = {"staff", "manager", "admin", "administrator", "superadmin", "root"}

_PRIVILEGED_PATH = re.compile(r"(^|/)(admin|administrator|manage|management|internal)(/|$)", re.IGNORECASE)
_SENSITIVE_PATH = re.compile(r"(admin|internal|config|secret|token|password|private|credential)", re.IGNORECASE)
_OBJECT_SEGMENT = re.compile(r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,})$")
_ID_PARAM = re.compile(r"(^|_)(id|uuid|guid)$", re.IGNORECASE)

# Fields/values that mark a body as *someone's owned data* rather than a public
# resource — the difference between a BOLA and a legitimately-shared object.
_OWNERSHIP_MARKERS = re.compile(
    r"\b(owner|owner_id|user_id|userid|account|account_id|customer|customer_id|email|"
    r"first_name|last_name|full_name|username|phone|address|ssn|dob|balance|iban|card)\b"
    r"|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)


def _ownership_marker(body: str) -> str | None:
    """The owner-identifying field/value in a response, if any (else None)."""
    match = _OWNERSHIP_MARKERS.search(body)
    return match.group(0) if match else None


# A *specific* principal identifier bound to a record: an owner/user/account id whose value is
# an actual identifier (number, UUID, or email) — not a generic label like "free"/"public". Two
# sessions returning the SAME such value are looking at the same owned record, regardless of the
# surrounding response chrome. This is stricter than `_OWNERSHIP_MARKERS` (which only asks "does
# this look like owned data") because here the value must *match across identities*.
# Capture an owner/user/account field and its *whole* value token; the value's shape is validated
# separately (below) so a partial match can never collapse two distinct ids into one signature.
_OWNER_ID_FIELD = re.compile(
    r"""["']?(owner_id|owner|user_id|userid|uid|account_id|customer_id)["']?\s*[:=]\s*"""
    r"""["']?([A-Za-z0-9._%@+-]+)""",
    re.IGNORECASE,
)
# A value that denotes a *specific principal*: a pure integer, a UUID, or an email. Anything else
# (a label like "free"/"public", a partial token) is rejected — it can't identify a record.
_UUID_VALUE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_INT_VALUE = re.compile(r"^\d+$")
_DENIED_STATUSES = {401, 403, 404}

# Strong per-user PII: data meaningful only to its owner. Requiring this in an *enumerated*
# cross-account read is what separates a real IDOR (leaking someone's private data) from a
# legitimately member-shared resource — a forum post carries an author id but never a stranger's
# email, SSN, or balance. This is the discriminator that keeps active enumeration low-FP.
_STRONG_PII = re.compile(
    r"\b(ssn|social_security|iban|bic|swift|card_number|cardnumber|credit_card|cvv|cvc|"
    r"balance|salary|passport|tax_id|national_id|phone|phone_number|birth|dob|date_of_birth)\b"
    r"|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # an email address
    re.IGNORECASE,
)


def _has_strong_pii(body: str) -> bool:
    return _STRONG_PII.search(body) is not None


def _is_principal_id(value: str) -> bool:
    return bool(_INT_VALUE.match(value) or _UUID_VALUE.match(value) or _EMAIL.fullmatch(value))


def _owner_record_signature(body: str) -> str | None:
    """A normalized token identifying *whose* record this response carries, or None.

    Prefers an explicit owner/user/account id field whose value is a real principal identifier
    (integer, UUID, or email); falls back to the first personal email in the body. The token is
    only meaningful for *matching across sessions*: two identities that both receive the same
    signature are reading the same principal's record. The value-shape check keeps a partial or
    generic match from ever collapsing two different owners into one signature.
    """
    for match in _OWNER_ID_FIELD.finditer(body):
        value = match.group(2)
        if _is_principal_id(value):
            return f"{match.group(1).lower()}={value.lower()}"
    email = _EMAIL.search(body)
    if email is not None:
        return f"email={email.group(0).lower()}"
    return None


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


_EMAIL = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_LONG_DIGITS = re.compile(r"\d{5,}")


def _redact(text: str) -> str:
    """Mask emails and long digit runs so the impact snippet proves the leak without dumping PII."""
    text = _EMAIL.sub(lambda m: m.group(0)[0] + "***@***" + m.group(0).rsplit(".", 1)[-1], text)
    text = _LONG_DIGITS.sub(lambda m: m.group(0)[:2] + "***" + m.group(0)[-1:], text)
    return text


def _bola_impact(response: HttpResponse, marker: str) -> str:
    """A bounded, redacted window of the cross-account object this session should not have read."""
    body = " ".join(response.text.split())
    idx = body.lower().find(marker.lower())
    window = body[max(0, idx - 40) : idx + 160] if idx != -1 else body[:200]
    snippet = _redact(window).strip()
    return (
        f"Registro de otra cuenta accedido por esta sesión: «{snippet}». "
        "Demuestra que la sesión leyó el objeto de otra identidad (autorización a nivel de objeto ausente)."
    )


def _bola_finding(
    request: HttpRequest,
    response: HttpResponse,
    identities: list[str],
    marker: str,
    *,
    confirmation: str | None = None,
) -> Finding:
    path = urlsplit(request.url).path or "/"
    detail = (
        f"identical owned object (contains '{marker}') returned to multiple "
        f"identities: {', '.join(identities)}"
    )
    if confirmation is not None:
        # Owner-signature match across differing response bodies (session chrome), plus a
        # privacy proof — the record is provably access-controlled, so a second reader is a leak.
        detail = (
            f"same owned record ({marker}) returned to multiple identities "
            f"({', '.join(identities)}); {confirmation}"
        )
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
                data=detail,
                confidence="high",
            )
        ],
        request=request,
        response=response,
        impact=_bola_impact(response, marker),
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

        # BOLA: an object-scoped endpoint returns the same owned object to two different users.
        if _looks_object_scoped(probe) and len(successful) >= 2:
            fired = False

            # Path 1 — identical owned body across ≥2 identities. Fire only when the shared body
            # is *owned data* (has ownership markers); an identical body with no owner identifiers
            # is likely a public/shared resource, not a broken authorization.
            by_body: dict[str, list[Identity]] = {}
            resp_by_body: dict[str, HttpResponse] = {}
            for identity, response, body in successful:
                by_body.setdefault(body, []).append(identity)
                resp_by_body.setdefault(body, response)
            for body, ids in by_body.items():
                marker = _ownership_marker(body)
                if len(ids) >= 2 and marker is not None:
                    findings.append(_bola_finding(probe, resp_by_body[body], [i.name for i in ids], marker))
                    fired = True
                    break

            # Path 2 — the same *owned record* reaches ≥2 identities even when the surrounding
            # bodies differ (per-session chrome: CSRF tokens, "welcome <name>" nav, timestamps).
            # Group by a specific principal id (owner_id/user_id/account_id value or email) instead
            # of full-body identity. Gated on a *privacy proof*: the object must be provably
            # access-controlled — unauthenticated access or at least one identity is denied
            # (401/403/404) — so a public resource that merely echoes a constant id can't fire.
            if not fired:
                access_controlled = (
                    unauth_response is not None and unauth_response.status_code in _DENIED_STATUSES
                ) or len(successful) < len(identities)
                if access_controlled:
                    by_owner: dict[str, list[tuple[Identity, HttpResponse]]] = {}
                    for identity, response, _ in successful:
                        signature = _owner_record_signature(response.text)
                        if signature is not None:
                            by_owner.setdefault(signature, []).append((identity, response))
                    for signature, group in by_owner.items():
                        if len(group) >= 2:
                            names = [i.name for i, _ in group]
                            findings.append(
                                _bola_finding(
                                    probe,
                                    group[0][1],
                                    names,
                                    signature,
                                    confirmation="object is access-controlled (denied to another caller)",
                                )
                            )
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


# --- Active IDOR by id enumeration -------------------------------------------------------------
# The checks above are *observational*: they replay already-crawled requests across sessions. This
# one is *active* — it walks neighbouring integer ids to reach objects the crawler never saw, the
# classic manual IDOR test. See run_bola_enumeration_checks for the (heavily gated) confirmation.
_MAX_ENUM_TEMPLATES = 40
_MAX_NEIGHBORS = 5  # ids probed on each side of an observed id


def _enumerable_points(request: HttpRequest) -> list[tuple[str, str | int, int]]:
    """Integer object-id positions in a request: ('path', segment_index, value) or ('param', name, value).

    Only short integers (<=9 digits) qualify — long digit runs are epochs/codes/phone numbers, not
    enumerable object ids, and walking them wastes requests.
    """
    points: list[tuple[str, str | int, int]] = []
    segments = urlsplit(request.url).path.split("/")
    for i, seg in enumerate(segments):
        if seg.isdigit() and len(seg) <= 9:
            points.append(("path", i, int(seg)))
    for name, value in request.params.items():
        if _ID_PARAM.search(name) and str(value).isdigit() and len(str(value)) <= 9:
            points.append(("param", name, int(value)))
    return points


def _with_id(request: HttpRequest, point: tuple[str, str | int, int], new_id: int) -> HttpRequest:
    """A copy of `request` with the id at `point` replaced by `new_id` (path segment or query param)."""
    kind, key, _ = point
    if kind == "path":
        parts = urlsplit(request.url)
        segments = parts.path.split("/")
        segments[int(key)] = str(new_id)
        new_url = urlunsplit((parts.scheme, parts.netloc, "/".join(segments), parts.query, parts.fragment))
        return request.model_copy(update={"url": new_url})
    params = dict(request.params)
    params[str(key)] = str(new_id)
    return request.model_copy(update={"params": params})


def _enum_template_key(request: HttpRequest, point: tuple[str, str | int, int]) -> str:
    """Stable key that ignores the concrete id, so each endpoint template is enumerated only once."""
    kind, key, _ = point
    if kind == "path":
        parts = urlsplit(request.url)
        segments = parts.path.split("/")
        segments[int(key)] = "{id}"
        return f"{request.method} {parts.netloc}{'/'.join(segments)}"
    return f"{request.method} {urlsplit(request.url).path}?{key}={{id}}"


def _idor_enum_finding(
    request: HttpRequest,
    response: HttpResponse,
    identity: Identity,
    owners: list[str],
    tested_ids: list[int],
) -> Finding:
    path = urlsplit(request.url).path or "/"
    template = re.sub(r"/\d+", "/{id}", path)
    marker = _owner_record_signature(response.text) or "owner"
    return Finding(
        id=f"authz-idor-enum:{request.method}:{template}",
        rule_id="authz-idor-enum",
        name="Broken Object Level Authorization (IDOR via id enumeration)",
        severity="high",
        cwe="CWE-639",
        owasp="OWASP API1:2023 - BOLA",
        injection_point=_authz_point(request, "object-id"),
        evidence=[
            Evidence(
                type="differential",
                data=(
                    f"session '{identity.name}' walked object ids {tested_ids} on the "
                    f"access-controlled endpoint {template} and read personal records of multiple "
                    f"distinct owners ({', '.join(owners)}); a session may only read its own objects"
                ),
                confidence="high",
            )
        ],
        request=request,
        response=response,
        impact=_bola_impact(response, marker.split("=")[-1]),
        remediation=(
            "Enforce object-level authorization: verify the authenticated subject owns or may "
            "access the specific object id server-side on every request. Do not rely on ids being "
            "sequential-but-unguessable — treat every id as attacker-controlled."
        ),
    )


async def run_bola_enumeration_checks(
    identities: list[Identity],
    probes: list[HttpRequest],
    *,
    unauth_client: HttpClient | None = None,
    max_templates: int = _MAX_ENUM_TEMPLATES,
    max_neighbors: int = _MAX_NEIGHBORS,
) -> list[Finding]:
    """Active IDOR: on an access-controlled, integer-id GET endpoint, a single non-privileged session
    walks neighbouring ids. If it retrieves the *personal records of two or more distinct owners*,
    object-level authorization is missing — a session may only ever read its own objects.

    Low false positives by construction:

    * the endpoint must be provably access-controlled (unauthenticated access is denied), which
      excludes public catalogs;
    * each qualifying response must carry a specific principal id (owner_id/user_id/...) *and*
      strong per-user PII (email/phone/SSN/IBAN/card/balance) — a legitimately member-shared
      resource (e.g. a forum) never returns a stranger's PII, so it can't trip this;
    * confirmation requires >=2 *distinct* principals reaching one session (proving per-id records,
      not a constant self-profile) and the hit is reproduced before reporting.

    Read-only (GET) so it never changes state.
    """
    if unauth_client is None:
        return []  # no privacy oracle -> cannot prove the endpoint is access-controlled

    findings: list[Finding] = []
    seen_templates: set[str] = set()

    for probe in probes:
        if probe.method != "GET":
            continue  # enumeration must not change state
        points = _enumerable_points(probe)
        if not points:
            continue
        point = points[-1]  # the last integer id — most likely the object id, not an api version
        template = _enum_template_key(probe, point)
        if template in seen_templates:
            continue
        if len(seen_templates) >= max_templates:
            break
        seen_templates.add(template)

        # Privacy proof: the endpoint must deny unauthenticated access.
        unauth_response = await _send(unauth_client, probe)
        if unauth_response is None or unauth_response.status_code not in _DENIED_STATUSES:
            continue

        base = point[2]
        candidate_ids = [base + d for d in range(-max_neighbors, max_neighbors + 1) if base + d > 0]
        for identity in identities:
            if identity.role.lower() in PRIVILEGED_ROLES:
                continue  # an admin legitimately reads many owners' objects
            owners: dict[str, tuple[int, HttpResponse]] = {}
            for cid in candidate_ids:
                response = await _send(identity.client, _with_id(probe, point, cid))
                if response is None or not _is_success(response.status_code):
                    continue
                signature = _owner_record_signature(response.text)
                if signature is not None and _has_strong_pii(response.text):
                    owners.setdefault(signature, (cid, response))
            if len(owners) < 2:
                continue
            # Reproduce one hit before reporting.
            first_sig, (first_id, first_resp) = next(iter(owners.items()))
            recheck = await _send(identity.client, _with_id(probe, point, first_id))
            if recheck is None or _owner_record_signature(recheck.text) != first_sig:
                continue
            tested = sorted(cid for _, (cid, _) in owners.items())
            findings.append(
                _idor_enum_finding(
                    _with_id(probe, point, first_id), first_resp, identity, list(owners), tested
                )
            )
            break  # one finding per endpoint template is enough

    return findings
