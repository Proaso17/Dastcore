"""Active detector: CSRF token not enforced.

A structural "this form has no token" check is guesswork — plenty of token-less endpoints are
safe (bearer auth, SameSite cookies, custom-header checks). So instead of guessing, this uses
a **runtime oracle**: take a state-changing request that *does* carry an anti-CSRF token,
replay it with the token stripped (and a foreign ``Origin``), and see whether the action still
succeeds. If it does — and the response matches the legitimate one — the token is decorative:
the server never verified it, which is exactly the CSRF weakness. A server that enforces the
token rejects the replay (different status/body) and is never flagged.

Intrusive and stateful (it re-issues a write), so it only runs behind ``--test-csrf`` and
never in the ``quick`` profile.

CWE-352 (Cross-Site Request Forgery) / OWASP WSTG-SESS-05.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.validation.baseline import similarity_ratio

_SIMILAR = 0.95
_FOREIGN_ORIGIN = "https://dastcore-attacker.test"
# Common anti-CSRF token field names (lowercased, substring match).
_TOKEN_HINTS = (
    "csrf",
    "xsrf",
    "_token",
    "authenticity_token",
    "requestverificationtoken",
    "anti_forgery",
    "antiforgery",
    "request_token",
    "nonce",
)


def _is_token_field(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _TOKEN_HINTS)


def _token_fields(request: HttpRequest) -> list[str]:
    fields: list[str] = [k for k in (request.data or {}) if _is_token_field(k)]
    if isinstance(request.json_body, dict):
        fields += [k for k in request.json_body if _is_token_field(k)]
    return fields


def _strip_tokens(request: HttpRequest, tokens: list[str]) -> HttpRequest:
    """A copy with the token fields removed and a foreign Origin / no Referer (a cross-site POST)."""
    data = {k: v for k, v in (request.data or {}).items() if k not in tokens} if request.data else None
    json_body = request.json_body
    if isinstance(json_body, dict):
        json_body = {k: v for k, v in json_body.items() if k not in tokens}
    headers = {k: v for k, v in request.headers.items() if k.lower() != "referer"}
    headers["Origin"] = _FOREIGN_ORIGIN
    return request.model_copy(update={"data": data, "json_body": json_body, "headers": headers})


def _similar(a: HttpResponse, b: HttpResponse) -> bool:
    return a.status_code == b.status_code and similarity_ratio(a.text, b.text) >= _SIMILAR


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


async def check_csrf(client: HttpClient, request: HttpRequest) -> list[Finding]:
    """Confirm a carried CSRF token is not actually enforced on this state-changing request."""
    if request.method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
        return []
    tokens = _token_fields(request)
    if not tokens:
        return []  # no token to test enforcement of — avoid structural guessing

    baseline = await _send(client, request)
    if baseline is None or baseline.status_code >= 400:
        return []  # the request as given doesn't succeed → can't establish the action works

    stripped = _strip_tokens(request, tokens)
    attack = await _send(client, stripped)
    if attack is None or attack.status_code >= 400 or not _similar(baseline, attack):
        return []  # token enforced (replay rejected or diverged) → not vulnerable

    repro = await _send(client, stripped)
    if repro is None or not _similar(baseline, repro):
        return []  # unstable → treat as noise

    path = urlsplit(request.url).path or "/"
    return [
        Finding(
            id=f"csrf:{request.method}:{path}",
            rule_id="csrf-token-not-enforced",
            name="CSRF: anti-forgery token not enforced",
            severity="medium",
            cwe="CWE-352",
            owasp="WSTG-SESS-05",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            family="csrf",
            injection_point=InjectionPoint(location="body", name=tokens[0], base_value="", request_template=request),
            evidence=[
                Evidence(
                    type="differential",
                    data=(
                        f"removing the '{tokens[0]}' token (with a foreign Origin) still completed the "
                        f"{request.method} {path} action (HTTP {attack.status_code}, same as the legitimate "
                        "request) — the anti-CSRF token is present but not verified server-side"
                    )[:200],
                    confidence="high",
                )
            ],
            request=stripped,
            response=attack,
            remediation=(
                "Verifica el token anti-CSRF en el servidor en cada petición que cambie estado y rechaza la "
                "petición si falta o no coincide. Refuerza con cookies `SameSite=Lax/Strict` y validación de "
                "`Origin`/`Referer`. No basta con emitir el token: hay que comprobarlo."
            ),
        )
    ]


async def run_csrf_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Run the CSRF-enforcement check over every token-bearing state-changing request, deduped."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for request in requests:
        signature = request.signature()
        if signature in seen:
            continue
        seen.add(signature)
        findings.extend(await check_csrf(client, request))
    return findings
