"""Weak / default credentials on a login form. CWE-1391 / CWE-287, OWASP A07:2021.

Tries a small list of well-known default credential pairs against the login endpoint and reports one
only when it clearly *authenticates* — a login attempt is accepted when it sets a session cookie that a
deliberately-invalid attempt did not, or redirects somewhere different from the invalid attempt. Those
are strong success signals, so a login form that rejects everything (or ignores the fields entirely) is
never flagged. Intrusive (it submits login attempts, which may count against lockout), so it is behind
``--test-weak-creds`` and off in the ``quick`` profile.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urlsplit

import httpx

from dastcore.config import FormLoginConfig
from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_SESSION_NAME = re.compile(r"(session|sess|sid|jsessionid|phpsessid|connect\.sid|laravel_session|auth|token)", re.I)
_NOT_SESSION = re.compile(r"(csrf|xsrf|_ga|_gid|consent|locale|lang|theme|timezone)", re.I)
_REDIRECTS = {301, 302, 303, 307, 308}
_MAX_ATTEMPTS = 40

_COMMON_PAIRS = [
    ("username", "password"),
    ("user", "pass"),
    ("email", "password"),
    ("login", "passwd"),
    ("j_username", "j_password"),
]
_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("admin", ""),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
]


def _session_names(cookies: dict[str, str]) -> set[str]:
    return {k for k in cookies if _SESSION_NAME.search(k) and not _NOT_SESSION.search(k)}


def _location(response: HttpResponse) -> str:
    for key, value in response.headers.items():
        if key.lower() == "location":
            return value
    return ""


async def _login(client: HttpClient, cfg: FormLoginConfig, body: dict[str, str]) -> HttpResponse | None:
    try:
        return await client.send_raw(
            "POST",
            cfg.login_url,
            json=body if cfg.as_json else None,
            data=None if cfg.as_json else body,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _accepted(resp: HttpResponse, bad: HttpResponse) -> bool:
    """True only on a strong authentication signal the invalid attempt did not produce."""
    if _session_names(resp.cookies) - _session_names(bad.cookies):
        return True  # login set a session cookie the invalid attempt didn't
    if resp.status_code in _REDIRECTS and _location(resp) != _location(bad):
        return True  # redirected somewhere the invalid attempt didn't (e.g. a dashboard)
    return False


def _finding(cfg: FormLoginConfig, u_field: str, p_field: str, user: str, password: str) -> Finding:
    path = urlsplit(cfg.login_url).path or "/"
    request = HttpRequest(method="POST", url=cfg.login_url, data={u_field: user, p_field: password})
    shown = password or "(vacía)"
    return Finding(
        id=f"default-credentials:POST:{path}:{user}",
        rule_id="default-credentials",
        name="Credenciales débiles o por defecto aceptadas",
        severity="critical",
        cwe="CWE-1391",
        owasp="A07:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        family="auth",
        injection_point=InjectionPoint(location="body", name=u_field, base_value=user, request_template=request),
        evidence=[
            Evidence(
                type="differential",
                data=(
                    f"el login aceptó credenciales por defecto {u_field}={user} / {p_field}={shown} "
                    "(estableció sesión / redirigió como un acceso válido, a diferencia de un intento inválido)"
                )[:200],
                confidence="high",
            )
        ],
        request=request,
        response=HttpResponse(status_code=200),
        remediation=(
            "Elimina las cuentas y contraseñas por defecto; obliga a cambiar la contraseña en el primer uso, "
            "aplica una política de contraseñas fuertes y limita/retrasa los intentos de login (rate-limit + "
            "bloqueo temporal) para frenar el adivinado."
        ),
    )


async def run_weak_credentials_check(client: HttpClient, cfg: FormLoginConfig) -> list[Finding]:
    """Probe the login endpoint for accepted default credentials (bounded, strong-signal only)."""
    field_pairs: list[tuple[str, str]] = []
    if len(cfg.credentials) >= 2:  # the operator told us the real field names
        keys = list(cfg.credentials)
        field_pairs.append((keys[0], keys[1]))
    field_pairs += [p for p in _COMMON_PAIRS if p not in field_pairs]

    attempts = 0
    for u_field, p_field in field_pairs:
        if attempts >= _MAX_ATTEMPTS:
            break
        bad = await _login(client, cfg, {u_field: f"dc{secrets.token_hex(4)}", p_field: secrets.token_hex(6)})
        attempts += 1
        if bad is None:
            continue
        for user, password in _DEFAULT_CREDS:
            if attempts >= _MAX_ATTEMPTS:
                break
            resp = await _login(client, cfg, {u_field: user, p_field: password})
            attempts += 1
            if resp is None or not _accepted(resp, bad):
                continue
            confirm = await _login(client, cfg, {u_field: user, p_field: password})  # reproducible
            attempts += 1
            if confirm is not None and _accepted(confirm, bad):
                return [_finding(cfg, u_field, p_field, user, password)]  # one working set is proof enough
    return []
