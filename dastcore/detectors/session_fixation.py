"""Session fixation: the session id does not change across authentication. CWE-384, OWASP A07:2021.

A secure app issues a brand-new session identifier the moment a user logs in. If the pre-auth session
id survives authentication, an attacker who *fixes* a victim's session id (planting a known cookie)
ends up sharing the victim's authenticated session once they log in.

Confirmed with a real login, and only when the login is shown to actually authenticate — we send the
correct credentials and, separately, deliberately wrong ones; unless the two responses differ (so the
endpoint really validates credentials) we abstain. When login works, we compare the session cookie a
fresh visit was assigned against its value after a successful login: if it is unchanged, the session
was not rotated. That keeps false positives near zero — a login that fails, or one we can't confirm,
is never reported.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urlsplit

import httpx

from dastcore.config import FormLoginConfig
from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.validation.baseline import similarity_ratio

_SESSION_NAME = re.compile(r"(session|sess|sid|jsessionid|phpsessid|connect\.sid|laravel_session|auth|token)", re.I)
_NOT_SESSION = re.compile(r"(csrf|xsrf|_ga|_gid|consent|locale|lang|theme|timezone)", re.I)
_DIFF = 0.95


def _is_session_cookie(name: str) -> bool:
    return bool(_SESSION_NAME.search(name)) and not _NOT_SESSION.search(name)


async def _post(
    client: HttpClient, cfg: FormLoginConfig, creds: dict[str, str], cookies: dict[str, str]
) -> HttpResponse | None:
    try:
        return await client.send_raw(
            "POST",
            cfg.login_url,
            cookies=cookies or None,
            json=creds if cfg.as_json else None,
            data=None if cfg.as_json else creds,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _finding(cfg: FormLoginConfig, name: str, value: str) -> Finding:
    path = urlsplit(cfg.login_url).path or "/"
    request = HttpRequest(method="POST", url=cfg.login_url)
    return Finding(
        id=f"session-fixation:POST:{path}:{name}",
        rule_id="session-fixation",
        name="Session fixation (la sesión no se renueva al autenticarse)",
        severity="high",
        cwe="CWE-384",
        owasp="A07:2021",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        family="auth",
        injection_point=InjectionPoint(location="cookie", name=name, base_value=value, request_template=request),
        evidence=[
            Evidence(
                type="differential",
                data=(
                    f"la cookie de sesión '{name}' mantuvo el mismo valor antes y después de un login válido — "
                    "el servidor no rota el identificador de sesión al autenticar, habilitando session fixation"
                )[:200],
                confidence="high",
            )
        ],
        request=request,
        response=HttpResponse(status_code=200),
        remediation=(
            "Regenera el identificador de sesión en el momento de autenticar (y al cambiar de privilegio): "
            "invalida la sesión previa y emite una nueva cookie de sesión. Marca la cookie como HttpOnly/Secure/"
            "SameSite y no aceptes identificadores de sesión suministrados por el cliente."
        ),
    )


async def check_session_fixation(client: HttpClient, cfg: FormLoginConfig) -> list[Finding]:
    """Report each session cookie that isn't rotated across a confirmed, successful login.

    ``client`` must be a fresh visitor (empty cookie jar); the caller opens one without a session.
    """
    try:
        pre = await client.send_raw("GET", cfg.login_url)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return []
    pre_session = {k: v for k, v in pre.cookies.items() if _is_session_cookie(k)}
    if not pre_session:
        return []  # stateless / no pre-auth session cookie -> nothing to fixate

    ok = await _post(client, cfg, cfg.credentials, pre.cookies)
    if ok is None or ok.status_code >= 400:
        return []  # login didn't succeed -> inconclusive

    # Confirm the endpoint actually validates credentials: wrong creds must produce a different result.
    wrong = {k: f"{v}{secrets.token_hex(3)}" for k, v in cfg.credentials.items()} or {"x": secrets.token_hex(4)}
    bad_pre = await client.send_raw("GET", cfg.login_url)
    bad = await _post(client, cfg, wrong, bad_pre.cookies if isinstance(bad_pre, HttpResponse) else {})
    login_authenticates = bad is not None and (
        ok.status_code != bad.status_code or similarity_ratio(ok.text, bad.text) < _DIFF
    )
    if not login_authenticates:
        return []  # can't prove the login gates on credentials -> don't claim fixation

    findings: list[Finding] = []
    for name, pre_val in pre_session.items():
        effective = ok.cookies.get(name, pre_val)  # login's re-set value, or the carried pre value
        if effective == pre_val:  # session id unchanged across authentication
            findings.append(_finding(cfg, name, pre_val))
    return findings
