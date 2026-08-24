"""Web cache deception — OWASP A05 / CWE-525.

Trick a caching layer into storing an authenticated page under a static-looking URL, then read it back
**anonymously**. The classic path-confusion: request ``/account/dcXXXX.css`` — the app ignores the extra
segment and serves ``/account`` (the victim's data), but the cache stores it by the ``.css`` extension.
An attacker who then fetches the same URL without a session gets the victim's cached page.

Needs authentication (an ``auth`` client with a session) and an anonymous client. Zero-FP, three-step
proof: (1) the page is actually auth-gated (auth content ≠ anon content); (2) the ``.css`` URL serves the
*authenticated* page when authenticated (path confusion); (3) the **same URL, fetched anonymously**,
returns that authenticated content — i.e. it was cached and served cross-user. Only then is it reported.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.validation.baseline import similarity_ratio

_SIMILAR = 0.9      # bodies at least this similar are "the same page"
_DIFFERENT = 0.6    # bodies below this are "clearly different pages"
_STATIC_EXT = (".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map", ".json")
_MAX_PAGES = 8


async def _get(client: HttpClient, url: str) -> HttpResponse | None:
    try:
        return await client.get(url, timeout=8.0, retries=0)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _candidates(requests: list[HttpRequest]) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for req in requests:
        if req.method != "GET":
            continue
        path = urlsplit(req.url).path
        if path.lower().endswith(_STATIC_EXT):
            continue  # already a static asset — no page to confuse
        base = f"{urlsplit(req.url).scheme}://{urlsplit(req.url).netloc}{path}"
        if base not in seen:
            seen.add(base)
            urls.append(base)
    return urls[:_MAX_PAGES]


async def run_cache_deception_checks(
    auth: HttpClient, anon: HttpClient, requests: list[HttpRequest]
) -> list[Finding]:
    """Flag authenticated pages that a cache stores and serves anonymously via path confusion (A05)."""
    findings: list[Finding] = []
    for page in _candidates(requests):
        auth_base = await _get(auth, page)
        anon_base = await _get(anon, page)
        if auth_base is None or anon_base is None or auth_base.status_code >= 400:
            continue
        # (1) the page must be auth-gated: authenticated content clearly differs from anonymous.
        if similarity_ratio(auth_base.text, anon_base.text) > _DIFFERENT:
            continue

        for ext in (".css", ".js"):
            marker = f"dc{secrets.token_hex(6)}{ext}"
            trick_url = f"{page.rstrip('/')}/{marker}"
            auth_trick = await _get(auth, trick_url)
            # (2) path confusion: the .css URL serves the authenticated page when authenticated.
            if auth_trick is None or auth_trick.status_code >= 400:
                continue
            if similarity_ratio(auth_trick.text, auth_base.text) < _SIMILAR:
                continue
            # (3) the SAME url fetched anonymously returns the authenticated content → cached cross-user.
            anon_trick = await _get(anon, trick_url)
            if anon_trick is None:
                continue
            served_authed = similarity_ratio(anon_trick.text, auth_base.text) >= _SIMILAR
            still_anon = similarity_ratio(anon_trick.text, anon_base.text) >= _SIMILAR
            if served_authed and not still_anon:
                findings.append(_finding(page, trick_url, auth_trick))
                break  # one finding per page
    return findings


def _finding(page: str, trick_url: str, response: HttpResponse) -> Finding:
    path = urlsplit(page).path or "/"
    request = HttpRequest(method="GET", url=trick_url)
    return Finding(
        id=f"web-cache-deception:GET:{path}",
        rule_id="web-cache-deception",
        name="Web cache deception (authenticated page cached and served anonymously)",
        severity="high",
        cwe="CWE-525",
        owasp="WSTG-ATHZ-05",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
        family="cache-deception",
        injection_point=InjectionPoint(location="path", name="path", base_value=path, request_template=request),  # type: ignore[arg-type]
        evidence=[Evidence(
            type="differential",
            data=(f"{page} is auth-gated, yet {trick_url} served the authenticated page and the SAME URL "
                  "fetched with no session returned that same authenticated content — the cache stored a "
                  "victim's page under the static-looking URL and serves it to anonymous users")[:280],
            confidence="high",
        )],
        request=request,
        response=response,
        remediation=(
            "No caches respuestas autenticadas: fija `Cache-Control: private, no-store` en páginas con "
            "datos de usuario. Normaliza la ruta antes de servir (no ignores segmentos extra), y que la "
            "caché/CDN cachee por Content-Type real, no por la extensión de la URL."
        ),
    )
