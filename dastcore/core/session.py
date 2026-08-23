"""Authentication / session management.

A `SessionManager` owns the current auth material (cookies + headers) and knows
how to (re)establish it. Static auth types (cookie/header/bearer) carry their
material from config and never change. Dynamic types (form-login, OAuth2
client-credentials) log in over the network and can *re-login* automatically
when a response signals the session was dropped.

The `HttpClient` injects a session's material into every outgoing request and,
on a dropped-session signal, asks the session to re-login and retries once.
Re-login is serialized and epoch-guarded so a burst of concurrent requests that
all see the same expiry triggers exactly one re-login, not one per request.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import secrets
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

from dastcore.config import AuthConfig

if TYPE_CHECKING:
    from dastcore.core.http_client import HttpClient


class SessionError(RuntimeError):
    """Raised when a dynamic login flow cannot establish a session at all."""


def auth_endpoint_urls(auth: AuthConfig) -> list[str]:
    """The IdP URLs a dynamic login flow must reach (login/token/authorize).

    These are exempt from the *attack* scope: the scanner must be able to authenticate against an
    identity provider on another host (e.g. a Supabase project) without that host becoming a scan
    target. Only these exact endpoints are reachable — nothing else on the IdP host is scanned.
    """
    urls: list[str] = []
    if auth.form is not None and auth.form.login_url:
        urls.append(auth.form.login_url)
    if auth.oauth2 is not None and auth.oauth2.token_url:
        urls.append(auth.oauth2.token_url)
    if auth.oauth2_pkce is not None:
        urls.extend(u for u in (auth.oauth2_pkce.login_url, auth.oauth2_pkce.authorize_url,
                                auth.oauth2_pkce.token_url) if u)
    return urls


class SessionManager:
    """Holds and refreshes the auth material applied to every scanner request."""

    def __init__(self, auth: AuthConfig) -> None:
        self._auth = auth
        self.cookies: dict[str, str] = dict(auth.cookies)
        self.headers: dict[str, str] = dict(auth.headers)

        if auth.type == "bearer" and auth.bearer_token:
            self.headers["Authorization"] = f"Bearer {auth.bearer_token}"

        self._epoch = 0
        self._relogin_count = 0
        self._lock = asyncio.Lock()
        # Static material is "established" the moment we have any of it; dynamic flows
        # only become established once their first login succeeds.
        self._established = auth.type in ("cookie", "header", "bearer") and bool(self.cookies or self.headers)

    @property
    def epoch(self) -> int:
        """Bumps on every successful (re)login; used to coalesce concurrent re-logins."""
        return self._epoch

    @property
    def can_relogin(self) -> bool:
        return self._auth.type in ("form", "oauth2", "oauth2_pkce", "macro")

    @property
    def is_established(self) -> bool:
        return self._established

    def apply(self, headers: dict[str, str] | None) -> dict[str, str]:
        """Merge session headers under any per-request overrides (explicit values win).

        Cookies are not injected here: static cookies seed the HttpClient's cookie jar
        once, and dynamically-obtained session cookies (form-login) are persisted by the
        jar automatically. Only header material (bearer/oauth2 tokens, custom headers) is
        applied per request.
        """
        return {**self.headers, **(headers or {})}

    def is_expired(self, response) -> bool:
        if not self._established or self._auth.type == "none":
            return False
        if response.status_code == self._auth.logged_out_status:
            return True
        if self._auth.logged_out_pattern and re.search(self._auth.logged_out_pattern, response.text):
            return True
        return False

    async def ensure_logged_in(
        self, client: HttpClient, *, seen_epoch: int | None = None, initial: bool = False
    ) -> bool:
        """(Re)establish the session. Returns whether usable auth material now exists.

        `seen_epoch` lets a caller say "I saw expiry at epoch N": if the session has
        already advanced past N (another task re-logged in), we simply report success
        without a redundant login. `initial=True` marks the first login and is exempt
        from the `max_relogin` budget.
        """
        if not self.can_relogin:
            return self._established

        async with self._lock:
            if seen_epoch is not None and seen_epoch != self._epoch:
                return True
            if not initial and self._relogin_count >= self._auth.max_relogin:
                return False

            success = await self._perform_login(client)
            if success:
                self._epoch += 1
                self._established = True
                if not initial:
                    self._relogin_count += 1
            return success

    async def _perform_login(self, client: HttpClient) -> bool:
        if self._auth.type == "form":
            return await self._form_login(client)
        if self._auth.type == "oauth2":
            return await self._oauth2_login(client)
        if self._auth.type == "oauth2_pkce":
            return await self._oauth2_pkce_login(client)
        if self._auth.type == "macro":
            return await self._macro_login(client)
        return False

    async def _macro_login(self, client: HttpClient) -> bool:
        """Replay a recorded browser login macro headlessly and adopt its session cookies."""
        from dastcore.auth.recorder import load_macro, replay_macro
        from dastcore.discovery.crawler_headless import HeadlessUnavailableError

        try:
            cookies = await replay_macro(load_macro(self._auth.macro_path), runtime=self._auth.macro_runtime)
        except (HeadlessUnavailableError, OSError):
            return False
        if not cookies:
            return False
        self.cookies.update(cookies)
        client.set_cookies(cookies)
        return True

    async def _form_login(self, client: HttpClient) -> bool:
        cfg = self._auth.form
        assert cfg is not None
        response = await client.send_raw(
            "POST",
            cfg.login_url,
            headers=cfg.login_headers or None,
            json=cfg.credentials if cfg.as_json else None,
            data=None if cfg.as_json else cfg.credentials,
        )
        if response.status_code >= 400:
            return False

        self.cookies.update(response.cookies)

        if cfg.token_json_field:
            token = _extract_json_field(response.text, cfg.token_json_field)
            if token is None:
                return False
            self.headers[cfg.token_header] = f"{cfg.token_prefix}{token}"

        return bool(response.cookies) or cfg.token_json_field is not None

    async def _oauth2_login(self, client: HttpClient) -> bool:
        cfg = self._auth.oauth2
        assert cfg is not None
        body: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret,
        }
        if cfg.scope:
            body["scope"] = cfg.scope

        response = await client.send_raw(
            "POST",
            cfg.token_url,
            json=body if cfg.as_json else None,
            data=None if cfg.as_json else body,
        )
        if response.status_code >= 400:
            return False

        token = _extract_json_field(response.text, cfg.token_json_field)
        if token is None:
            return False
        self.headers[cfg.token_header] = f"{cfg.token_prefix}{token}"
        return True

    async def _oauth2_pkce_login(self, client: HttpClient) -> bool:
        """OAuth2 authorization-code + PKCE (RFC 7636), driven headlessly.

        Establish an IdP session (optional), call the authorize endpoint with a fresh S256
        challenge, capture the ``code`` from the redirect, and exchange it with the matching
        verifier. The redirect is *not* followed (the client defaults to no-follow), so the
        code is read straight from the ``Location`` header — the redirect_uri host is never hit.
        """
        cfg = self._auth.oauth2_pkce
        assert cfg is not None
        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(16)

        if cfg.login_url:  # establish an IdP session cookie so authorize can issue a code
            login = await client.send_raw(
                "POST",
                cfg.login_url,
                json=cfg.login_credentials if cfg.login_as_json else None,
                data=None if cfg.login_as_json else cfg.login_credentials,
            )
            if login.status_code >= 400:
                return False
            self.cookies.update(login.cookies)

        authorize_params = {
            "response_type": "code",
            "client_id": cfg.client_id,
            "redirect_uri": cfg.redirect_uri,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if cfg.scope:
            authorize_params["scope"] = cfg.scope
        authorized = await client.send_raw("GET", cfg.authorize_url, params=authorize_params)
        code = _code_from_redirect(authorized, state)
        if code is None:
            return False

        exchange = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": cfg.redirect_uri,
            "client_id": cfg.client_id,
            "code_verifier": verifier,
        }
        if cfg.client_secret:
            exchange["client_secret"] = cfg.client_secret
        token_response = await client.send_raw("POST", cfg.token_url, data=exchange)
        if token_response.status_code >= 400:
            return False
        token = _extract_json_field(token_response.text, cfg.token_json_field)
        if token is None:
            return False
        self.headers[cfg.token_header] = f"{cfg.token_prefix}{token}"
        return True


def _pkce_pair() -> tuple[str, str]:
    """A PKCE (verifier, S256 challenge) pair per RFC 7636 (base64url, no padding)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _code_from_redirect(response, expected_state: str) -> str | None:
    """Pull the authorization ``code`` from a redirect's Location, checking ``state`` first."""
    location = response.headers.get("location") or response.headers.get("Location")
    if not location:
        return None
    query = parse_qs(urlsplit(location).query)
    if expected_state and query.get("state", [None])[0] != expected_state:
        return None  # state mismatch → possible CSRF/mix-up; refuse the code
    codes = query.get("code")
    return codes[0] if codes else None


def _extract_json_field(text: str, field: str) -> str | None:
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(payload, dict) and field in payload:
        return str(payload[field])
    return None
