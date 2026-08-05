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
import json
import re
from typing import TYPE_CHECKING

from dastcore.config import AuthConfig

if TYPE_CHECKING:
    from dastcore.core.http_client import HttpClient


class SessionError(RuntimeError):
    """Raised when a dynamic login flow cannot establish a session at all."""


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
        return self._auth.type in ("form", "oauth2")

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
        return False

    async def _form_login(self, client: HttpClient) -> bool:
        cfg = self._auth.form
        assert cfg is not None
        response = await client.send_raw(
            "POST",
            cfg.login_url,
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


def _extract_json_field(text: str, field: str) -> str | None:
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(payload, dict) and field in payload:
        return str(payload[field])
    return None
