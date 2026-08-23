"""Scan configuration models.

Every scan is driven by a validated ``ScanConfig`` instance. Nothing in the
engine should read raw dicts or environment variables directly — config
flows in through these pydantic models so it is validated once, at the edge.
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, HttpUrl, model_validator

Severity = Literal["info", "low", "medium", "high", "critical"]


class ScopeConfig(BaseModel):
    """Allow/deny rules enforced by ``dastcore.core.scope`` before any request is sent."""

    allow_domains: list[str] = Field(default_factory=list)
    deny_domains: list[str] = Field(default_factory=list)
    allow_subdomains: bool = True
    allowed_ports: list[int] | None = None


class FormLoginConfig(BaseModel):
    """Form-based login: POST credentials to a URL, then reuse the resulting session cookie
    (and/or a token pulled from the JSON response) on every subsequent request."""

    login_url: str
    credentials: dict[str, str] = Field(default_factory=dict)
    as_json: bool = True
    # Extra headers on the login request itself (e.g. an IdP API key: Supabase's `apikey`).
    login_headers: dict[str, str] = Field(default_factory=dict)
    # If set, pull a token out of the JSON login response instead of relying on a cookie.
    token_json_field: str | None = None
    token_header: str = "Authorization"
    token_prefix: str = "Bearer "


class OAuth2Config(BaseModel):
    """OAuth2 client-credentials grant: exchange client id/secret for a bearer token."""

    token_url: str
    client_id: str
    client_secret: str
    scope: str | None = None
    as_json: bool = False
    token_json_field: str = "access_token"
    token_header: str = "Authorization"
    token_prefix: str = "Bearer "


class OAuth2PkceConfig(BaseModel):
    """OAuth2 authorization-code grant with PKCE (RFC 7636), driven headlessly.

    The scanner establishes an IdP session (optional ``login_url`` + credentials), calls the
    authorization endpoint with a freshly generated ``code_challenge`` (S256), captures the
    ``code`` from the redirect, and exchanges it at the token endpoint with the matching
    ``code_verifier`` for a bearer token. ``client_secret`` is optional (public clients)."""

    authorize_url: str
    token_url: str
    client_id: str
    redirect_uri: str
    client_secret: str | None = None
    scope: str | None = None
    # Optional IdP login POSTed before the authorize call to establish a session cookie.
    login_url: str | None = None
    login_credentials: dict[str, str] = Field(default_factory=dict)
    login_as_json: bool = False
    token_json_field: str = "access_token"
    token_header: str = "Authorization"
    token_prefix: str = "Bearer "


class AuthConfig(BaseModel):
    """How the scanner authenticates. Static types (cookie/header/bearer) carry the material
    directly; ``form``/``oauth2`` log in dynamically and can re-login when the session drops."""

    type: Literal["none", "cookie", "header", "bearer", "form", "oauth2", "oauth2_pkce", "macro"] = "none"
    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    bearer_token: str | None = None
    form: FormLoginConfig | None = None
    oauth2: OAuth2Config | None = None
    oauth2_pkce: OAuth2PkceConfig | None = None
    # Browser login macro (type "macro"): a recorded JS-login replayed headlessly to get
    # the session cookies. `macro_runtime` fills `{{name}}` placeholders (password/OTP).
    macro_path: str = ""
    macro_runtime: dict[str, str] = Field(default_factory=dict)

    # Dropped-session detection: a response matching either signal triggers an auto re-login.
    logged_out_status: int = 401
    logged_out_pattern: str | None = None
    # Long deep scans outlive a short-lived token (e.g. a ~1h Supabase JWT), so allow many
    # automatic re-logins — one per expiry — not just a handful. Still bounded to catch a broken
    # login loop. Concurrent expiries coalesce into a single re-login (epoch-guarded).
    max_relogin: int = 20

    @model_validator(mode="after")
    def _require_flow_config_for_dynamic_types(self) -> AuthConfig:
        if self.type == "form" and self.form is None:
            raise ValueError("auth.type 'form' requires auth.form to be set")
        if self.type == "oauth2" and self.oauth2 is None:
            raise ValueError("auth.type 'oauth2' requires auth.oauth2 to be set")
        if self.type == "oauth2_pkce" and self.oauth2_pkce is None:
            raise ValueError("auth.type 'oauth2_pkce' requires auth.oauth2_pkce to be set")
        if self.type == "macro" and not self.macro_path:
            raise ValueError("auth.type 'macro' requires auth.macro_path to be set")
        return self


class Identity(BaseModel):
    """One authenticated actor for authorization testing (BOLA/BFLA).

    Multiple identities with different roles let the scanner compare who can access
    what: e.g. can user B read user A's object, or can a plain user hit an admin route.
    """

    name: str
    role: str = "user"
    auth: AuthConfig = Field(default_factory=AuthConfig)


class RateLimitConfig(BaseModel):
    requests_per_second: float = Field(default=5.0, gt=0)
    max_concurrency: int = Field(default=5, gt=0)
    timeout: float = Field(default=10.0, gt=0)  # per-request timeout (s); lower it for slow targets
    max_retries: int = Field(default=2, ge=0)  # transport retries; lower it to avoid dragging on a slow host


class OastConfig(BaseModel):
    enabled: bool = False
    provider: Literal["interactsh"] = "interactsh"
    server_url: str | None = None


class OutputConfig(BaseModel):
    format: Literal["json", "sarif", "html"] = "json"
    path: str | None = None
    severity_threshold: Severity = "low"


class ScanFile(BaseModel):
    """A scan described in a YAML/JSON file (`dastcore scan --config scan.yaml`).

    Every field is optional; explicit CLI flags override whatever the file sets, so a
    file can hold the stable parts (scope, auth, identities) while flags tweak a run.
    """

    model_config = {"extra": "forbid"}

    target: str | None = None
    allow_domains: list[str] | None = None
    deny_domains: list[str] | None = None
    auth: AuthConfig | None = None
    identities: list[Identity] | None = None
    engine: str | None = None
    oast: str | None = None
    oast_server: str | None = None
    profile: str | None = None
    rps: float | None = None
    concurrency: int | None = None
    max_pages: int | None = None
    max_requests: int | None = None
    time_budget: float | None = None
    openapi: str | None = None
    graphql: str | None = None
    format: str | None = None
    output: str | None = None
    fail_on: str | None = None


class ScanConfig(BaseModel):
    """Root configuration object for a single scan run."""

    target: HttpUrl
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    identities: list[Identity] = Field(default_factory=list)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    oast: OastConfig = Field(default_factory=OastConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    i_have_authorization: bool = False

    @model_validator(mode="after")
    def _ensure_target_host_in_scope(self) -> ScanConfig:
        """The target's own host is always in scope, regardless of --allow-domain.

        --allow-domain only ever *widens* scope (e.g. to reach a secondary API host);
        it must never be able to accidentally exclude the target being scanned.
        """
        host = urlsplit(str(self.target)).hostname
        if host and host not in self.scope.allow_domains:
            self.scope.allow_domains = [*self.scope.allow_domains, host]
        return self
