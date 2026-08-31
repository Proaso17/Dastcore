"""The bug-bounty ``Program`` model — an authorized scope + limits, mapped onto ``ScanConfig``.

Everything an autonomous hunt is *allowed* to touch lives here. The scope is expressed the way bounty
programs write it (``*.target.com`` wildcards, exact domains, CIDR ranges, plus an out-of-scope list)
and flattened into the existing ``ScopeConfig`` pattern lists — the engine-level ``ScopeChecker`` already
understands wildcards and CIDR, so no new enforcement path is introduced. Out-of-scope always wins.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from dastcore.config import AuthConfig, RateLimitConfig, ScanConfig, ScopeConfig

Platform = Literal["hackerone", "bugcrowd", "intigriti", "immunefi", "self"]


class ProgramScope(BaseModel):
    """The program's declared scope. Patterns are matched by ``ScopeChecker`` (wildcard + CIDR aware)."""

    domains: list[str] = Field(default_factory=list)  # exact hosts, e.g. target.com
    wildcards: list[str] = Field(default_factory=list)  # e.g. *.target.com (subdomains, not the apex)
    cidrs: list[str] = Field(default_factory=list)  # e.g. 10.0.0.0/8
    out_of_scope: list[str] = Field(default_factory=list)  # deny list (domains / wildcards / CIDR)

    def allow_patterns(self) -> list[str]:
        return [*self.domains, *self.wildcards, *self.cidrs]


class ProgramLimits(BaseModel):
    """Behavioural limits the program imposes on us."""

    requests_per_second: float = Field(default=5.0, gt=0)
    max_concurrency: int = Field(default=5, gt=0)
    # Some programs forbid automated/active scanning — this hard-disables the active scanner
    # for the whole hunt (recon + passive only). Enforced by the campaign runner (Phase 11).
    no_automated_scanning: bool = False
    # Per-host / per-endpoint RoE caps (None = off), enforced by the RateGovernor on every request:
    per_host_rps: float | None = None  # no single host is hit faster than this
    per_endpoint_daily_cap: int | None = None  # max requests/day/endpoint, persisted across runs


class Program(BaseModel):
    """An authorized bug-bounty program and its scope/limits."""

    platform: Platform = "self"
    handle: str
    policy_url: str | None = None
    scope: ProgramScope = Field(default_factory=ProgramScope)
    limits: ProgramLimits = Field(default_factory=ProgramLimits)
    # How to connect: route the hunt via a proxy/VPN (exit from a trusted IP, past WAF IP-reputation
    # blocks) and/or send a specific User-Agent (pair with a cf_clearance cookie). Empty = defaults.
    proxy: str = ""
    user_agent: str = ""
    # Session cookies sent on every request — a WAF-clearance token (cf_clearance) and/or a logged-in
    # session, so the hunt reaches the real app behind Cloudflare/auth. Paired with user_agent + proxy.
    cookies: dict[str, str] = Field(default_factory=dict)
    # Bug-bounty mode: suppress hardening/disclosure/no-impact findings the program would close as N/A,
    # so the hunt's report shows only the potentially-reportable findings.
    bug_bounty_mode: bool = False
    # Attribution / required headers the program asks for on every request (many require an identifying
    # header). Empty = auto-add ``X-Bug-Bounty: <platform>-<handle>`` for a real-platform program.
    required_headers: dict[str, str] = Field(default_factory=dict)
    seeds: list[str] = Field(default_factory=list)  # root domains/URLs recon starts from
    payouts: dict[str, float] = Field(default_factory=dict)  # per vuln-class expected payout (Phase 12)

    def allows_active_scanning(self) -> bool:
        """False when the program forbids automated scanning — the campaign must stay recon/passive."""
        return not self.limits.no_automated_scanning

    def attribution_headers(self) -> dict[str, str]:
        """Headers that identify the researcher's traffic, as many programs require. Uses
        ``required_headers`` if set; otherwise a default ``X-Bug-Bounty: <platform>-<handle>`` for a
        real-platform program (never for a private ``self`` target)."""
        if self.required_headers:
            return dict(self.required_headers)
        if self.platform != "self" and self.handle:
            return {"X-Bug-Bounty": f"{self.platform}-{self.handle}"}
        return {}

    def to_scope_config(self) -> ScopeConfig:
        """Flatten the program scope into the engine's allow/deny pattern lists."""
        return ScopeConfig(
            allow_domains=self.scope.allow_patterns(),
            deny_domains=list(self.scope.out_of_scope),
            allow_subdomains=True,
        )

    def to_scan_config(self, target: str, *, authorized: bool) -> ScanConfig:
        """Build a per-target ``ScanConfig`` under this program's scope and rate limits.

        ``authorized`` carries the operator's explicit ``--i-have-authorization`` through — a loaded
        program never bypasses the legal gate on its own.
        """
        return ScanConfig(
            target=target,  # type: ignore[arg-type]
            scope=self.to_scope_config(),
            auth=AuthConfig(type="cookie", cookies=dict(self.cookies)) if self.cookies else AuthConfig(),
            rate_limit=RateLimitConfig(
                requests_per_second=self.limits.requests_per_second,
                max_concurrency=self.limits.max_concurrency,
                per_host_rps=self.limits.per_host_rps,
                per_endpoint_daily_cap=self.limits.per_endpoint_daily_cap,
            ),
            i_have_authorization=authorized,
        )
