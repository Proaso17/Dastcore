"""Scope enforcement.

This is the engine-level gate: every outbound request the scanner ever makes
(crawler, active scanner, OAST correlation, everything) MUST be checked with
``ScopeChecker.is_in_scope`` before it is sent. Scope is never just a config
suggestion — a request outside scope must never leave the process.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from dastcore.config import ScopeConfig


def _cidr_matches(host: str, pattern: str) -> bool:
    """True if ``host`` is an IP inside the CIDR ``pattern`` (e.g. 10.0.0.0/8)."""
    if "/" not in pattern:
        return False
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return False


def _domain_matches(host: str, pattern: str, allow_subdomains: bool) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if _cidr_matches(host, pattern):  # IP-in-range (bug-bounty CIDR scope)
        return True
    if pattern.startswith("*."):  # explicit wildcard: *.x matches subdomains of x, not the apex
        return host.endswith(pattern[1:])
    if host == pattern:
        return True
    if allow_subdomains and host.endswith("." + pattern):
        return True
    return False


def _endpoint_key(url: str) -> str:
    """scheme://host/path (lowercased, no query) — the identity used to exempt an auth endpoint."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{(parts.hostname or '').lower()}{parts.path or ''}".rstrip("/")


class ScopeChecker:
    """Allow/deny enforcement for a single scan. Deny always wins over allow."""

    def __init__(self, scope: ScopeConfig, auth_urls: list[str] | None = None) -> None:
        self._scope = scope
        # Auth/IdP endpoints the session manager may reach to (re)authenticate, even if their host
        # isn't in the attack scope. Exact scheme+host+path only — never opens the IdP to scanning.
        self._auth_endpoints = {_endpoint_key(u) for u in (auth_urls or [])}

    def is_in_scope(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
        except ValueError:
            return False

        if parts.scheme not in ("http", "https"):
            return False

        host = parts.hostname
        if not host:
            return False

        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError:
            return False

        for pattern in self._scope.deny_domains:
            if _domain_matches(host, pattern, self._scope.allow_subdomains):
                return False  # deny always wins, even for an auth endpoint

        # A configured auth endpoint is reachable for (re)login regardless of the attack scope.
        if self._auth_endpoints and _endpoint_key(url) in self._auth_endpoints:
            return True

        if self._scope.allowed_ports is not None and port not in self._scope.allowed_ports:
            return False

        for pattern in self._scope.allow_domains:
            if _domain_matches(host, pattern, self._scope.allow_subdomains):
                return True

        return False

    def is_asset_in_scope(self, host_or_ip: str) -> bool:
        """Scope check for a bare host or IP (recon assets, which have no URL/port yet).

        Same deny-wins-over-allow, deny-by-default rule as ``is_in_scope`` — every discovered
        asset must pass this before it is ever stored or probed."""
        host = (host_or_ip or "").strip().lower().rstrip(".")
        if not host:
            return False
        for pattern in self._scope.deny_domains:
            if _domain_matches(host, pattern, self._scope.allow_subdomains):
                return False
        return any(
            _domain_matches(host, pattern, self._scope.allow_subdomains) for pattern in self._scope.allow_domains
        )


def is_in_scope(url: str, scope: ScopeConfig) -> bool:
    """Convenience wrapper around ``ScopeChecker`` for one-off checks."""
    return ScopeChecker(scope).is_in_scope(url)
