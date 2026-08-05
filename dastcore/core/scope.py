"""Scope enforcement.

This is the engine-level gate: every outbound request the scanner ever makes
(crawler, active scanner, OAST correlation, everything) MUST be checked with
``ScopeChecker.is_in_scope`` before it is sent. Scope is never just a config
suggestion — a request outside scope must never leave the process.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from dastcore.config import ScopeConfig


def _domain_matches(host: str, pattern: str, allow_subdomains: bool) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if host == pattern:
        return True
    if allow_subdomains and host.endswith("." + pattern):
        return True
    return False


class ScopeChecker:
    """Allow/deny enforcement for a single scan. Deny always wins over allow."""

    def __init__(self, scope: ScopeConfig) -> None:
        self._scope = scope

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
                return False

        if self._scope.allowed_ports is not None and port not in self._scope.allowed_ports:
            return False

        for pattern in self._scope.allow_domains:
            if _domain_matches(host, pattern, self._scope.allow_subdomains):
                return True

        return False


def is_in_scope(url: str, scope: ScopeConfig) -> bool:
    """Convenience wrapper around ``ScopeChecker`` for one-off checks."""
    return ScopeChecker(scope).is_in_scope(url)
