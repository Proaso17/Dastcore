"""Shared HTTP security headers for dastcore's own FastAPI apps.

A vulnerability scanner shouldn't ship apps that fail its own passive checks. This
sets the baseline response headers (clickjacking, MIME-sniffing, CSP, referrer) on
both the local dashboard and the cloud control-plane. The CSP allows inline
script/style because those UIs are intentionally self-contained (no external assets);
a stricter nonce-based policy is the natural next step.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI

_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


def add_security_headers(app: FastAPI) -> None:
    """Attach a middleware that sets security headers on every response."""

    @app.middleware("http")
    async def _security_headers(request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Content-Security-Policy", _CSP)
        # Don't advertise the server stack (reduces fingerprinting).
        response.headers["Server"] = "dastcore"
        return response
