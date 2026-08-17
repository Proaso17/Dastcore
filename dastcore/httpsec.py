"""Shared HTTP security headers for dastcore's own FastAPI apps.

A vulnerability scanner shouldn't ship apps that fail its own passive checks. This
sets the baseline response headers (clickjacking, MIME-sniffing, CSP, referrer, and
HSTS over TLS) on both the local dashboard and the cloud control-plane. The CSP allows
inline script/style because those UIs are intentionally self-contained (no external
assets); a stricter nonce-based policy is the natural next step.

It also adds two more defenses shared by both apps: ``add_csrf_protection`` (rejects
cross-origin state-changing requests) and ``add_error_pages`` (turns any unhandled
exception into a friendly page instead of a raw stack trace, and logs it). An unhandled
500 is produced *above* the header middleware so it won't carry these headers, but it now
renders a clean page and leaks nothing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI, Request

_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'self'"
)


def is_https(request: Request) -> bool:
    """Whether the request reached us over TLS — directly or via a terminating proxy."""
    if request.url.scheme == "https":
        return True
    forwarded = request.headers.get("x-forwarded-proto", "")
    return forwarded.split(",")[0].strip().lower() == "https"


def add_security_headers(app: FastAPI) -> None:
    """Attach a middleware that sets security headers on every response."""

    @app.middleware("http")
    async def _security_headers(request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Content-Security-Policy", _CSP)
        # HSTS is only meaningful (and only valid) over HTTPS.
        if is_https(request):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        # Don't advertise the server stack (reduces fingerprinting).
        response.headers["Server"] = "dastcore"
        return response


_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def add_csrf_protection(app: FastAPI) -> None:
    """Refuse cross-origin state-changing requests (CSRF defense-in-depth).

    The CSRF-able surface is cookie-authenticated form POSTs; Bearer-token API calls are immune, since a
    browser never attaches an ``Authorization`` header on a cross-site request. A browser *does* attach an
    ``Origin`` (or at least a ``Referer``) on any cross-site POST, so when that source host doesn't match
    ours we reject. Requests carrying neither header — API clients, curl, the test transport — are left
    alone. Together with the ``SameSite=Strict`` session cookie this closes the browser CSRF vector without
    touching a single template or form field.
    """
    from urllib.parse import urlsplit

    from starlette.responses import PlainTextResponse

    @app.middleware("http")
    async def _csrf(request, call_next):  # type: ignore[no-untyped-def]
        if request.method in _UNSAFE_METHODS:
            source = request.headers.get("origin") or request.headers.get("referer")
            if source:
                src_host = urlsplit(source).netloc.lower()
                host = (request.headers.get("host") or "").lower()
                if src_host and host and src_host != host:
                    return PlainTextResponse("Cross-origin request refused (CSRF protection).", status_code=403)
        return await call_next(request)


def _error_page_html() -> str:
    """A small self-contained error page — a friendly message, never a stack trace."""
    return (
        "<!doctype html><html lang='es'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>dastcore — error</title><style>"
        "body{font:16px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;"
        "background:#f6f7f9;color:#1a1d21;margin:0;display:grid;place-items:center;min-height:100vh}"
        "@media(prefers-color-scheme:dark){body{background:#14171c;color:#e6e8eb}.muted{color:#98a2b3}"
        "a{color:#7aa5ff}}.card{max-width:460px;padding:32px;text-align:center}"
        "h1{font-size:20px;margin:0 0 8px}.muted{color:#667085;margin:0 0 18px}"
        "a{color:#2f6fed;text-decoration:none;font-weight:600}</style></head><body><div class='card'>"
        "<h1>Algo salió mal</h1><p class='muted'>Ha ocurrido un error inesperado y no se pudo completar la "
        "acción. Vuelve a intentarlo; si persiste, revisa los registros del servidor.</p>"
        "<a href='/'>&larr; Volver al inicio</a></div></body></html>"
    )


def add_error_pages(app: FastAPI) -> None:
    """Turn any unhandled exception into a friendly page (never a raw 500/stack trace) and log it.

    JSON for ``/api`` paths (machine clients), HTML otherwise (a person in a browser). The exception is
    logged with a traceback under the ``dastcore`` logger so operators can still diagnose it.
    """
    import logging

    from starlette.responses import HTMLResponse, JSONResponse

    logger = logging.getLogger("dastcore")

    @app.exception_handler(Exception)
    async def _unhandled(request, exc):  # type: ignore[no-untyped-def]
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        if request.url.path.startswith("/api"):
            return JSONResponse({"detail": "internal server error"}, status_code=500)
        return HTMLResponse(_error_page_html(), status_code=500)
