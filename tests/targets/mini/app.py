"""A tiny vulnerable target for the dashboard/UI tests.

The web-UI integration tests only need *a* real scan that produces one stable
finding (``sqli-injection``) to exercise history / triage / retest / diff. Pointing
them at the full vuln_app (now ~35 endpoints) made those scans slow and timing-flaky;
this two-endpoint target scans in a couple of seconds and is fully deterministic:
only a single quote triggers the error, and nothing is reflected, so exactly one
error-based SQL injection is found and no other class fires.
"""

from __future__ import annotations

from flask import Flask, Response, request


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index() -> Response:
        return Response(
            '<!doctype html><html><body><a href="/search?q=demo">buscar</a>'
            '<form action="/search" method="get"><input name="q" value=""></form></body></html>',
            mimetype="text/html",
        )

    @app.get("/search")
    def search() -> Response:
        # Error-based SQL injection: a single quote breaks the (pretend) query. Nothing
        # is echoed back, so no reflected-XSS/other class fires — only sqli-injection.
        if "'" in request.args.get("q", ""):
            return Response("<pre>SQLite3::error near: unrecognized token</pre>", status=500, mimetype="text/html")
        return Response("<h1>Resultados</h1>", mimetype="text/html")

    return app
