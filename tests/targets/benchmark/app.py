"""Labeled accuracy benchmark target for dastcore.

Unlike the main vuln_app (almost all true positives — easy to "teach to the test"),
this app pairs each vulnerable endpoint with realistic **decoys**: things that look
injectable but aren't (escaped reflection, reflection in a JSON body, a soft-404
catch-all, an endpoint that echoes NoSQL operators without erroring, a redirect that
ignores its input, a placeholder that resembles a secret). Scoring against the
``EXPECTED`` labels yields honest precision/recall/F1, and the decoys are exactly the
false-positive traps a precise scanner must avoid.
"""

from __future__ import annotations

import html
import json as _json
import re

from flask import Flask, Response, jsonify, redirect, request

# path -> the vulnerability family that SHOULD be found there, or None for a decoy
# (a safe endpoint that must NOT produce an active finding).
EXPECTED: dict[str, str | None] = {
    # --- true positives ---
    "/b/sqli-error": "sqli",
    "/b/sqli-blind": "sqli",
    "/b/xss-html": "xss",
    "/b/xss-attr": "xss",
    "/b/cmdi": "cmdi",
    "/b/xpath": "xpath",
    "/b/ldap": "ldap",
    "/b/redirect": "open_redirect",
    "/b/lfi": "lfi",
    "/b/secret": "secret",
    # --- decoys / true negatives (must NOT fire) ---
    "/b/xss-escaped": None,  # reflected but HTML-escaped
    "/b/xss-json": None,  # reflected raw but in a JSON body (can't execute)
    "/b/xss-comment": None,  # reflected inside an HTML comment (inert)
    "/b/reflect-safe": None,  # echoes input (escaped), no error, no boolean behaviour
    "/b/static": None,  # identical response for any input (boolean/differential trap)
    "/b/nosql-safe": None,  # echoes NoSQL operators in JSON, no DB error
    "/b/lfi-catchall": None,  # passwd-like content for ANY input (soft-404 catch-all)
    "/b/redirect-safe": None,  # redirect target is fixed, ignores input
    "/b/secret-example": None,  # a placeholder that resembles but isn't a real key
    "/b/slow": None,  # a uniformly slightly-slow endpoint (time-based trap)
}

# Sample query for each endpoint so the crawler can reach and fuzz it.
_SAMPLES = {
    "/b/sqli-error": "q=demo",
    "/b/sqli-blind": "id=1",
    "/b/xss-html": "name=guest",
    "/b/xss-attr": "v=x",
    "/b/cmdi": "host=localhost",
    "/b/xpath": "q=x",
    "/b/ldap": "u=x",
    "/b/redirect": "url=/",
    "/b/lfi": "file=readme.txt",
    "/b/secret": "",
    "/b/xss-escaped": "name=x",
    "/b/xss-json": "name=x",
    "/b/xss-comment": "name=x",
    "/b/reflect-safe": "q=x",
    "/b/static": "id=1",
    "/b/nosql-safe": "filter=all",
    "/b/lfi-catchall": "file=x",
    "/b/redirect-safe": "url=/",
    "/b/secret-example": "",
    "/b/slow": "x=1",
}

_BOOL = re.compile(r"and\s+'?(\w+)'?\s*=\s*'?(\w+)'?", re.IGNORECASE)
_CMD = re.compile(r"[;&|`$(]+\s*(id|whoami)", re.IGNORECASE)


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index() -> Response:
        links = "".join(f'<a href="{p}{("?" + _SAMPLES[p]) if _SAMPLES[p] else ""}">{p}</a> ' for p in EXPECTED)
        return Response(f"<!doctype html><html><body><h1>benchmark</h1>{links}</body></html>", mimetype="text/html")

    @app.get("/sitemap.xml")
    def sitemap() -> Response:
        urls = "".join(f"<url><loc>{p}{('?' + _SAMPLES[p]) if _SAMPLES[p] else ''}</loc></url>" for p in EXPECTED)
        return Response(
            f'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>',
            mimetype="application/xml",
        )

    # --- true positives -------------------------------------------------------------------

    @app.get("/b/sqli-error")
    def sqli_error() -> Response:
        if any(c in request.args.get("q", "") for c in ("'", '"')):
            return Response("SQLite3::error near: syntax error", status=500, mimetype="text/plain")
        return jsonify({"results": []})

    @app.get("/b/sqli-blind")
    def sqli_blind() -> Response:
        cond = _BOOL.search(request.args.get("id", "1"))
        truthy = (cond.group(1) == cond.group(2)) if cond else True
        return Response(f"<h1>Item</h1><p>{'in stock' if truthy else 'not found'}</p>", mimetype="text/html")

    @app.get("/b/xss-html")
    def xss_html() -> Response:
        return Response(f"<h1>Hola {request.args.get('name', '')}</h1>", mimetype="text/html")

    @app.get("/b/xss-attr")
    def xss_attr() -> Response:
        return Response(f'<input value="{request.args.get("v", "")}">', mimetype="text/html")

    @app.get("/b/cmdi")
    def cmdi() -> Response:
        out = "PING ok"
        if _CMD.search(request.args.get("host", "")):
            out += "\nuid=0(root) gid=0(root) groups=0(root)"
        return Response(f"<pre>{out}</pre>", mimetype="text/html")

    @app.get("/b/xpath")
    def xpath() -> Response:
        if any(c in request.args.get("q", "") for c in ("'", '"', "]", "(")):
            return Response("XPathException: Invalid predicate", status=500, mimetype="text/plain")
        return jsonify({"r": []})

    @app.get("/b/ldap")
    def ldap() -> Response:
        if any(c in request.args.get("u", "") for c in ("(", ")", "*", "\\", "|")):
            return Response("LDAPError: bad search filter (LDAP: error code 87)", status=500, mimetype="text/plain")
        return jsonify({"found": False})

    @app.get("/b/redirect")
    def redir() -> Response:
        return redirect(request.args.get("url", "/"))

    @app.get("/b/lfi")
    def lfi() -> Response:
        name = request.args.get("file", "readme.txt")
        if "../" in name or "etc/passwd" in name:
            return Response("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon", mimetype="text/plain")
        return Response("welcome to the benchmark", mimetype="text/plain")

    @app.get("/b/secret")
    def secret() -> Response:
        return jsonify({"note": "config", "aws_key": "AKIAIOSFODNN7EXAMPLE"})

    # --- decoys / true negatives ----------------------------------------------------------

    @app.get("/b/xss-escaped")
    def xss_escaped() -> Response:
        return Response(f"<h1>Hola {html.escape(request.args.get('name', ''))}</h1>", mimetype="text/html")

    @app.get("/b/xss-json")
    def xss_json() -> Response:
        # Raw echo, but in a JSON body (json.dumps doesn't escape <, unlike Flask's jsonify)
        return Response(_json.dumps({"echo": request.args.get("name", "")}), mimetype="application/json")

    @app.get("/b/xss-comment")
    def xss_comment() -> Response:
        return Response(f"<!-- echo: {request.args.get('name', '')} -->", mimetype="text/html")

    @app.get("/b/reflect-safe")
    def reflect_safe() -> Response:
        return Response(f"<p>Buscaste: {html.escape(request.args.get('q', ''))}</p>", mimetype="text/html")

    @app.get("/b/static")
    def static_ep() -> Response:
        return Response("<h1>Catálogo</h1><p>Contenido fijo para todos.</p>", mimetype="text/html")

    @app.get("/b/nosql-safe")
    def nosql_safe() -> Response:
        return Response(_json.dumps({"filter": request.args.get("filter", "")}), mimetype="application/json")

    @app.get("/b/lfi-catchall")
    def lfi_catchall() -> Response:
        # Returns passwd-like content for ANY input -> a soft-404 catch-all, not a real read.
        return Response("root:x:0:0:root:/root:/bin/bash", mimetype="text/plain")

    @app.get("/b/redirect-safe")
    def redirect_safe() -> Response:
        return redirect("/")  # fixed target, ignores the user input

    @app.get("/b/secret-example")
    def secret_example() -> Response:
        return jsonify({"example": "AKIA-YOUR-KEY-HERE", "docs": "put your real key in the env"})

    @app.get("/b/slow")
    def slow() -> Response:
        import time

        time.sleep(0.05)  # constant small delay regardless of input
        return jsonify({"ok": True})

    return app
