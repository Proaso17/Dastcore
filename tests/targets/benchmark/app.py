"""Labeled accuracy benchmark target for dastcore.

Unlike the main vuln_app (almost all true positives — easy to "teach to the test"),
this app pairs vulnerable endpoints with realistic **decoys**: things that look
injectable but aren't. Scoring active findings against the ``EXPECTED`` labels yields
honest precision / recall / F1 — the decoys are the false-positive traps a precise
scanner must avoid, spanning contexts (HTML text, attribute, JS, comment, textarea),
injection points (query, body, header), and confirmation styles (error, boolean,
output, template eval, out-of-band).
"""

from __future__ import annotations

import html
import json as _json
import random
import re
import time
import urllib.request

from flask import Flask, Response, jsonify, redirect, request

# path -> the vulnerability family that SHOULD be found there, or None for a decoy.
EXPECTED: dict[str, str | None] = {
    # --- true positives (16) ---
    "/b/sqli-error": "sqli",  # error-based, query
    "/b/sqli-blind": "sqli",  # boolean-blind, query
    "/b/sqli-post": "sqli",  # error-based, POST body
    "/b/xss-html": "xss",  # reflected in HTML text
    "/b/xss-attr": "xss",  # reflected in a quoted attribute (breakout)
    "/b/xss-js": "xss",  # reflected in a <script> JS string
    "/b/xss-href": "xss",  # javascript: URL in href
    "/b/cmdi": "cmdi",  # OS command output
    "/b/xpath": "xpath",  # XPath error
    "/b/ldap": "ldap",  # LDAP error
    "/b/ssti": "ssti",  # template evaluation ({{1337*1337}} -> 1787569)
    "/b/hosthdr": "host_header",  # reflected Host header
    "/b/redirect": "open_redirect",  # Location = user input
    "/b/lfi": "lfi",  # path traversal -> /etc/passwd
    "/b/secret": "secret",  # leaked cloud key
    "/b/nosql-error": "nosqli",  # NoSQL error-based
    "/b/cors": "cors",  # arbitrary Origin reflected with credentials
    "/b/ssrf": "ssrf",  # blind SSRF (out-of-band)
    "/b/log4shell": "rce",  # JNDI / Log4Shell (out-of-band)
    "/b/xxe": "xxe",  # XML external entity (out-of-band, POST body)
    "/b/cmdi-blind": "cmdi",  # blind OS command injection (out-of-band)
    # --- decoys / true negatives (19) ---
    "/b/xss-escaped": None,  # reflected but HTML-escaped
    "/b/xss-json": None,  # reflected raw but in a JSON body (can't execute)
    "/b/xss-comment": None,  # reflected inside an HTML comment (inert)
    "/b/xss-textarea": None,  # reflected inside <textarea> (only </textarea> breaks out)
    "/b/xss-attr-safe": None,  # reflected in a quoted attribute, but escaped (no breakout)
    "/b/reflect-safe": None,  # echoes input (escaped), no error, no boolean behaviour
    "/b/static": None,  # identical response for any input (boolean/differential trap)
    "/b/nosql-safe": None,  # echoes NoSQL operators in JSON, no DB error
    "/b/lfi-catchall": None,  # passwd-like content for ANY input (soft-404 catch-all)
    "/b/redirect-safe": None,  # redirect target is fixed, ignores input
    "/b/redirect-body": None,  # reflects the URL in the body (escaped), no Location redirect
    "/b/secret-example": None,  # a placeholder that resembles but isn't a real key
    "/b/secret-hash": None,  # a hex digest (looks secret-y, not a known key format)
    "/b/slow": None,  # a uniformly slightly-slow endpoint
    "/b/slow-random": None,  # random jitter, uncorrelated to input (time-based trap)
    "/b/error500": None,  # generic 500 on bad input, no DB/parse signature
    "/b/ssti-literal": None,  # echoes {{1337*1337}} literally (not evaluated)
    "/b/cmdi-echo": None,  # echoes the command separator (escaped), never runs it
    "/b/xpath-generic-500": None,  # 500 on special chars but a generic message
}

_SAMPLES = {
    "/b/sqli-error": "q=demo",
    "/b/sqli-blind": "id=1",
    "/b/xss-html": "name=guest",
    "/b/xss-attr": "v=x",
    "/b/xss-js": "v=x",
    "/b/xss-href": "v=/",
    "/b/cmdi": "host=localhost",
    "/b/xpath": "q=x",
    "/b/ldap": "u=x",
    "/b/ssti": "tpl=hi",
    "/b/hosthdr": "",
    "/b/redirect": "url=/",
    "/b/lfi": "file=readme.txt",
    "/b/secret": "",
    "/b/nosql-error": "filter=all",
    "/b/cors": "",
    "/b/ssrf": "url=http://placeholder/",
    "/b/log4shell": "q=hello",
    "/b/cmdi-blind": "host=localhost",
    "/b/xss-escaped": "name=x",
    "/b/xss-json": "name=x",
    "/b/xss-comment": "name=x",
    "/b/xss-textarea": "name=x",
    "/b/xss-attr-safe": "v=x",
    "/b/reflect-safe": "q=x",
    "/b/static": "id=1",
    "/b/nosql-safe": "filter=all",
    "/b/lfi-catchall": "file=x",
    "/b/redirect-safe": "url=/",
    "/b/redirect-body": "url=/",
    "/b/secret-example": "",
    "/b/secret-hash": "",
    "/b/slow": "x=1",
    "/b/slow-random": "x=1",
    "/b/error500": "q=x",
    "/b/ssti-literal": "tpl=x",
    "/b/cmdi-echo": "host=x",
    "/b/xpath-generic-500": "q=x",
}

_BOOL = re.compile(r"and\s+'?(\w+)'?\s*=\s*'?(\w+)'?", re.IGNORECASE)
_CMD = re.compile(r"[;&|`$(]+\s*(id|whoami)", re.IGNORECASE)
_TPL = re.compile(r"\{\{|\$\{|#\{|<%")  # a template-injection delimiter
_MUL = re.compile(r"(\d+)\s*\*\s*(\d+)")


def _sql_error(value: str) -> bool:
    return any(c in value for c in ("'", '"'))


def _oob_fetch(url: str) -> None:
    """Simulate a server-side fetch (SSRF/RCE/XXE reaching the OAST collector)."""
    try:
        urllib.request.urlopen(url, timeout=3).read()  # noqa: S310 (intentional, offline test target)
    except Exception:
        pass


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index() -> Response:
        # Links cover the GET endpoints; the POST endpoint is reached via the form.
        links = "".join(f'<a href="{p}{("?" + q) if q else ""}">{p}</a> ' for p, q in _SAMPLES.items())
        form = (
            '<form action="/b/sqli-post" method="post"><input name="q" value=""></form>'
            '<form action="/b/xxe" method="post"><input name="xml" value=""></form>'
        )
        return Response(
            f"<!doctype html><html><body><h1>benchmark</h1>{links}{form}</body></html>", mimetype="text/html"
        )

    @app.get("/sitemap.xml")
    def sitemap() -> Response:
        urls = "".join(f"<url><loc>{p}{('?' + q) if q else ''}</loc></url>" for p, q in _SAMPLES.items())
        return Response(
            f'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>',
            mimetype="application/xml",
        )

    # --- true positives -------------------------------------------------------------------

    @app.get("/b/sqli-error")
    def sqli_error() -> Response:
        if _sql_error(request.args.get("q", "")):
            return Response("SQLite3::error near: syntax error", status=500, mimetype="text/plain")
        return jsonify({"results": []})

    @app.post("/b/sqli-post")
    def sqli_post() -> Response:
        if _sql_error((request.form or {}).get("q", "")):
            return Response("SQLite3::error near: syntax error", status=500, mimetype="text/plain")
        return jsonify({"ok": True})

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

    @app.get("/b/xss-js")
    def xss_js() -> Response:
        return Response(f"<script>var q = '{request.args.get('v', '')}';</script>", mimetype="text/html")

    @app.get("/b/xss-href")
    def xss_href() -> Response:
        return Response(f'<a href="{request.args.get("v", "/")}">next</a>', mimetype="text/html")

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

    @app.get("/b/ssti")
    def ssti() -> Response:
        raw = request.args.get("tpl", "")
        if _TPL.search(raw):
            mul = _MUL.search(raw)
            if mul:
                return Response(f"<p>{int(mul.group(1)) * int(mul.group(2))}</p>", mimetype="text/html")
        return Response(f"<p>{html.escape(raw)}</p>", mimetype="text/html")

    @app.get("/b/hosthdr")
    def hosthdr() -> Response:
        return Response(f"<p>Host: {request.headers.get('Host', '')}</p>", mimetype="text/html")

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

    @app.get("/b/nosql-error")
    def nosql_error() -> Response:
        if any(c in request.args.get("filter", "") for c in ("'", '"', "{", "$", "[")):
            return Response("MongoError: unknown top level operator", status=500, mimetype="text/plain")
        return jsonify({"results": []})

    @app.get("/b/cors")
    def cors() -> Response:
        resp = jsonify({"data": "sensitive account data"})
        origin = request.headers.get("Origin")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    @app.get("/b/ssrf")
    def ssrf() -> Response:
        url = request.args.get("url", "")
        if url.startswith(("http://", "https://")):
            _oob_fetch(url)
        return jsonify({"status": "processed"})

    @app.get("/b/log4shell")
    def log4shell() -> Response:
        candidate = request.args.get("q", "") + " " + request.headers.get("User-Agent", "")
        m = re.search(r"jndi:\w+://([^}\s]+)", candidate, re.IGNORECASE)
        if m:
            _oob_fetch("http://" + m.group(1))
        return jsonify({"logged": True})

    @app.post("/b/xxe")
    def xxe() -> Response:
        body = (request.form or {}).get("xml", "") or request.get_data(as_text=True)
        m = re.search(r'SYSTEM\s+"(https?://[^"]+)"', body)
        if m:
            _oob_fetch(m.group(1))
        return jsonify({"parsed": True})

    @app.get("/b/cmdi-blind")
    def cmdi_blind() -> Response:
        m = re.search(r"(?:curl|wget)\s+(https?://[^\s;`)]+)", request.args.get("host", ""))
        if m:
            _oob_fetch(m.group(1))
        return jsonify({"pinged": True})

    # --- decoys / true negatives ----------------------------------------------------------

    @app.get("/b/xss-escaped")
    def xss_escaped() -> Response:
        return Response(f"<h1>Hola {html.escape(request.args.get('name', ''))}</h1>", mimetype="text/html")

    @app.get("/b/xss-json")
    def xss_json() -> Response:
        return Response(_json.dumps({"echo": request.args.get("name", "")}), mimetype="application/json")

    @app.get("/b/xss-comment")
    def xss_comment() -> Response:
        return Response(f"<!-- echo: {request.args.get('name', '')} -->", mimetype="text/html")

    @app.get("/b/xss-textarea")
    def xss_textarea() -> Response:
        return Response(f"<textarea>{request.args.get('name', '')}</textarea>", mimetype="text/html")

    @app.get("/b/xss-attr-safe")
    def xss_attr_safe() -> Response:
        return Response(f'<input value="{html.escape(request.args.get("v", ""))}">', mimetype="text/html")

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
        return Response("root:x:0:0:root:/root:/bin/bash", mimetype="text/plain")

    @app.get("/b/redirect-safe")
    def redirect_safe() -> Response:
        return redirect("/")

    @app.get("/b/redirect-body")
    def redirect_body() -> Response:
        return Response(f"<p>Irías a: {html.escape(request.args.get('url', ''))}</p>", mimetype="text/html")

    @app.get("/b/secret-example")
    def secret_example() -> Response:
        return jsonify({"example": "AKIA-YOUR-KEY-HERE", "docs": "put your real key in the env"})

    @app.get("/b/secret-hash")
    def secret_hash() -> Response:
        return jsonify({"commit": "da39a3ee5e6b4b0d3255bfef95601890afd80709"})

    @app.get("/b/slow")
    def slow() -> Response:
        time.sleep(0.05)
        return jsonify({"ok": True})

    @app.get("/b/slow-random")
    def slow_random() -> Response:
        time.sleep(random.uniform(0.0, 0.2))  # noqa: S311 (jitter, not crypto)
        return jsonify({"ok": True})

    @app.get("/b/error500")
    def error500() -> Response:
        if any(c in request.args.get("q", "") for c in ("'", '"', "<", ";")):
            return Response("Internal Server Error", status=500, mimetype="text/plain")
        return jsonify({"ok": True})

    @app.get("/b/ssti-literal")
    def ssti_literal() -> Response:
        return Response(f"<p>{html.escape(request.args.get('tpl', ''))}</p>", mimetype="text/html")

    @app.get("/b/cmdi-echo")
    def cmdi_echo() -> Response:
        return Response(f"<pre>cmd recibido: {html.escape(request.args.get('host', ''))}</pre>", mimetype="text/html")

    @app.get("/b/xpath-generic-500")
    def xpath_generic_500() -> Response:
        if any(c in request.args.get("q", "") for c in ("'", '"', "(")):
            return Response("Query error", status=500, mimetype="text/plain")
        return jsonify({"r": []})

    return app
