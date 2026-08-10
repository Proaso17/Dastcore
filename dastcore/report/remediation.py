"""Remediation knowledge base: turns a Finding into actionable, well-presented guidance.

Every finding already carries a one-line `remediation` string from its rule. This
module enriches that with concrete step-by-step fixes, a *vulnerable → secure* code
example, and curated references (OWASP Cheat Sheets / PortSwigger + the CWE page),
so the HTML report can render a proper "How to fix" panel instead of a bare sentence.

The rule's own `remediation` stays authoritative as the summary line; everything else
is additive and keyed by the finding's `family` (falling back to its `rule_id` for the
passive/active detector findings that have no family).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

_CHEATSHEET = "https://cheatsheetseries.owasp.org/cheatsheets/"


class RemediationTarget(Protocol):
    """The minimal surface `guide_for` needs. Both `Finding` and a correlated
    `IssueGroup` satisfy it, so the HTML report, SARIF and the web UI share one
    knowledge base."""

    family: str
    rule_id: str
    cwe: str
    remediation: str


@dataclass(frozen=True)
class Reference:
    """An external, authoritative page a developer can open to go deeper."""

    label: str
    url: str


@dataclass(frozen=True)
class CodeExample:
    """A minimal before/after pair: the insecure pattern and its secure rewrite."""

    bad: str
    good: str
    lang: str = ""
    note: str = ""


@dataclass(frozen=True)
class RemediationGuide:
    """Everything the report needs to render a rich, actionable fix panel."""

    summary: str
    steps: tuple[str, ...] = ()
    example: CodeExample | None = None
    references: tuple[Reference, ...] = field(default_factory=tuple)


# --- per-family / per-detector knowledge ------------------------------------------------
# Each entry may define `steps`, `example` and `references`. Keys are either a rule
# `family` or one of the synthetic keys used by `_RULE_PREFIXES` for detector findings.

_GUIDES: dict[str, dict] = {
    "sqli": {
        "steps": (
            "Use parameterized queries / prepared statements for every database call.",
            "Bind user input as parameters — never concatenate or interpolate it into the SQL string.",
            "Apply least-privilege DB accounts so an injection cannot read or write beyond its scope.",
            "Add strict server-side type/allowlist validation for values used in ORDER BY / column names, which cannot be parameterized.",
        ),
        "example": CodeExample(
            lang="python",
            bad='cur.execute("SELECT * FROM users WHERE id = " + user_id)',
            good='cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            note="The '?' placeholder keeps the value as data; the driver never treats it as SQL.",
        ),
        "references": (
            Reference(
                "OWASP SQL Injection Prevention Cheat Sheet", _CHEATSHEET + "SQL_Injection_Prevention_Cheat_Sheet.html"
            ),
            Reference(
                "OWASP Query Parameterization Cheat Sheet", _CHEATSHEET + "Query_Parameterization_Cheat_Sheet.html"
            ),
        ),
    },
    "xss": {
        "steps": (
            "Contextually output-encode all user input at the point it is rendered (HTML body, attribute, JS, URL, CSS).",
            "Use a templating engine with autoescaping enabled and avoid raw/unescaped output helpers.",
            "Add a Content-Security-Policy that disables inline script (no 'unsafe-inline') as defense in depth.",
            "For rich text, sanitize with a vetted allowlist library (e.g. DOMPurify) instead of hand-rolled filtering.",
        ),
        "example": CodeExample(
            lang="python",
            bad="return f\"<h1>Hello {request.args['name']}</h1>\"",
            good='return render_template("hello.html", name=request.args["name"])  # autoescaped',
            note="Let the framework encode for the exact context; do not build HTML by string concatenation.",
        ),
        "references": (
            Reference(
                "OWASP XSS Prevention Cheat Sheet", _CHEATSHEET + "Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ),
            Reference(
                "OWASP DOM-based XSS Prevention Cheat Sheet", _CHEATSHEET + "DOM_based_XSS_Prevention_Cheat_Sheet.html"
            ),
        ),
    },
    "ssrf": {
        "steps": (
            "Do not fetch user-supplied URLs directly; require selection from a server-side allowlist where possible.",
            "Validate the scheme and host against a strict allowlist, then resolve the DNS name and pin the connection to that resolved IP.",
            "Block requests to private, loopback, link-local and cloud-metadata ranges (e.g. 169.254.169.254).",
            "Disable redirects on the outbound fetch, or re-validate the target after each redirect hop.",
        ),
        "example": CodeExample(
            lang="python",
            bad="requests.get(request.args['url'])",
            good="host = urlparse(url).hostname\nif host not in ALLOWED_HOSTS:\n    abort(400)\nrequests.get(url, allow_redirects=False)",
            note="Validate the final destination, not just the string — attackers use redirects and DNS rebinding.",
        ),
        "references": (
            Reference(
                "OWASP SSRF Prevention Cheat Sheet",
                _CHEATSHEET + "Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            ),
        ),
    },
    "open_redirect": {
        "steps": (
            "Never redirect to a raw user-controlled URL.",
            "Validate the destination against an allowlist of known-safe paths or hosts.",
            "Prefer relative paths, or map an opaque key to a fixed server-side URL instead of passing the URL itself.",
            "Reject absolute URLs, protocol-relative ('//evil.com') and backslash-obfuscated values.",
        ),
        "example": CodeExample(
            lang="python",
            bad="return redirect(request.args['next'])",
            good='target = request.args["next"]\nif not target.startswith("/") or target.startswith("//"):\n    target = "/"\nreturn redirect(target)',
            note="Force the redirect to stay on your own site; only allow local, non-protocol-relative paths.",
        ),
        "references": (
            Reference(
                "OWASP Unvalidated Redirects and Forwards Cheat Sheet",
                _CHEATSHEET + "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            ),
        ),
    },
    "lfi": {
        "steps": (
            "Never build filesystem paths directly from user input.",
            "Resolve the requested path against a fixed base directory, canonicalize it, and reject anything that escapes the base.",
            "Prefer mapping an opaque identifier to a known file over accepting a filename at all.",
            "Strip or reject path separators, NUL bytes and encoded traversal sequences (../, ..%2f).",
        ),
        "example": CodeExample(
            lang="python",
            bad="open(os.path.join(BASE, request.args['file']))",
            good='p = (BASE / request.args["file"]).resolve()\nif not p.is_relative_to(BASE):\n    abort(400)\nopen(p)',
            note="Canonicalize first, then confirm the result is still inside the intended base directory.",
        ),
        "references": (
            Reference("OWASP Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
            Reference("OWASP File Upload Cheat Sheet", _CHEATSHEET + "File_Upload_Cheat_Sheet.html"),
        ),
    },
    "cmdi": {
        "steps": (
            "Never pass user input to a shell.",
            "Use process APIs that take an argument vector (no shell interpretation) instead of a single command string.",
            "Validate arguments against a strict allowlist and reject shell metacharacters.",
            "Run the process with least privilege so a successful injection has minimal impact.",
        ),
        "example": CodeExample(
            lang="python",
            bad='subprocess.run("ping " + host, shell=True)',
            good='subprocess.run(["ping", "-c", "1", host], shell=False)',
            note="An argument vector with shell=False means metacharacters like ; and | stay literal data.",
        ),
        "references": (
            Reference(
                "OWASP OS Command Injection Defense Cheat Sheet",
                _CHEATSHEET + "OS_Command_Injection_Defense_Cheat_Sheet.html",
            ),
        ),
    },
    "rce": {
        "steps": (
            "Patch or upgrade the vulnerable component immediately (e.g. Log4j ≥ 2.17.1 for Log4Shell).",
            "Disable dangerous lookups/features you do not need (for Log4j, message lookups and JNDI).",
            "Never evaluate, deserialize or template user-controlled data into code or lookups.",
            "Apply egress filtering so a compromised host cannot reach attacker infrastructure (JNDI/LDAP/DNS).",
        ),
        "example": CodeExample(
            lang="text",
            bad="log4j-core 2.14.1  (JNDI lookups enabled)",
            good="log4j-core 2.17.1+  (message lookups removed) — or set log4j2.formatMsgNoLookups=true",
            note="Prefer upgrading the library over runtime flags; flags are a stopgap, not a fix.",
        ),
        "references": (
            Reference(
                "CISA Apache Log4j Guidance",
                "https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance",
            ),
            Reference("OWASP Deserialization Cheat Sheet", _CHEATSHEET + "Deserialization_Cheat_Sheet.html"),
        ),
    },
    "xxe": {
        "steps": (
            "Disable DOCTYPE / DTD processing and external entity resolution in the XML parser.",
            "In Python, use defusedxml (or set resolve_entities=False on lxml); in Java, enable FEATURE_SECURE_PROCESSING and disallow-doctype-decl.",
            "Prefer a data format without entities (JSON) when you control the interface.",
            "Never echo parser errors containing file contents back to the client.",
        ),
        "example": CodeExample(
            lang="python",
            bad="from xml.etree.ElementTree import fromstring\nfromstring(user_xml)",
            good="from defusedxml.ElementTree import fromstring\nfromstring(user_xml)  # entities/DTD disabled",
            note="defusedxml is a drop-in that turns off the dangerous XML features by default.",
        ),
        "references": (
            Reference(
                "OWASP XXE Prevention Cheat Sheet", _CHEATSHEET + "XML_External_Entity_Prevention_Cheat_Sheet.html"
            ),
        ),
    },
    "ssti": {
        "steps": (
            "Do not render user input as a template.",
            "Pass user data strictly as bound context variables, never concatenated into the template source.",
            "Use a logic-less or sandboxed template engine for any user-authored templates.",
            "Keep the template engine and its sandbox up to date.",
        ),
        "example": CodeExample(
            lang="python",
            bad='Template("Hello " + request.args["name"]).render()',
            good='Template("Hello {{ name }}").render(name=request.args["name"])',
            note="The user value is data for a fixed template — it is never compiled as template code.",
        ),
        "references": (
            Reference(
                "PortSwigger: Server-Side Template Injection",
                "https://portswigger.net/web-security/server-side-template-injection",
            ),
        ),
    },
    "host_header": {
        "steps": (
            "Do not build absolute URLs, password-reset links or cache keys from the Host / X-Forwarded-Host header.",
            "Validate the incoming Host against an allowlist of expected hostnames and reject the request otherwise.",
            "Configure a canonical base URL (or trusted-host list) in the framework and use it for link generation.",
            "Constrain the trusted Host at the reverse proxy / load balancer as well.",
        ),
        "example": CodeExample(
            lang="python",
            bad="reset_link = f\"https://{request.headers['Host']}/reset?t={token}\"",
            good='reset_link = f"https://{settings.CANONICAL_HOST}/reset?t={token}"',
            note="Generate security-sensitive links from server config, not from a client-controlled header.",
        ),
        "references": (
            Reference("PortSwigger: HTTP Host Header Attacks", "https://portswigger.net/web-security/host-header"),
        ),
    },
    "crlf": {
        "steps": (
            "Strip or reject CR/LF (and their encoded forms %0d/%0a) from any user input placed into HTTP headers or response metadata.",
            "Use framework APIs that set headers/cookies safely and encode values for you.",
            "Never build a Location, Set-Cookie or custom header by concatenating raw user input.",
            "Keep the web server / framework patched — most modern stacks reject header CRLF by default.",
        ),
        "example": CodeExample(
            lang="python",
            bad='resp.headers["Location"] = request.args["next"]',
            good='value = request.args["next"]\nif "\\r" in value or "\\n" in value:\n    abort(400)\nresp.headers["Location"] = value',
            note="Reject control characters before they reach any header value.",
        ),
        "references": (
            Reference(
                "OWASP HTTP Response Splitting", "https://owasp.org/www-community/attacks/HTTP_Response_Splitting"
            ),
        ),
    },
    "nosqli": {
        "steps": (
            "Treat user input as data, not as query operators.",
            "Validate and cast types (a field expected to be a string must not arrive as an object).",
            "Reject keys that begin with '$' and nested query-operator structures.",
            "Use the driver's parameterized query building rather than passing raw request bodies into queries.",
        ),
        "example": CodeExample(
            lang="python",
            bad='db.users.find_one({"user": request.json["user"]})',
            good='user = request.json["user"]\nif not isinstance(user, str):\n    abort(400)\ndb.users.find_one({"user": user})',
            note="Enforcing the scalar type stops {'$ne': null}-style operator injection.",
        ),
        "references": (
            Reference("PortSwigger: NoSQL Injection", "https://portswigger.net/web-security/nosql-injection"),
        ),
    },
    "ldap": {
        "steps": (
            "Escape user input for LDAP using the framework's dedicated encoder before placing it in a filter or DN.",
            "Validate against a strict allowlist of expected characters.",
            "Bind with least-privilege service accounts.",
            "Prefer parameterized LDAP APIs where the library offers them.",
        ),
        "example": CodeExample(
            lang="python",
            bad="f\"(uid={request.args['user']})\"",
            good="from ldap3.utils.conv import escape_filter_chars\nf\"(uid={escape_filter_chars(request.args['user'])})\"",
            note="Escaping neutralizes ()*\\ and NUL, which are the LDAP filter metacharacters.",
        ),
        "references": (
            Reference(
                "OWASP LDAP Injection Prevention Cheat Sheet",
                _CHEATSHEET + "LDAP_Injection_Prevention_Cheat_Sheet.html",
            ),
        ),
    },
    "xpath": {
        "steps": (
            "Never concatenate user input into an XPath expression.",
            "Use parameterized/variable-bound XPath (pass values through the evaluation context).",
            "Validate input against a strict allowlist of expected characters.",
            "Consider storing the data in a queryable store that supports parameterization instead of raw XML.",
        ),
        "example": CodeExample(
            lang="python",
            bad="tree.xpath(f\"//user[name='{name}']\")",
            good='tree.xpath("//user[name=$n]", n=name)  # value bound as a variable',
            note="A bound variable keeps the value out of the expression grammar.",
        ),
        "references": (Reference("OWASP XPath Injection", "https://owasp.org/www-community/attacks/XPATH_Injection"),),
    },
    "cors": {
        "steps": (
            "Do not reflect the request Origin into Access-Control-Allow-Origin.",
            "Match the Origin against a strict server-side allowlist and echo only exact, known values.",
            "Never combine Access-Control-Allow-Credentials: true with a wildcard or a reflected origin.",
            "Return no CORS headers at all for endpoints that are not meant to be cross-origin.",
        ),
        "example": CodeExample(
            lang="python",
            bad='resp.headers["Access-Control-Allow-Origin"] = request.headers["Origin"]',
            good='origin = request.headers.get("Origin", "")\nif origin in ALLOWED_ORIGINS:\n    resp.headers["Access-Control-Allow-Origin"] = origin',
            note="Only echo origins you explicitly trust; reflecting any origin defeats the same-origin policy.",
        ),
        "references": (Reference("PortSwigger: CORS Misconfiguration", "https://portswigger.net/web-security/cors"),),
    },
    "secrets": {
        "steps": (
            "Treat the exposed value as compromised: rotate/revoke the credential immediately.",
            "Remove the secret from the response body, source, logs and version history.",
            "Load secrets at runtime from a secrets manager or environment variables, never hard-code them.",
            "Add secret scanning to CI and pre-commit to catch regressions.",
        ),
        "example": CodeExample(
            lang="python",
            bad='AWS_KEY = "AKIA...hard-coded..."',
            good='AWS_KEY = os.environ["AWS_KEY"]  # injected from a secrets manager',
            note="Rotation matters more than removal — assume anything that shipped has been captured.",
        ),
        "references": (
            Reference("OWASP Secrets Management Cheat Sheet", _CHEATSHEET + "Secrets_Management_Cheat_Sheet.html"),
        ),
    },
    "authz": {
        "steps": (
            "Enforce object-level authorization on the server for every request: verify the current user owns or may access the referenced object.",
            "Do not rely on the client hiding IDs, on obscure/unguessable identifiers, or on UI-level checks.",
            "Check function-level permissions (roles) on every privileged endpoint, not just in the menu.",
            "Deny by default and centralize the authorization decision so it cannot be forgotten per-route.",
        ),
        "example": CodeExample(
            lang="python",
            bad="order = Order.get(request.view_args['id'])\nreturn order.json()",
            good="order = Order.get(request.view_args['id'])\nif order.owner_id != current_user.id:\n    abort(403)\nreturn order.json()",
            note="The ownership check must run server-side on every access, regardless of how the ID was obtained.",
        ),
        "references": (
            Reference("OWASP Authorization Cheat Sheet", _CHEATSHEET + "Authorization_Cheat_Sheet.html"),
            Reference(
                "OWASP API1:2023 Broken Object Level Authorization",
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            ),
        ),
    },
    "security_headers": {
        "steps": (
            "Set the missing security header on every response, ideally in one place (middleware / reverse proxy).",
            "Content-Security-Policy: start from a restrictive default-src 'self' and remove 'unsafe-inline'.",
            "Strict-Transport-Security: enable with a long max-age once you are fully on HTTPS.",
            "X-Content-Type-Options: nosniff and X-Frame-Options: DENY (or CSP frame-ancestors 'none').",
        ),
        "example": CodeExample(
            lang="python",
            bad="# no security headers set",
            good='resp.headers["X-Content-Type-Options"] = "nosniff"\nresp.headers["X-Frame-Options"] = "DENY"\nresp.headers["Content-Security-Policy"] = "default-src \'self\'"',
            note="Apply these in shared middleware so no route can accidentally omit them.",
        ),
        "references": (
            Reference("OWASP Secure Headers Project", "https://owasp.org/www-project-secure-headers/"),
            Reference(
                "OWASP Content Security Policy Cheat Sheet", _CHEATSHEET + "Content_Security_Policy_Cheat_Sheet.html"
            ),
        ),
    },
    "insecure_cookie": {
        "steps": (
            "Set Secure so the cookie is only sent over HTTPS.",
            "Set HttpOnly so it is not readable from JavaScript (mitigates XSS token theft).",
            "Set SameSite=Lax or Strict to reduce CSRF exposure.",
            "Scope cookies with a narrow Path and, where possible, __Host- prefix.",
        ),
        "example": CodeExample(
            lang="python",
            bad='resp.set_cookie("session", token)',
            good='resp.set_cookie("session", token, secure=True, httponly=True, samesite="Lax")',
            note="Session cookies should carry Secure + HttpOnly + SameSite at minimum.",
        ),
        "references": (
            Reference("OWASP Session Management Cheat Sheet", _CHEATSHEET + "Session_Management_Cheat_Sheet.html"),
        ),
    },
    "info_disclosure": {
        "steps": (
            "Return generic error pages to clients; never expose stack traces, SQL errors or framework internals.",
            "Disable debug mode in production and log detailed diagnostics server-side only.",
            "Remove version-revealing headers (Server, X-Powered-By) or set them to a neutral value.",
            "Disable directory listing on the web server.",
        ),
        "example": CodeExample(
            lang="python",
            bad="app.run(debug=True)  # tracebacks shown to users",
            good="app.run(debug=False)\n# register a handler that returns a generic 500 page",
            note="Diagnostics belong in your logs, not in the HTTP response.",
        ),
        "references": (Reference("OWASP Error Handling Cheat Sheet", _CHEATSHEET + "Error_Handling_Cheat_Sheet.html"),),
    },
    "xst": {
        "steps": (
            "Disable the HTTP TRACE (and TRACK) method on the web server and application.",
            "Return 405 Method Not Allowed for TRACE across all vhosts.",
            "Keep sensitive tokens in HttpOnly cookies so any tracing cannot expose them to script.",
        ),
        "example": CodeExample(
            lang="text",
            bad="TRACE / HTTP/1.1  ->  200 OK (request echoed back)",
            good="TRACE / HTTP/1.1  ->  405 Method Not Allowed",
            note="Most servers expose a directive (e.g. TraceEnable off in Apache) to turn TRACE off.",
        ),
        "references": (
            Reference("OWASP Cross Site Tracing", "https://owasp.org/www-community/attacks/Cross_Site_Tracing"),
        ),
    },
    "graphql": {
        "steps": (
            "Disable schema introspection in production.",
            "Enforce authentication/authorization on every resolver, not just at the gateway.",
            "Add query depth/complexity limits and rate limiting to blunt abusive queries.",
            "Turn off any GraphQL IDE (GraphiQL/Playground) on public deployments.",
        ),
        "references": (Reference("OWASP GraphQL Cheat Sheet", _CHEATSHEET + "GraphQL_Cheat_Sheet.html"),),
    },
    "sensitive_file": {
        "steps": (
            "Remove the sensitive file from the web root, or block it at the server/CDN level.",
            "Never deploy .git, .env, backups or config files to a publicly served directory.",
            "Add deny rules for dotfiles and known sensitive paths.",
            "Rotate any credentials that the exposed file may have leaked.",
        ),
        "references": (),
    },
    "csv_injection": {
        "steps": (
            "When exporting user-controlled data to CSV/spreadsheets, prefix any cell that begins with =, +, -, @ (or tab/CR) with a single quote.",
            "Quote fields that contain separators, and strip leading formula triggers server-side.",
            "Do not rely on the spreadsheet client to sanitize on open.",
        ),
        "example": CodeExample(
            lang="python",
            bad="writer.writerow([user_value])",
            good="v = user_value\nif v[:1] in ('=', '+', '-', '@'):\n    v = \"'\" + v\nwriter.writerow([v])",
            note="The leading apostrophe makes the cell a literal string, not a formula.",
        ),
        "references": (Reference("OWASP CSV Injection", "https://owasp.org/www-community/attacks/CSV_Injection"),),
    },
    "http_methods": {
        "steps": (
            "Disable HTTP methods the app doesn't use (PUT/DELETE/PATCH/CONNECT/TRACK) at the server or proxy.",
            "For any write method you do expose, enforce authentication and authorization server-side.",
            "Do not rely on the client's method for access decisions; check permissions on every verb.",
        ),
        "example": CodeExample(
            lang="text",
            bad="OPTIONS /  ->  Allow: GET, PUT, DELETE, PATCH",
            good="OPTIONS /  ->  Allow: GET, POST, HEAD, OPTIONS   (write verbs disabled)",
            note="Advertised write methods are an attack surface even before authz is considered.",
        ),
        "references": (
            Reference(
                "OWASP WSTG: Test HTTP Methods",
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
            ),
        ),
    },
    "xml_injection": {
        "steps": (
            "Never build XML by concatenating user input.",
            "Build the document with a DOM/serializer API that escapes values, or escape &, <, >, \" and ' yourself.",
            "Validate the input against a schema (XSD/RelaxNG) and reject malformed structure.",
            "Disable DTD and external-entity processing in the parser (defends XXE at the same time).",
        ),
        "example": CodeExample(
            lang="python",
            bad='xml = f"<result>{user_value}</result>"',
            good='from xml.sax.saxutils import escape\nxml = f"<result>{escape(user_value)}</result>"',
            note="Escaping the XML metacharacters keeps user data as text, not markup.",
        ),
        "references": (
            Reference(
                "OWASP XML External Entity Prevention Cheat Sheet",
                _CHEATSHEET + "XML_External_Entity_Prevention_Cheat_Sheet.html",
            ),
        ),
    },
    "jwt": {
        "steps": (
            "Verify the signature with a fixed, server-side algorithm allow-list (e.g. only RS256, or only HS256).",
            "Reject alg:none and any algorithm the server did not issue — never trust the token's alg header.",
            "Use a maintained JWT library and its verify() path; do not decode-without-verify for auth decisions.",
            "Rotate signing keys and keep the secret/private key out of client-reachable code.",
        ),
        "example": CodeExample(
            lang="python",
            bad='claims = jwt.decode(token, options={"verify_signature": False})',
            good='claims = jwt.decode(token, key, algorithms=["RS256"])  # alg pinned, signature verified',
            note="Pinning algorithms server-side defeats alg:none and algorithm-confusion attacks.",
        ),
        "references": (
            Reference("OWASP JSON Web Token Cheat Sheet", _CHEATSHEET + "JSON_Web_Token_for_Java_Cheat_Sheet.html"),
            Reference(
                "OWASP API2:2023 Broken Authentication",
                "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
            ),
        ),
    },
    "deserialization": {
        "steps": (
            "Do not send native serialized objects to the client, and never deserialize untrusted input with them.",
            "Prefer a data-only format (JSON) over language-native serialization (Java/PHP/pickle).",
            "If native serialization is unavoidable, sign the blob (HMAC) and verify before deserializing, and use type allow-lists.",
            "Keep deserialization libraries patched.",
        ),
        "example": CodeExample(
            lang="python",
            bad="obj = pickle.loads(request.cookies['state'])",
            good='obj = json.loads(request.cookies["state"])  # data only, no code paths',
            note="pickle/readObject/unserialize can execute code during deserialization; JSON cannot.",
        ),
        "references": (
            Reference("OWASP Deserialization Cheat Sheet", _CHEATSHEET + "Deserialization_Cheat_Sheet.html"),
        ),
    },
    "session_exposure": {
        "steps": (
            "Never put session or authentication tokens in the URL/query string.",
            "Keep the session in a Secure, HttpOnly, SameSite cookie, or send tokens in the Authorization header.",
            "Rotate any token that may have leaked via history/logs/Referer, and set a short expiry.",
        ),
        "example": CodeExample(
            lang="text",
            bad="GET /account?sessionid=8f3b1c2d9a7e4f60  (leaks via logs/Referer/history)",
            good="Cookie: sessionid=8f3b1c2d...  (Secure; HttpOnly; SameSite=Lax)",
            note="Query strings are logged and forwarded; cookies/headers are not shared the same way.",
        ),
        "references": (
            Reference("OWASP Session Management Cheat Sheet", _CHEATSHEET + "Session_Management_Cheat_Sheet.html"),
        ),
    },
    "cleartext": {
        "steps": (
            "Serve login pages over HTTPS and post credentials only to an https:// endpoint.",
            "Redirect all HTTP traffic to HTTPS and enable HSTS with a long max-age.",
            "Never hard-code an absolute http:// form action for a form that carries credentials.",
        ),
        "example": CodeExample(
            lang="html",
            bad='<form action="http://api.example.com/login"><input type="password"></form>',
            good='<form action="https://api.example.com/login"><input type="password"></form>',
            note="Credentials on an http:// action travel unencrypted regardless of the page's own scheme.",
        ),
        "references": (
            Reference(
                "OWASP Transport Layer Security Cheat Sheet", _CHEATSHEET + "Transport_Layer_Security_Cheat_Sheet.html"
            ),
        ),
    },
}

# Detector findings carry no `family`; map their rule_id prefixes onto a guide key.
_RULE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("passive-missing-", "security_headers"),
    ("passive-insecure-cookie", "insecure_cookie"),
    ("passive-error-disclosure", "info_disclosure"),
    ("passive-tech-disclosure", "info_disclosure"),
    ("passive-directory-listing", "info_disclosure"),
    ("tech-fingerprint", "info_disclosure"),
    ("passive-cors-", "cors"),
    ("active-cors-", "cors"),
    ("authz-", "authz"),
    ("secret-", "secrets"),
    ("active-trace-", "xst"),
    ("active-dangerous-methods", "http_methods"),
    ("active-graphql-", "graphql"),
    ("active-sensitive-file", "sensitive_file"),
    ("dom-xss", "xss"),
)

_CWE_RE = re.compile(r"CWE-(\d+)")


def _cwe_reference(cwe: str) -> Reference | None:
    """Turn a 'CWE-89' label into a link to its MITRE definition page."""
    match = _CWE_RE.search(cwe or "")
    if not match:
        return None
    number = match.group(1)
    return Reference(f"CWE-{number}: definition", f"https://cwe.mitre.org/data/definitions/{number}.html")


def _resolve_key(target: RemediationTarget) -> str | None:
    if target.family and target.family in _GUIDES:
        return target.family
    for prefix, key in _RULE_PREFIXES:
        if target.rule_id.startswith(prefix):
            return key
    return None


def guide_for(target: RemediationTarget) -> RemediationGuide:
    """Build the rich remediation guide for a finding or correlated issue.

    The rule's own `remediation` is always the summary; steps, example and references
    come from the knowledge base when the family/rule is recognized. The CWE reference
    is appended automatically so every finding links to its authoritative definition.
    """
    entry = _GUIDES.get(_resolve_key(target) or "", {})
    references: list[Reference] = list(entry.get("references", ()))
    cwe_ref = _cwe_reference(target.cwe)
    if cwe_ref and all(cwe_ref.url != r.url for r in references):
        references.append(cwe_ref)
    return RemediationGuide(
        summary=target.remediation,
        steps=tuple(entry.get("steps", ())),
        example=entry.get("example"),
        references=tuple(references),
    )
