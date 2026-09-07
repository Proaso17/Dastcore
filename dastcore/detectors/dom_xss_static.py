"""Static DOM-XSS taint analysis. CWE-79, OWASP WSTG-CLNT-01.

Complements the dynamic DOM-XSS detector (which *runs* the page headlessly): this parses the JavaScript
into an AST and tracks data flow from an attacker-controllable **source** (``location.hash``,
``document.referrer``, ``window.name``, …) into a dangerous **sink** (``innerHTML``, ``document.write``,
``eval``, ``insertAdjacentHTML``, jQuery ``.html()``, …) — catching flows a runtime trigger might not
exercise. Static analysis is inherently more false-positive-prone than execution (Burp says the same),
so we stay CONSERVATIVE: taint only propagates through direct use, single-variable assignment, string
concatenation/templating and taint-preserving string methods; a known sanitizer (``encodeURIComponent``,
``DOMPurify.sanitize``, ``Number``…), an angle-bracket-stripping ``replace``, or any unknown function
UNtaints. Findings are reported at *medium* confidence so ``--min-confidence`` can filter them.

Requires the optional ``esprima`` parser; without it (or on un-parseable modern/minified bundles) the
check simply yields nothing — never a crash.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx
from selectolax.parser import HTMLParser

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_MAX_SCRIPTS = 60        # bound the scripts analysed per scan
_MAX_JS_BYTES = 400_000  # skip huge bundles (usually minified modern ES the parser rejects anyway)

# Attacker-controllable DOM sources (dotted member paths, lowercased).
_SOURCES = frozenset({
    "location.hash", "location.search", "location.href", "location.pathname", "location.hostname",
    "document.url", "document.documenturi", "document.baseuri", "document.referrer", "document.cookie",
    "window.name", "window.location.hash", "window.location.search", "window.location.href",
    "document.location.hash", "document.location.search", "document.location.href",
})
# Calls that render input safe → they UNtaint their result.
_SANITIZERS = frozenset({
    "encodeuricomponent", "encodeuri", "escape", "number", "parseint", "parsefloat",
    "dompurify.sanitize", "sanitizehtml", "sanitize", "json.stringify", "btoa",
})
# Property assignment sinks (``x.innerHTML = tainted``).
_PROP_SINKS = frozenset({"innerhtml", "outerhtml"})
# Global/known call sinks, matched by full dotted name → index of the argument that reaches the parser.
_GLOBAL_CALL_SINKS = {
    "document.write": 0, "document.writeln": 0, "eval": 0, "window.eval": 0,
    "settimeout": 0, "setinterval": 0,
}
# Method sinks, matched by the bare method name on ANY object (``el.insertAdjacentHTML``, ``$(x).html``).
_METHOD_CALL_SINKS = {"insertadjacenthtml": 1, "html": 0}
# Taint-preserving string methods (the result still carries the tainted substring).
_STRING_METHODS = frozenset({
    "substring", "substr", "slice", "tolowercase", "touppercase", "trim", "charat", "concat",
    "padstart", "padend", "tostring", "normalize", "trimstart", "trimend", "at",
})


def _member_path(node: object) -> str | None:
    """Dotted path of a non-computed member/identifier (``a.b.c``), lowercased; None if computed/other."""
    t = getattr(node, "type", None)
    if t == "Identifier":
        return getattr(node, "name", "").lower()
    if t == "ThisExpression":
        return "this"
    if t == "MemberExpression" and not getattr(node, "computed", False):
        base = _member_path(node.object)
        prop = getattr(node.property, "name", None)
        return f"{base}.{prop.lower()}" if base is not None and prop else None
    return None


def _method_name(callee: object) -> str:
    """The bare, lowercased name of the thing being called: the tail property of ``a.b.method`` ->
    ``method``, or a plain identifier ``eval`` -> ``eval``. Empty for computed/other callees."""
    t = getattr(callee, "type", None)
    if t == "Identifier":
        return (getattr(callee, "name", "") or "").lower()
    if t == "MemberExpression" and not getattr(callee, "computed", False):
        return (getattr(callee.property, "name", "") or "").lower()
    return ""


class _Analyzer:
    def __init__(self) -> None:
        self.flows: list[tuple[str, str, int]] = []  # (sink, source description, line)

    # --- taint of an expression under the current variable-taint map -------------------------
    def tainted_source(self, node: object, taint: dict[str, str]) -> str | None:
        """Return a short description of the source tainting ``node``, or None if it is not tainted."""
        if node is None:
            return None
        t = getattr(node, "type", None)
        if t == "Identifier":
            return taint.get(getattr(node, "name", ""))
        if t == "MemberExpression":
            path = _member_path(node)
            if path in _SOURCES:
                return path
            return self.tainted_source(node.object, taint)  # x.foo where x is tainted
        if t == "CallExpression":
            full = _member_path(node.callee) or ""
            method = _method_name(node.callee)
            if full in _SANITIZERS or method in _SANITIZERS:
                return None
            if method == "replace" and self._replace_strips_html(node):
                return None
            if getattr(node.callee, "type", None) == "MemberExpression" and (
                method in _STRING_METHODS or method == "replace"
            ):
                return self.tainted_source(node.callee.object, taint)  # tainted.substring()/.replace() stays tainted
            return None  # any other (unknown) function untaints — conservative, avoids false positives
        if t in ("BinaryExpression", "LogicalExpression") and getattr(node, "operator", "") in ("+", "||", "&&", "??"):
            return self.tainted_source(node.left, taint) or self.tainted_source(node.right, taint)
        if t == "ConditionalExpression":
            return self.tainted_source(node.consequent, taint) or self.tainted_source(node.alternate, taint)
        if t == "TemplateLiteral":
            for expr in getattr(node, "expressions", []) or []:
                src = self.tainted_source(expr, taint)
                if src:
                    return src
        if t == "AssignmentExpression":
            return self.tainted_source(node.right, taint)
        return None

    @staticmethod
    def _replace_strips_html(call: object) -> bool:
        """A ``.replace(...)`` whose pattern removes angle brackets/script is treated as a sanitizer."""
        for arg in getattr(call, "arguments", []) or []:
            if getattr(arg, "type", None) == "Literal":
                raw = str(getattr(arg, "value", "") or getattr(arg, "regex", "") or "")
                if any(c in raw for c in ("<", ">", "&", "script")):
                    return True
            if getattr(arg, "type", None) == "Identifier" and any(
                c in (getattr(arg, "name", "") or "").lower() for c in ("<", ">")
            ):
                return True
        return False

    def _line(self, node: object) -> int:
        loc = getattr(node, "loc", None)
        return getattr(getattr(loc, "start", None), "line", 0) if loc else 0

    # --- sink detection on a single expression ----------------------------------------------
    def check_sink(self, node: object, taint: dict[str, str]) -> None:
        t = getattr(node, "type", None)
        if t == "AssignmentExpression" and getattr(node.left, "type", None) == "MemberExpression":
            prop = (getattr(node.left.property, "name", "") or "").lower()
            if prop in _PROP_SINKS and not getattr(node.left, "computed", False):
                src = self.tainted_source(node.right, taint)
                if src:
                    self.flows.append((f".{prop}", src, self._line(node)))
        elif t in ("CallExpression", "NewExpression"):
            full = _member_path(node.callee)  # e.g. "document.write", None if computed
            method = _method_name(node.callee)  # bare method name for a.b.method(...)
            label = full or method
            if t == "NewExpression" and (full == "function" or method == "function"):
                idx, label = 0, "Function"  # new Function(str) ~ eval
            else:
                idx = _GLOBAL_CALL_SINKS.get(full or "")
                if idx is None:
                    idx = _METHOD_CALL_SINKS.get(method)
            if idx is not None:
                args = getattr(node, "arguments", []) or []
                if len(args) > idx:
                    src = self.tainted_source(args[idx], taint)
                    if src:
                        self.flows.append((f"{label}()", src, self._line(node)))

    # --- flow-sensitive walk, one variable-taint map per function scope ----------------------
    def walk(self, node: object, taint: dict[str, str], depth: int = 0) -> None:
        if node is None or depth > 300:
            return
        t = getattr(node, "type", None)
        if t is None:
            return

        # Update the taint map on declarations/assignments (statement order = flow order).
        if t == "VariableDeclaration":
            for decl in getattr(node, "declarations", []) or []:
                self._assign(getattr(decl.id, "name", None), decl.init, taint)
                self.walk(decl.init, taint, depth + 1)  # catch sinks inside the initializer (var x = eval(src))
            return
        if t == "ExpressionStatement":
            self.walk(node.expression, taint, depth + 1)
            return
        if t == "AssignmentExpression":
            self.check_sink(node, taint)
            if getattr(node.left, "type", None) == "Identifier" and node.operator == "=":
                self._assign(node.left.name, node.right, taint)
            self.walk(node.right, taint, depth + 1)
            return
        if t in ("CallExpression", "NewExpression"):
            self.check_sink(node, taint)

        # New function scope: inherit a copy of the current taint so outer tainted vars still apply.
        if t in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
            self.walk(getattr(node, "body", None), dict(taint), depth + 1)
            return

        for child in self._children(node):
            self.walk(child, taint, depth + 1)

    def _assign(self, name: str | None, value: object, taint: dict[str, str]) -> None:
        if not name:
            return
        if value is not None and self.tainted_source(value, taint):
            taint[name] = self.tainted_source(value, taint) or "?"
        else:
            taint.pop(name, None)  # reassigned to something safe → no longer tainted

    @staticmethod
    def _children(node: object):
        for attr in getattr(node, "__dict__", {}).values() if hasattr(node, "__dict__") else []:
            if isinstance(attr, list):
                for item in attr:
                    if hasattr(item, "type"):
                        yield item
            elif hasattr(attr, "type"):
                yield attr


def analyze_js(code: str) -> list[tuple[str, str, int]]:
    """Return (sink, source, line) taint flows in ``code``; empty if esprima is absent or parsing fails."""
    if not code or len(code) > _MAX_JS_BYTES:
        return []
    try:
        import esprima
    except ImportError:
        return []
    try:
        tree = esprima.parseScript(code, {"loc": True, "tolerant": True})
    except Exception:  # noqa: BLE001 — a parse error (modern/minified syntax) just means no static result
        return []
    analyzer = _Analyzer()
    analyzer.walk(tree, {})
    # Dedupe identical (sink, source) flows, keep first line.
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str, int]] = []
    for sink, src, line in analyzer.flows:
        if (sink, src) not in seen:
            seen.add((sink, src))
            out.append((sink, src, line))
    return out


def _finding(url: str, sink: str, source: str, line: int) -> Finding:
    request = HttpRequest(method="GET", url=url)
    return Finding(
        id=f"dom-xss-static:{url}:{sink}:{source}",
        rule_id="dom-xss-static",
        name="DOM-based XSS (static taint analysis)",
        severity="high",
        cwe="CWE-79",
        owasp="WSTG-CLNT-01",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        family="xss",
        injection_point=InjectionPoint(location="query", name=source, base_value="", request_template=request),
        evidence=[Evidence(
            type="static",
            data=(f"flujo de taint estático en {url}{f' (línea {line})' if line else ''}: la fuente "
                  f"'{source}' (controlable por el atacante) llega al sink '{sink}' sin sanear — XSS basado en DOM")[:300],
            confidence="medium",  # static analysis is FP-prone vs execution → filterable via --min-confidence
        )],
        request=request,
        response=HttpResponse(status_code=0, url=url),
        remediation=(
            "No pases fuentes DOM no confiables (location.hash/search, document.referrer, window.name) a sinks "
            "HTML/JS (innerHTML, document.write, eval, insertAdjacentHTML). Usa textContent, o sanea con "
            "DOMPurify.sanitize antes de asignar HTML."
        ),
    )


def _scripts_from_html(base_url: str, html: str) -> tuple[list[str], list[str]]:
    """(inline script bodies, same-origin external .js URLs) from an HTML page."""
    tree = HTMLParser(html)
    inline: list[str] = []
    external: list[str] = []
    origin = urlsplit(base_url)
    for node in tree.css("script"):
        src = node.attributes.get("src")
        if src:
            from urllib.parse import urljoin
            absolute = urljoin(base_url, src)
            if urlsplit(absolute).netloc == origin.netloc and absolute.split("?")[0].endswith((".js", ".mjs")):
                external.append(absolute)
        elif node.text():
            inline.append(node.text())
    return inline, external


async def run_dom_xss_static_checks(client: HttpClient, requests: list[HttpRequest]) -> list[Finding]:
    """Fetch discovered HTML pages + their same-origin scripts and report source→sink DOM-XSS taint flows."""
    findings: list[Finding] = []
    seen_finding: set[str] = set()
    analysed = 0
    page_urls = dict.fromkeys(r.url for r in requests if r.method == "GET" and not r.json_body)
    for page_url in page_urls:
        if analysed >= _MAX_SCRIPTS:
            break
        try:
            resp = await client.get(page_url)
        except (OutOfScopeError, httpx.HTTPError):
            continue
        except BudgetExceededError:
            break
        if "html" not in resp.headers.get("content-type", ""):
            continue
        inline, external = _scripts_from_html(page_url, resp.text)
        scripts: list[tuple[str, str]] = [(page_url, js) for js in inline]
        for js_url in external:
            if analysed >= _MAX_SCRIPTS:
                break
            try:
                js_resp = await client.get(js_url)
            except (OutOfScopeError, httpx.HTTPError):
                continue
            except BudgetExceededError:
                break
            scripts.append((js_url, js_resp.text))
        for origin_url, js in scripts:
            analysed += 1
            for sink, source, line in analyze_js(js):
                key = f"{origin_url}:{sink}:{source}"
                if key not in seen_finding:
                    seen_finding.add(key)
                    findings.append(_finding(origin_url, sink, source, line))
    return findings
