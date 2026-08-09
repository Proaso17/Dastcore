"""Reflection-context analysis for reflected XSS.

A payload appearing in the response is *not* XSS on its own — it only matters if it
lands somewhere it can execute. This analyzer locates where a payload reflects (HTML
text, a tag attribute, a `<script>` block, an HTML comment, a raw-text element) and
decides whether, in that context, the payload actually breaks out into executable
markup/JS. Reflections that are escaped or land in inert contexts are dropped, which
is the main false-positive source for reflected XSS.

The bias is toward precision without new false negatives: when a reflection is raw in
HTML text and introduces a tag, it's executable; the "not executable" verdicts are
reserved for the clearly-inert cases (escaped, comment/raw-text with no breakout, a
quoted attribute the payload can't break out of, a bare string with no markup).
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

from dastcore.core.models import Evidence, HttpResponse

_INTRODUCES_TAG = re.compile(r"<[a-zA-Z]")
_EVENT_HANDLER = re.compile(r"\son\w+\s*=")
_SCRIPT_URL = re.compile(r"\s*(?:javascript|data):", re.IGNORECASE)
_RAWTEXT_TAGS = ("script", "style", "textarea", "title")
_URL_ATTRS = ("href", "src", "action", "formaction", "data", "poster")
_ATTR_NAME = re.compile(r"([a-zA-Z_:][\w:.-]*)\s*=\s*[\"']?[^\"'<>=]*$")


@dataclass
class ReflectionInfo:
    """Where a payload reflected and whether it can execute there."""

    reflected: bool  # payload appears verbatim (unescaped)
    context: str  # text | attribute | script | comment | rawtext | none
    executable: bool
    escaped: bool = False  # an HTML-escaped copy appears (inert reflection)


def _enclosing_quote(segment: str) -> str | None:
    """The quote char an offset sits inside, scanning a `<tag ...` segment."""
    quote: str | None = None
    for ch in segment:
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
    return quote


def _context_at(body: str, idx: int) -> tuple[str, str | None, str | None]:
    """Classify the HTML context at ``idx`` → (context, enclosing_quote, attr_name)."""
    prefix = body[:idx]
    low = prefix.lower()

    if low.rfind("<!--") > low.rfind("-->"):
        return "comment", None, None

    for tag in _RAWTEXT_TAGS:
        open_at = low.rfind("<" + tag)
        if open_at != -1 and open_at > low.rfind("</" + tag):
            gt = low.find(">", open_at)
            if gt != -1 and gt < idx:  # the opening tag is closed; we're in its content
                return ("script" if tag == "script" else "rawtext"), None, tag

    lt, gt = prefix.rfind("<"), prefix.rfind(">")
    if lt > gt and lt + 1 < len(prefix) and (prefix[lt + 1].isalpha() or prefix[lt + 1] == "/"):
        segment = prefix[lt:]
        attr_match = _ATTR_NAME.search(segment)
        attr = attr_match.group(1).lower() if attr_match else None
        return "attribute", _enclosing_quote(segment), attr

    return "text", None, None


def _executable(context: str, quote: str | None, attr: str | None, payload: str) -> bool:
    has_tag = _INTRODUCES_TAG.search(payload) is not None
    has_handler = _EVENT_HANDLER.search(" " + payload) is not None
    low = payload.lower()

    if context == "text":
        return has_tag
    if context == "comment":
        return "-->" in payload and has_tag
    if context == "rawtext":  # textarea/title/style: only closing THAT element breaks out
        return bool(attr) and f"</{attr}" in low and has_tag
    if context == "script":  # break out of the block or the surrounding JS string
        return "</script" in low or any(q in payload for q in ("'", '"', "`"))
    if context == "attribute":
        if attr in _URL_ATTRS and _SCRIPT_URL.match(payload):
            return True
        if quote:  # quoted value: need the same quote to escape it, then run something
            return quote in payload and (has_tag or has_handler or ">" in payload)
        return has_tag or has_handler or ">" in payload  # unquoted: any of these breaks out
    return has_tag


def analyze_reflection(body: str, payload: str) -> ReflectionInfo:
    """Locate ``payload`` in ``body`` and judge whether it can execute there."""
    if not payload:
        return ReflectionInfo(False, "none", False)
    if payload not in body:
        escaped = html.escape(payload) in body or html.escape(payload, quote=False) in body
        return ReflectionInfo(False, "none", False, escaped=escaped)

    last_context = "text"
    start = 0
    while (i := body.find(payload, start)) != -1:
        context, quote, attr = _context_at(body, i)
        if _executable(context, quote, attr, payload):
            return ReflectionInfo(True, context, True)
        last_context = context
        start = i + 1
    return ReflectionInfo(True, last_context, False)


def _executes_as_html(response: HttpResponse) -> bool:
    """Whether a reflected script could actually run — i.e. the browser renders the body
    as HTML. A reflection in a JSON/plain/CSS/JS response (e.g. an API validation error
    that echoes the input) can't execute, so it isn't XSS."""
    content_type = next((v for k, v in response.headers.items() if k.lower() == "content-type"), "").lower()
    if not content_type:
        return True  # no Content-Type: a browser may sniff the body as HTML
    return "html" in content_type or "xml" in content_type


def check_reflected_xss(response: HttpResponse, payload: str) -> Evidence | None:
    """Reflected-XSS oracle: fires only when the payload reflects unescaped into a
    context where it actually executes. Escaped or inert reflections, and reflections
    in a non-HTML response body, produce nothing."""
    if not _executes_as_html(response):
        return None
    info = analyze_reflection(response.text, payload)
    if info.reflected and info.executable:
        return Evidence(
            type="reflected",
            data=f"payload reflected unescaped in {info.context} context (executable)"[:200],
            confidence="high",
        )
    return None
