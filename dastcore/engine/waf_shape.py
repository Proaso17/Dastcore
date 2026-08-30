"""Alternative WAF-evasion by RESHAPING the request — complements ``engine/waf.py``'s payload tampers.

``waf.py`` rewrites the payload's *bytes* so a signature filter no longer recognises it. This module
keeps the payload **byte-for-byte identical** and instead changes *where and how the request carries
it*, to defeat a WAF that inspects only one parameter occurrence, or only one body format, while the
backend reads another:

  * **HTTP Parameter Pollution (HPP)** — the parameter is sent twice; the WAF inspects one occurrence,
    the backend uses the other. Last-wins and first-wins stacks differ, so both orders are tried.
  * **Location relocation** — a query parameter is re-sent inside a form or JSON body (and a body
    parameter is lifted up into the query string). Many WAFs scrutinise query strings far more than
    JSON bodies, and some only scan bodies — moving the payload crosses whichever boundary is watched.

Like the tamper path this is *only* a confirmation step, gated behind ``--waf-evasion``: a reshaped
variant is reported solely when its oracle fires on the backend's real behaviour, so it never adds
false positives — it can only reveal a vulnerability the WAF was masking.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from dastcore.core.models import HttpRequest, InjectionPoint


def _other_query_pairs(request: HttpRequest, exclude: str) -> list[tuple[str, str]]:
    """Every existing query pair (from the URL and from ``params``) except the injected name."""
    parts = urlsplit(request.url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != exclude]
    pairs += [(k, str(v)) for k, v in (request.params or {}).items() if k != exclude]
    return pairs


def _url_with_query(request: HttpRequest, pairs: list[tuple[str, str]]) -> str:
    parts = urlsplit(request.url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def reshaped_requests(point: InjectionPoint, payload: str) -> list[tuple[str, HttpRequest]]:
    """Return (name, request) variants that carry ``payload`` in an alternative request shape.

    The payload string is never altered — only the request structure changes. HPP variants put the
    whole query (with the duplicated parameter) into the URL and clear ``params`` so the wire order is
    deterministic; relocation variants move the parameter to another carrier."""
    req = point.request_template
    name = point.name
    benign = point.base_value or "1"
    variants: list[tuple[str, HttpRequest]] = []

    if point.location == "query":
        others = _other_query_pairs(req, name)
        # HPP: the same parameter twice, both orders (last-wins vs first-wins backends).
        for label, dup in (
            ("hpp-payload-last", [(name, benign), (name, payload)]),
            ("hpp-payload-first", [(name, payload), (name, benign)]),
        ):
            url = _url_with_query(req, others + dup)
            variants.append((label, req.model_copy(update={"url": url, "params": {}})))
        # Relocation: carry the payload in a JSON / form body instead of the query string.
        clean_url = _url_with_query(req, others)
        json_body = {**(req.json_body if isinstance(req.json_body, dict) else {}), name: payload}
        variants.append(("relocate-json", req.model_copy(update={
            "method": "POST", "url": clean_url, "params": {}, "json_body": json_body, "data": None})))
        form = {**(req.data or {}), name: payload}
        variants.append(("relocate-form", req.model_copy(update={
            "method": "POST", "url": clean_url, "params": {}, "data": form, "json_body": None})))

    elif point.location in ("body", "json"):
        # Lift a body parameter up into the query string — the complementary crossing for WAFs that
        # only scan request bodies.
        parts = urlsplit(req.url)
        existing = parse_qsl(parts.query, keep_blank_values=True)
        url = _url_with_query(req, existing + [(name, payload)])
        variants.append(("relocate-query", req.model_copy(update={"url": url})))

    return variants
