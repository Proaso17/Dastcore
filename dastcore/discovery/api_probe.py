"""API schema auto-discovery.

The real attack surface of a SaaS is its API, but it's only scanned today if the user hands dastcore
an ``--openapi-url`` / ``--graphql-url``. This probes each in-scope host for the well-known locations of
an OpenAPI/Swagger document or a GraphQL endpoint, so the whole documented API is found and tested
automatically — no need to know the schema URL up front.

Zero false positives: an OpenAPI hit must actually parse as an OpenAPI/Swagger document (``openapi``/
``swagger`` + ``paths``), and a GraphQL hit must genuinely answer a ``{__typename}`` query. The endpoints
are then fed into the normal crawl/scan and the existing (oracle-backed) GraphQL checks.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin

import httpx

from dastcore.core.http_client import HttpClient, OutOfScopeError

_OPENAPI_PATHS = [
    "openapi.json", "swagger.json", "api-docs", "v2/api-docs", "v3/api-docs",
    "swagger/v1/swagger.json", "api/openapi.json", "api/swagger.json", "api-docs/swagger.json",
    "openapi.yaml", "swagger.yaml", "docs/openapi.json", "swagger/doc.json", "api/docs",
]
_GRAPHQL_PATHS = ["graphql", "api/graphql", "v1/graphql", "query", "graphql/console"]


def _looks_like_openapi(response: httpx.Response | object) -> bool:
    """True only if the body genuinely parses as an OpenAPI/Swagger document."""
    status = getattr(response, "status_code", 0)
    text = getattr(response, "text", "") or ""
    headers = {k.lower(): v for k, v in getattr(response, "headers", {}).items()}
    if status != 200:
        return False
    if "json" in headers.get("content-type", "").lower() or text.lstrip().startswith("{"):
        try:
            doc = json.loads(text)
        except ValueError:
            return False
        return isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) and "paths" in doc
    head = "\n".join(text.splitlines()[:6]).lower()
    return ("openapi:" in head or "swagger:" in head) and "paths:" in text.lower()


async def _is_graphql(client: HttpClient, url: str) -> bool:
    """True if the endpoint answers a GraphQL ``{__typename}`` query (or errors like GraphQL does)."""
    try:
        response = await client.post(url, json={"query": "{__typename}"})
    except (OutOfScopeError, httpx.HTTPError, OSError):
        return False
    if response.status_code not in (200, 400):
        return False
    text = response.text or ""
    low = text.lower()
    return (
        "__typename" in text
        or ("graphql" in low and ("errors" in low or "query" in low))
        or ("must provide" in low and "query" in low)
    )


async def probe_api_schemas(client: HttpClient, roots: list[str]) -> tuple[list[str], list[str]]:
    """Find OpenAPI/Swagger documents and GraphQL endpoints under each root. Returns (openapi, graphql)."""
    openapi: list[str] = []
    graphql: list[str] = []
    seen: set[str] = set()
    for root in roots:
        base = root if root.endswith("/") else root + "/"
        for path in _OPENAPI_PATHS:
            url = urljoin(base, path)
            if url in seen:
                continue
            seen.add(url)
            try:
                response = await client.get(url)
            except (OutOfScopeError, httpx.HTTPError, OSError):
                continue
            if _looks_like_openapi(response):
                openapi.append(url)
        for path in _GRAPHQL_PATHS:
            url = urljoin(base, path)
            if url in seen:
                continue
            seen.add(url)
            if await _is_graphql(client, url):
                graphql.append(url)
    return openapi, graphql
