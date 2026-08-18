"""C7: API schema auto-discovery — find OpenAPI/Swagger docs and GraphQL endpoints, zero-FP."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from dastcore.core.models import HttpResponse
from dastcore.discovery.api_probe import probe_api_schemas


class _FakeClient:
    def __init__(self, pages: dict[str, tuple[int, str, dict[str, str]]]) -> None:
        self.pages = pages

    def is_in_scope(self, url: str) -> bool:
        return True

    async def get(self, url: str) -> HttpResponse:
        status, body, headers = self.pages.get(urlsplit(url).path, (404, "not found", {}))
        return HttpResponse(method="GET", status_code=status, headers=headers, text=body, url=url)

    async def post(self, url: str, json: object = None) -> HttpResponse:  # noqa: A002
        status, body, headers = self.pages.get(urlsplit(url).path, (404, "not found", {}))
        return HttpResponse(method="POST", status_code=status, headers=headers, text=body, url=url)


_JSON = {"content-type": "application/json"}


async def test_finds_an_openapi_document() -> None:
    doc = json.dumps({"openapi": "3.0.0", "info": {}, "paths": {"/api/users": {"get": {}}}})
    client = _FakeClient({"/openapi.json": (200, doc, _JSON)})
    openapi, graphql = await probe_api_schemas(client, ["http://api.test/"])  # type: ignore[arg-type]
    assert any(u.endswith("/openapi.json") for u in openapi)
    assert graphql == []


async def test_finds_a_graphql_endpoint() -> None:
    client = _FakeClient({"/graphql": (200, '{"data":{"__typename":"Query"}}', _JSON)})
    openapi, graphql = await probe_api_schemas(client, ["http://api.test/"])  # type: ignore[arg-type]
    assert any(u.endswith("/graphql") for u in graphql)


async def test_plain_json_endpoint_is_not_mistaken_for_a_schema() -> None:
    # a health endpoint that returns JSON but isn't an OpenAPI doc must be ignored (zero-FP)
    client = _FakeClient({"/openapi.json": (200, '{"status":"ok"}', _JSON)})
    openapi, graphql = await probe_api_schemas(client, ["http://api.test/"])  # type: ignore[arg-type]
    assert openapi == [] and graphql == []
