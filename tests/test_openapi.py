"""Phase 7: OpenAPI / Swagger ingestion."""
from __future__ import annotations

import httpx

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.discovery.openapi import fetch_and_parse_openapi, parse_openapi

_SCOPE = ScopeConfig(allow_domains=["127.0.0.1"])


def test_parse_openapi_3x_fills_path_param_from_example() -> None:
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/orders/{order_id}": {
                "get": {
                    "parameters": [
                        {"name": "order_id", "in": "path", "schema": {"type": "integer", "example": 101}}
                    ]
                }
            }
        },
    }
    requests = parse_openapi(spec, "http://t")
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert requests[0].url == "http://t/api/orders/101"


def test_parse_openapi_query_param_and_request_body() -> None:
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/search": {
                "get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string", "example": "x"}}]}
            },
            "/orders": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"type": "object", "properties": {"item": {"type": "string"}}}
                            }
                        }
                    }
                }
            },
        },
    }
    requests = {(r.method, r.url): r for r in parse_openapi(spec, "http://t")}
    assert requests[("GET", "http://t/search")].params == {"q": "x"}
    assert requests[("POST", "http://t/orders")].json_body == {"item": "test"}


def test_parse_swagger_2_0_body_param_and_basepath() -> None:
    spec = {
        "swagger": "2.0",
        "basePath": "/v2",
        "paths": {
            "/pets": {
                "post": {
                    "parameters": [
                        {"name": "body", "in": "body", "schema": {"type": "object", "properties": {"name": {"type": "string"}}}}
                    ]
                }
            }
        },
    }
    requests = parse_openapi(spec, "http://t")
    assert requests[0].url == "http://t/v2/pets"
    assert requests[0].json_body == {"name": "test"}


async def test_fetch_and_parse_openapi_from_target(vuln_app_url: str) -> None:
    async with HttpClient(_SCOPE) as client:
        requests = await fetch_and_parse_openapi(client, f"{vuln_app_url}/openapi.json", vuln_app_url)
    urls = {r.url for r in requests}
    assert any(u.endswith("/api/orders/101") for u in urls), urls
    assert any(u.endswith("/admin/stats") for u in urls)
    assert any(u.endswith("/api/internal/config") for u in urls)
