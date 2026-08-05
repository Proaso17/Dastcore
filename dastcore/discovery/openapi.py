"""OpenAPI / Swagger ingestion.

Parses an OpenAPI 3.x or Swagger 2.0 document into concrete `HttpRequest`s the
scanner and the authorization detector can exercise — filling path/query
parameters and request bodies with values derived from the schema (examples,
defaults, enums, or type-based placeholders). Schema-driven discovery reaches
API endpoints no crawler would ever find by following links.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin, urlsplit, urlunsplit

import yaml

from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def _example_from_schema(schema: dict | None) -> object:
    if not isinstance(schema, dict):
        return "test"
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    schema_type = schema.get("type")
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1.0
    if schema_type == "boolean":
        return True
    if schema_type == "array":
        return [_example_from_schema(schema.get("items", {}))]
    if schema_type == "object" or "properties" in schema:
        return {name: _example_from_schema(sub) for name, sub in (schema.get("properties") or {}).items()}
    return "test"


def _base_from_spec(spec: dict, target: str) -> str:
    """Resolve the API's base URL, honoring servers (3.x) / host+basePath (2.0)."""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict) and servers[0].get("url"):
        return urljoin(target, servers[0]["url"])
    # Swagger 2.0
    host = spec.get("host")
    base_path = spec.get("basePath", "")
    if host:
        scheme = (spec.get("schemes") or ["https"])[0]
        return f"{scheme}://{host}{base_path}"
    if base_path:
        parts = urlsplit(target)
        return urlunsplit((parts.scheme, parts.netloc, base_path, "", ""))
    return target


def _collect_params(operation: dict, path_item: dict) -> list[dict]:
    params: list[dict] = []
    for source in (path_item.get("parameters", []), operation.get("parameters", [])):
        for param in source:
            if isinstance(param, dict):
                params.append(param)
    return params


def _build_request(base: str, path: str, method: str, operation: dict, path_item: dict) -> HttpRequest:
    concrete_path = path
    query: dict[str, str] = {}
    json_body: dict | list | None = None
    body_data: dict[str, str] | None = None

    for param in _collect_params(operation, path_item):
        name = param.get("name")
        if not name:
            continue
        location = param.get("in")
        value = _example_from_schema(param.get("schema") or param)
        if location == "path":
            concrete_path = concrete_path.replace(f"{{{name}}}", str(value))
        elif location == "query":
            query[name] = str(value)
        elif location == "body":  # Swagger 2.0 body parameter
            example = _example_from_schema(param.get("schema"))
            if isinstance(example, dict):
                json_body = example

    request_body = operation.get("requestBody")  # OpenAPI 3.x
    if isinstance(request_body, dict):
        content = request_body.get("content", {})
        json_schema = content.get("application/json", {}).get("schema")
        form_schema = content.get("application/x-www-form-urlencoded", {}).get("schema")
        if json_schema is not None:
            example = _example_from_schema(json_schema)
            if isinstance(example, (dict, list)):
                json_body = example
        elif form_schema is not None:
            example = _example_from_schema(form_schema)
            if isinstance(example, dict):
                body_data = {k: str(v) for k, v in example.items()}

    url = urljoin(base.rstrip("/") + "/", concrete_path.lstrip("/"))
    return HttpRequest(
        method=method.upper(),  # type: ignore[arg-type]
        url=url,
        params=query,
        data=body_data,
        json_body=json_body,
    )


def parse_openapi(spec: dict, target: str) -> list[HttpRequest]:
    """Turn an OpenAPI/Swagger document into concrete requests."""
    base = _base_from_spec(spec, target)
    requests: list[HttpRequest] = []
    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if isinstance(operation, dict):
                requests.append(_build_request(base, path, method, operation, path_item))
    return requests


def _load_spec_text(text: str) -> dict:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return yaml.safe_load(text)


async def fetch_and_parse_openapi(http_client: HttpClient, spec_url: str, target: str) -> list[HttpRequest]:
    """Fetch an OpenAPI document over HTTP and parse it into requests."""
    response = await http_client.get(spec_url)
    spec = _load_spec_text(response.text)
    if not isinstance(spec, dict):
        return []
    return parse_openapi(spec, target)
