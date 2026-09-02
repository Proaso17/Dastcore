"""Rule engine: loads YAML rule definitions and mutates injection points into payloaded requests.

A new injection detector is meant to be addable by writing a YAML file here
— nothing in this module is family-specific (no "if family == sqli" branches).
"""

from __future__ import annotations

import copy
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import yaml
from pydantic import BaseModel, Field

from dastcore.config import Severity
from dastcore.core.models import HttpRequest, InjectionLocation, InjectionPoint, Payload
from dastcore.validation.oracles import OracleSpec

DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class BooleanPair(BaseModel):
    """A pair of logically-opposite conditions for boolean-based blind detection.

    ``{{base}}`` is replaced with the injection point's original value, so the TRUE
    condition should behave like the untouched request and the FALSE one differ.
    """

    when_true: str
    when_false: str


class Rule(BaseModel):
    """A single declarative detector, parsed straight from a rules/*.yaml file."""

    id: str
    name: str
    family: str
    severity: Severity
    cwe: str
    owasp: str
    inject_into: list[InjectionLocation]
    payloads: list[str] = Field(default_factory=list)
    oracle: OracleSpec | None = None
    boolean_pairs: list[BooleanPair] = Field(default_factory=list)
    confirm_reproducible: bool = True
    # Soft-404 guard: drop a hit when the endpoint returns the same response for a
    # random junk value (a catch-all that ignores the parameter). For file/id rules.
    catch_all_guard: bool = False
    remediation: str
    cvss: str | None = None

    @property
    def is_oob(self) -> bool:
        """True if this rule is confirmed out-of-band (has an `oob` oracle check)."""
        return self.oracle is not None and any(check.type == "oob" for check in self.oracle.checks)

    @property
    def is_boolean(self) -> bool:
        """True if this rule is confirmed by a boolean TRUE/FALSE differential."""
        return bool(self.boolean_pairs)


_OAST_PLACEHOLDERS = ("{{oast_url}}", "{{oast_domain}}", "{{oast_token}}")


def oob_payload_templates(rule: Rule) -> list[str]:
    """Payload templates carrying an OAST placeholder, to be substituted per probe."""
    return [payload for payload in rule.payloads if any(p in payload for p in _OAST_PLACEHOLDERS)]


def load_rule(path: Path) -> Rule:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Rule.model_validate(data)


def load_rules(directory: Path | None = None) -> list[Rule]:
    directory = directory or DEFAULT_RULES_DIR
    return [load_rule(path) for path in sorted(directory.glob("*.yaml"))]


def render_payload_template(template: str, *, delay: float | None = None) -> str:
    rendered = template
    if delay is not None:
        rendered = rendered.replace("{{delay}}", str(int(delay)))
    return rendered


def applicable_payloads(rule: Rule) -> list[Payload]:
    """Every payload this rule will try: the declared `payloads`, plus any oracle
    check's own templated `payload` (e.g. a time-based SLEEP() probe)."""
    values: list[str] = list(rule.payloads)
    for check in rule.oracle.checks if rule.oracle else []:
        if check.payload:
            rendered = render_payload_template(check.payload, delay=check.delay)
            if rendered not in values:
                values.append(rendered)
    return [Payload(value=value, family=rule.family, oob=False) for value in values]


def inband_payloads(rule: Rule) -> list[Payload]:
    """Only the declared in-band payloads. Timing probes (a check's own templated
    `payload`) are driven separately by the scanner's proportional-delay confirmation,
    so they are deliberately excluded here."""
    return [Payload(value=value, family=rule.family, oob=False) for value in rule.payloads]


def build_mutated_request(point: InjectionPoint, payload_value: str) -> HttpRequest:
    """Returns a copy of the point's request_template with exactly this one parameter replaced."""
    request = point.request_template

    if point.location == "query":
        params = dict(request.params)
        params[point.name] = payload_value
        return request.model_copy(update={"params": params})

    if point.location == "body":
        data = dict(request.data or {})
        data[point.name] = payload_value
        return request.model_copy(update={"data": data})

    if point.location == "json":
        # Deep-copy the body and set the value at the point's dotted path (``a.b.0.c`` navigates nested
        # objects/arrays), so nested-JSON injection points mutate exactly one leaf.
        root = copy.deepcopy(request.json_body) if isinstance(request.json_body, (dict, list)) else {}
        _set_json_path(root, point.name, payload_value)
        return request.model_copy(update={"json_body": root})

    if point.location == "path":
        # Replace the injected path segment and rebuild the URL (IDOR/SQLi/traversal on /api/orders/123).
        parts = urlsplit(request.url)
        segs = parts.path.split("/")
        idx = int(point.name)
        if 0 <= idx < len(segs):
            segs[idx] = payload_value  # raw — httpx normalises; traversal payloads keep their slashes
        new_url = urlunsplit((parts.scheme, parts.netloc, "/".join(segs), parts.query, parts.fragment))
        return request.model_copy(update={"url": new_url})

    if point.location == "header":
        headers = dict(request.headers)
        headers[point.name] = payload_value
        return request.model_copy(update={"headers": headers})

    raise ValueError(f"Unsupported injection location for mutation: {point.location}")


def _set_json_path(root: object, path: str, value: str) -> None:
    """Set ``value`` at ``path`` (dot-separated: dict keys and list indices) inside a JSON structure,
    in place. A single-segment path (a top-level key) works too."""
    keys = path.split(".")
    node: object = root
    for key in keys[:-1]:
        node = node[int(key)] if isinstance(node, list) else node[key]  # type: ignore[index]
    last = keys[-1]
    if isinstance(node, list):
        node[int(last)] = value
    elif isinstance(node, dict):
        node[last] = value
