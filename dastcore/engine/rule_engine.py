"""Rule engine: loads YAML rule definitions and mutates injection points into payloaded requests.

A new injection detector is meant to be addable by writing a YAML file here
— nothing in this module is family-specific (no "if family == sqli" branches).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from dastcore.config import Severity
from dastcore.core.models import HttpRequest, InjectionLocation, InjectionPoint, Payload
from dastcore.validation.oracles import OracleSpec

DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


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
    oracle: OracleSpec
    confirm_reproducible: bool = True
    remediation: str

    @property
    def is_oob(self) -> bool:
        """True if this rule is confirmed out-of-band (has an `oob` oracle check)."""
        return any(check.type == "oob" for check in self.oracle.checks)


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
    for check in rule.oracle.checks:
        if check.payload:
            rendered = render_payload_template(check.payload, delay=check.delay)
            if rendered not in values:
                values.append(rendered)
    return [Payload(value=value, family=rule.family, oob=False) for value in values]


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
        json_body = dict(request.json_body) if isinstance(request.json_body, dict) else {}
        json_body[point.name] = payload_value
        return request.model_copy(update={"json_body": json_body})

    if point.location == "header":
        headers = dict(request.headers)
        headers[point.name] = payload_value
        return request.model_copy(update={"headers": headers})

    raise ValueError(f"Unsupported injection location for mutation: {point.location}")
