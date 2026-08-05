"""Triage suppressions: a `.dastcore-ignore` file to accept/ignore findings.

A suppression marks a finding as a known false-positive or an accepted risk so it
no longer fails the `--fail-on` CI gate. Suppressed findings are **not** deleted:
they stay in the JSON/SARIF audit trail (SARIF marks them as ``suppressions`` so
GitHub code scanning shows them dismissed rather than open), and only drop out of
the human-facing console/HTML views and the exit-code gate.

File format (either a top-level list or a ``suppressions:`` mapping)::

    suppressions:
      - rule_id: passive-missing-x-content-type-options
        reason: "Aceptado: lo fija el CDN en el edge"
      - id: "xss-reflected:GET:/legacy:query:q"
        reason: "Falso positivo conocido en el endpoint legacy"
      - rule_id: xss-reflected
        url: "*/legacy/*"
        reason: "Ruta legacy fuera de alcance"
        expires: 2026-12-31

An entry matches a finding when **every** field it specifies matches (``id`` exact,
``rule_id`` exact, ``url`` as an fnmatch glob against the request URL). An entry with
an ``expires`` date in the past is inactive, so stale suppressions auto-expire instead
of silently hiding regressions forever.
"""

from __future__ import annotations

import datetime as _dt
from fnmatch import fnmatch
from pathlib import Path

from pydantic import BaseModel, model_validator

from dastcore.core.models import Finding

DEFAULT_SUPPRESS_FILE = ".dastcore-ignore"


class Suppression(BaseModel):
    """One triage rule: silence findings matching all of its (given) criteria."""

    id: str | None = None
    rule_id: str | None = None
    url: str | None = None
    reason: str = ""
    expires: _dt.date | None = None

    @model_validator(mode="after")
    def _needs_a_selector(self) -> Suppression:
        if not (self.id or self.rule_id or self.url):
            raise ValueError("each suppression needs at least one of: id, rule_id, url")
        return self

    def is_expired(self, today: _dt.date) -> bool:
        return self.expires is not None and self.expires < today

    def matches(self, finding: Finding, today: _dt.date) -> bool:
        if self.is_expired(today):
            return False
        if self.id is not None and finding.id != self.id:
            return False
        if self.rule_id is not None and finding.rule_id != self.rule_id:
            return False
        if self.url is not None and not fnmatch(finding.request.url, self.url):
            return False
        return True


def _parse_items(data: object) -> list[Suppression]:
    if data is None:
        return []
    if isinstance(data, dict):
        items = data.get("suppressions") or []
    elif isinstance(data, list):
        items = data
    else:
        raise ValueError("el archivo de suppressions debe ser una lista o un mapeo con 'suppressions:'")
    if not isinstance(items, list):
        raise ValueError("'suppressions' debe ser una lista de reglas")
    return [Suppression.model_validate(item) for item in items]


def load_suppressions(path: str | Path) -> list[Suppression]:
    """Parse a suppressions file. Raises if it's missing or malformed."""
    import yaml

    text = Path(path).read_text(encoding="utf-8")
    return _parse_items(yaml.safe_load(text))


def resolve_suppressions(explicit_path: str = "") -> list[Suppression]:
    """Load suppressions from ``explicit_path`` if given, else auto-detect
    ``.dastcore-ignore`` in the working directory. Returns [] when neither exists.

    An explicitly requested path that doesn't exist is an error (the user asked for
    it); the auto-detected default is optional and simply absent when not present.
    """
    if explicit_path:
        return load_suppressions(explicit_path)
    default = Path(DEFAULT_SUPPRESS_FILE)
    if default.exists():
        return load_suppressions(default)
    return []


def apply_suppressions(
    findings: list[Finding],
    suppressions: list[Suppression],
    *,
    today: _dt.date | None = None,
) -> list[Finding]:
    """Mark every finding matched by a suppression (sets ``suppressed`` + reason).

    Mutates and returns the same list. The first matching suppression wins for the
    reason. A no-op when there are no suppressions.
    """
    if not suppressions:
        return findings
    today = today or _dt.date.today()
    for finding in findings:
        for suppression in suppressions:
            if suppression.matches(finding, today):
                finding.suppressed = True
                finding.suppression_reason = suppression.reason or "matched a triage suppression"
                break
    return findings
