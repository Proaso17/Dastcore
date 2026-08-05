"""JSON report renderer."""

from __future__ import annotations

import json

from dastcore.core.models import Finding


def render_json(findings: list[Finding], *, indent: int = 2) -> str:
    """Serialize findings to a stable, pretty-printed JSON array."""
    return json.dumps(
        [finding.model_dump(mode="json") for finding in findings],
        indent=indent,
        ensure_ascii=False,
    )
