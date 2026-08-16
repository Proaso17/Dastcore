"""Load a bug-bounty ``Program`` from a ``program.yaml`` file."""

from __future__ import annotations

from pathlib import Path

import yaml

from dastcore.bugbounty.program import Program


def load_program(path: str | Path) -> Program:
    """Parse and validate a program definition from YAML."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return Program.model_validate(data)
