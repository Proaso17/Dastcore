"""Incremental finding persistence: append each finding to a JSONL file the moment it's found.

Even with graceful budget/network handling, a hard interruption (Ctrl+C, kill, power loss) during a
long scan would lose everything gathered in memory — the final report is only written at the very end.
This sink writes one JSON line per finding as the scan progresses and flushes immediately, so the work
survives any interruption. Read it back later with ``load_jsonl`` (e.g. to resume or salvage a report).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dastcore.core.models import Finding


class FindingSink:
    """Append findings to a JSONL file as they're discovered (deduplicated by finding id)."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._seen: set[str] = set()
        self._fh = None

    def open(self) -> FindingSink:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self._path.open("w", encoding="utf-8")
        return self

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> FindingSink:
        return self.open()

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.close()

    def write(self, findings: Iterable[Finding]) -> None:
        """Append any not-yet-written findings and flush so they survive an interruption."""
        if self._fh is None:
            return
        wrote = False
        for finding in findings:
            if finding.id in self._seen:
                continue
            self._seen.add(finding.id)
            self._fh.write(json.dumps(finding.model_dump(mode="json"), ensure_ascii=False) + "\n")
            wrote = True
        if wrote:
            self._fh.flush()


def load_jsonl(path: str | Path) -> list[Finding]:
    """Read findings back from a JSONL file written by :class:`FindingSink`."""
    from dastcore.core.models import Finding

    source = Path(path)
    if not source.exists():
        return []
    findings: list[Finding] = []
    for line in source.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            findings.append(Finding.model_validate(json.loads(line)))
    return findings
