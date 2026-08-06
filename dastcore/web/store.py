"""SQLite persistence for the web dashboard.

One row per scan run. Findings are stored as the same JSON array the CLI's
``-f json`` report produces, so a run can be re-hydrated into `Finding` objects
for the UI (or downloaded verbatim). Access is serialized behind a lock: the app
is single-process and every call runs on the event-loop thread, so a single
connection guarded by a lock is enough and keeps the store dependency-free.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path

from dastcore.core.models import Finding

_SEVERITIES = ("critical", "high", "medium", "low", "info")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    engine          TEXT NOT NULL,
    profile         TEXT,
    status          TEXT NOT NULL,
    created_at      REAL NOT NULL,
    finished_at     REAL,
    duration_s      REAL,
    num_findings    INTEGER NOT NULL DEFAULT 0,
    severity_counts TEXT NOT NULL DEFAULT '{}',
    error           TEXT,
    findings_json   TEXT NOT NULL DEFAULT '[]'
);
"""


@dataclass
class ScanRow:
    """A persisted scan run (without its findings blob, unless loaded on demand)."""

    id: str
    target: str
    engine: str
    profile: str | None
    status: str  # running | done | error | interrupted
    created_at: float
    finished_at: float | None = None
    duration_s: float | None = None
    num_findings: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    error: str | None = None


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Count findings per severity (always includes every severity key)."""
    counts = dict.fromkeys(_SEVERITIES, 0)
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    return counts


class Store:
    """Thread-safe (single-connection + lock) SQLite store of scan runs."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = str(db_path)
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def _row_to_scan(self, row: sqlite3.Row) -> ScanRow:
        return ScanRow(
            id=row["id"],
            target=row["target"],
            engine=row["engine"],
            profile=row["profile"],
            status=row["status"],
            created_at=row["created_at"],
            finished_at=row["finished_at"],
            duration_s=row["duration_s"],
            num_findings=row["num_findings"],
            severity_counts=json.loads(row["severity_counts"] or "{}"),
            error=row["error"],
        )

    def insert_running(self, scan_id: str, target: str, engine: str, profile: str | None, created_at: float) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO scans (id, target, engine, profile, status, created_at) VALUES (?, ?, ?, ?, 'running', ?)",
                (scan_id, target, engine, profile, created_at),
            )

    def mark_done(self, scan_id: str, finished_at: float, duration_s: float, findings: list[Finding]) -> None:
        counts = severity_counts(findings)
        findings_json = json.dumps([f.model_dump(mode="json") for f in findings], ensure_ascii=False)
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE scans SET status='done', finished_at=?, duration_s=?, num_findings=?, "
                "severity_counts=?, findings_json=? WHERE id=?",
                (finished_at, duration_s, len(findings), json.dumps(counts), findings_json, scan_id),
            )

    def mark_error(self, scan_id: str, finished_at: float, duration_s: float, error: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE scans SET status='error', finished_at=?, duration_s=?, error=? WHERE id=?",
                (finished_at, duration_s, error, scan_id),
            )

    def mark_interrupted_running(self) -> None:
        """Flip any 'running' rows to 'interrupted' — a scan can't survive a restart."""
        with self._lock, self._conn:
            self._conn.execute("UPDATE scans SET status='interrupted' WHERE status='running'")

    def list_scans(self, limit: int = 100) -> list[ScanRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_scan(row) for row in rows]

    def get_scan(self, scan_id: str) -> ScanRow | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return self._row_to_scan(row) if row else None

    def get_findings_json(self, scan_id: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT findings_json FROM scans WHERE id=?", (scan_id,)).fetchone()
        return row["findings_json"] if row else None

    def get_findings(self, scan_id: str) -> list[Finding]:
        raw = self.get_findings_json(scan_id)
        if not raw:
            return []
        return [Finding.model_validate(item) for item in json.loads(raw)]
