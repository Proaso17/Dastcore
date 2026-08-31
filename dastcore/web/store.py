"""SQLite persistence for the web dashboard.

One row per scan run. Findings are stored as the same JSON array the CLI's
``-f json`` report produces, so a run can be re-hydrated into `Finding` objects
for the UI (or downloaded verbatim). Access is serialized behind a lock: the app
is single-process and every call runs on the event-loop thread, so a single
connection guarded by a lock is enough and keeps the store dependency-free.
"""

from __future__ import annotations

import datetime as _dt
import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from dastcore.bugbounty.program import Program
from dastcore.core.models import Finding
from dastcore.suppressions import Suppression

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
    findings_json   TEXT NOT NULL DEFAULT '[]',
    kind            TEXT NOT NULL DEFAULT 'scan',
    parent_id       TEXT,
    retest_json     TEXT
);

CREATE TABLE IF NOT EXISTS suppressions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT,
    finding_id  TEXT,
    url         TEXT,
    reason      TEXT NOT NULL DEFAULT '',
    expires     TEXT,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS schedules (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    target           TEXT NOT NULL,
    engine           TEXT NOT NULL DEFAULT 'http',
    profile          TEXT,
    rps              REAL NOT NULL DEFAULT 5.0,
    auth_bearer      TEXT,
    auth_cookie      TEXT,
    interval_minutes INTEGER NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       REAL NOT NULL,
    last_run_at      REAL,
    next_run_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS programs (
    id           TEXT PRIMARY KEY,
    handle       TEXT NOT NULL,
    platform     TEXT NOT NULL DEFAULT 'self',
    program_json TEXT NOT NULL,
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_settings (
    id           INTEGER PRIMARY KEY CHECK (id = 1),  -- single-row config
    webhook_url  TEXT NOT NULL DEFAULT '',
    fmt          TEXT NOT NULL DEFAULT 'slack',       -- slack | discord | generic
    min_severity TEXT NOT NULL DEFAULT 'medium',
    enabled      INTEGER NOT NULL DEFAULT 0
);
"""

# Columns added after the initial release; applied to pre-existing DBs on open.
_MIGRATIONS = {
    "kind": "TEXT NOT NULL DEFAULT 'scan'",
    "parent_id": "TEXT",
    "retest_json": "TEXT",
}


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
    kind: str = "scan"  # scan | retest
    parent_id: str | None = None
    accepted: int = 0  # display-only: findings hidden by triage (not persisted)


@dataclass
class ScheduleRow:
    """A recurring scan definition. Auth material is persisted here (local DB, single
    operator) so scheduled runs can reach authenticated targets unattended."""

    id: int
    target: str
    engine: str
    profile: str | None
    rps: float
    auth_bearer: str | None
    auth_cookie: str | None
    interval_minutes: int
    enabled: bool
    created_at: float
    last_run_at: float | None
    next_run_at: float


@dataclass
class AlertSettings:
    """Delta-alert config for the self-hosted path (single row). ``enabled`` + a webhook_url gate it."""

    webhook_url: str = ""
    fmt: str = "slack"  # slack | discord | generic
    min_severity: str = "medium"
    enabled: bool = False


@dataclass
class SuppressionRow:
    """A persisted triage suppression (DB row)."""

    id: int
    rule_id: str | None
    finding_id: str | None
    url: str | None
    reason: str
    expires: str | None
    created_at: float


@dataclass
class ProgramRow:
    """A persisted bug-bounty program (DB row + the parsed ``Program``)."""

    id: str
    handle: str
    platform: str
    created_at: float
    program: Program


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
            self._migrate()

    def _migrate(self) -> None:
        """Add any columns introduced after a DB was first created."""
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(scans)")}
        for column, decl in _MIGRATIONS.items():
            if column not in existing:
                self._conn.execute(f"ALTER TABLE scans ADD COLUMN {column} {decl}")

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
            kind=row["kind"] if "kind" in row.keys() else "scan",
            parent_id=row["parent_id"] if "parent_id" in row.keys() else None,
        )

    def insert_running(
        self,
        scan_id: str,
        target: str,
        engine: str,
        profile: str | None,
        created_at: float,
        *,
        kind: str = "scan",
        parent_id: str | None = None,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO scans (id, target, engine, profile, status, created_at, kind, parent_id) "
                "VALUES (?, ?, ?, ?, 'running', ?, ?, ?)",
                (scan_id, target, engine, profile, created_at, kind, parent_id),
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

    def mark_retest_done(
        self,
        scan_id: str,
        finished_at: float,
        duration_s: float,
        still_open: list[Finding],
        retest: dict,
    ) -> None:
        """Persist a finished retest: still-open findings as the run's findings,
        plus the per-prior-finding verdicts (open/fixed/unverified) in ``retest_json``."""
        counts = severity_counts(still_open)
        findings_json = json.dumps([f.model_dump(mode="json") for f in still_open], ensure_ascii=False)
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE scans SET status='done', finished_at=?, duration_s=?, num_findings=?, "
                "severity_counts=?, findings_json=?, retest_json=? WHERE id=?",
                (
                    finished_at,
                    duration_s,
                    len(still_open),
                    json.dumps(counts),
                    findings_json,
                    json.dumps(retest, ensure_ascii=False),
                    scan_id,
                ),
            )

    def get_retest(self, scan_id: str) -> dict | None:
        """The stored retest verdicts ({counts, outcomes}) for a retest run, if any."""
        with self._lock:
            row = self._conn.execute("SELECT retest_json FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row or not row["retest_json"]:
            return None
        return json.loads(row["retest_json"])

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
            rows = self._conn.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
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

    # --- triage suppressions -----------------------------------------------------------

    def add_suppression(
        self,
        *,
        rule_id: str | None = None,
        finding_id: str | None = None,
        url: str | None = None,
        reason: str = "",
        expires: str | None = None,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO suppressions (rule_id, finding_id, url, reason, expires, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    rule_id or None,
                    finding_id or None,
                    url or None,
                    reason,
                    expires or None,
                    _dt.datetime.now().timestamp(),
                ),
            )

    def list_suppressions(self) -> list[SuppressionRow]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM suppressions ORDER BY created_at DESC").fetchall()
        return [
            SuppressionRow(
                id=row["id"],
                rule_id=row["rule_id"],
                finding_id=row["finding_id"],
                url=row["url"],
                reason=row["reason"],
                expires=row["expires"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def delete_suppression(self, row_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM suppressions WHERE id=?", (row_id,))

    # --- schedules ---------------------------------------------------------------------

    def _row_to_schedule(self, row: sqlite3.Row) -> ScheduleRow:
        return ScheduleRow(
            id=row["id"],
            target=row["target"],
            engine=row["engine"],
            profile=row["profile"],
            rps=row["rps"],
            auth_bearer=row["auth_bearer"],
            auth_cookie=row["auth_cookie"],
            interval_minutes=row["interval_minutes"],
            enabled=bool(row["enabled"]),
            created_at=row["created_at"],
            last_run_at=row["last_run_at"],
            next_run_at=row["next_run_at"],
        )

    def add_schedule(
        self,
        *,
        target: str,
        engine: str,
        profile: str | None,
        rps: float,
        auth_bearer: str,
        auth_cookie: str,
        interval_minutes: int,
        now: float,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO schedules (target, engine, profile, rps, auth_bearer, auth_cookie, "
                "interval_minutes, enabled, created_at, next_run_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (
                    target,
                    engine,
                    profile,
                    rps,
                    auth_bearer or None,
                    auth_cookie or None,
                    interval_minutes,
                    now,
                    now + interval_minutes * 60,  # wait one interval before the first run
                ),
            )

    def list_schedules(self) -> list[ScheduleRow]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM schedules ORDER BY created_at DESC").fetchall()
        return [self._row_to_schedule(row) for row in rows]

    def get_schedule(self, schedule_id: int) -> ScheduleRow | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM schedules WHERE id=?", (schedule_id,)).fetchone()
        return self._row_to_schedule(row) if row else None

    def due_schedules(self, now: float) -> list[ScheduleRow]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM schedules WHERE enabled=1 AND next_run_at<=?", (now,)).fetchall()
        return [self._row_to_schedule(row) for row in rows]

    def mark_ran(self, schedule_id: int, last_run_at: float, next_run_at: float) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE schedules SET last_run_at=?, next_run_at=? WHERE id=?",
                (last_run_at, next_run_at, schedule_id),
            )

    def set_schedule_enabled(self, schedule_id: int, enabled: bool) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE schedules SET enabled=? WHERE id=?", (1 if enabled else 0, schedule_id))

    def delete_schedule(self, schedule_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))

    # --- delta alerts (continuous monitoring) ------------------------------------------------

    def get_alert_settings(self) -> AlertSettings:
        """The single-row delta-alert config (defaults when unset)."""
        with self._lock:
            row = self._conn.execute("SELECT * FROM alert_settings WHERE id=1").fetchone()
        if not row:
            return AlertSettings()
        return AlertSettings(
            webhook_url=row["webhook_url"], fmt=row["fmt"],
            min_severity=row["min_severity"], enabled=bool(row["enabled"]),
        )

    def set_alert_settings(self, webhook_url: str, fmt: str, min_severity: str, enabled: bool) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO alert_settings (id, webhook_url, fmt, min_severity, enabled) VALUES (1, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET webhook_url=excluded.webhook_url, fmt=excluded.fmt, "
                "min_severity=excluded.min_severity, enabled=excluded.enabled",
                (webhook_url.strip(), fmt, min_severity, 1 if enabled else 0),
            )

    def previous_findings_for_target(self, target: str, exclude_scan_id: str) -> list[Finding]:
        """Findings of the most recent *finished* scan of the same target (excluding ``exclude_scan_id``)
        — the baseline a delta alert diffs against. Empty if this is the first scan of the target."""
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM scans WHERE target=? AND status='done' AND id!=? AND kind='scan' "
                "ORDER BY created_at DESC LIMIT 1",
                (target, exclude_scan_id),
            ).fetchone()
        return self.get_findings(row["id"]) if row else []

    def build_suppressions(self) -> list[Suppression]:
        """Domain `Suppression` objects for applying/exporting (skips malformed rows)."""
        result: list[Suppression] = []
        for row in self.list_suppressions():
            try:
                expires = _dt.date.fromisoformat(row.expires) if row.expires else None
                result.append(
                    Suppression(id=row.finding_id, rule_id=row.rule_id, url=row.url, reason=row.reason, expires=expires)
                )
            except ValueError:
                continue  # bad date or no selector at all — ignore rather than crash the view
        return result

    # --- bug-bounty programs -----------------------------------------------------------------

    def add_program(self, program: Program) -> str:
        """Persist a program and return its new id."""
        program_id = secrets.token_hex(6)
        with self._lock:
            self._conn.execute(
                "INSERT INTO programs (id, handle, platform, program_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (program_id, program.handle, program.platform, program.model_dump_json(), time.time()),
            )
            self._conn.commit()
        return program_id

    def list_programs(self) -> list[ProgramRow]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM programs ORDER BY created_at DESC").fetchall()
        return [self._row_to_program(row) for row in rows]

    def get_program(self, program_id: str) -> ProgramRow | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM programs WHERE id = ?", (program_id,)).fetchone()
        return self._row_to_program(row) if row else None

    def delete_program(self, program_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM programs WHERE id = ?", (program_id,))
            self._conn.commit()

    @staticmethod
    def _row_to_program(row: sqlite3.Row) -> ProgramRow:
        return ProgramRow(
            id=row["id"],
            handle=row["handle"],
            platform=row["platform"],
            created_at=row["created_at"],
            program=Program.model_validate_json(row["program_json"]),
        )
