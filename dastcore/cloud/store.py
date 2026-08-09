"""Persistence for the control-plane (SQLite or PostgreSQL via `dastcore.cloud.db`).

Multi-tenant: every job belongs to a project, and a project's API key scopes all
access to it. API keys and runner tokens are stored hashed (only the plaintext, shown
once at creation, can authenticate). The job queue is durable: a claim increments an
attempt counter, and `requeue_stale_jobs` returns jobs a crashed/vanished runner never
finished back to the queue (or fails them once retries are exhausted), so in-flight
work is never silently lost.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dastcore.cloud.db import open_database
from dastcore.cloud.models import JobSpec, ScheduleCreate
from dastcore.core.models import Finding

_SEVERITIES = ("critical", "high", "medium", "low", "info")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_hash   TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL,
    target          TEXT NOT NULL,
    engine          TEXT NOT NULL DEFAULT 'http',
    profile         TEXT,
    rps             REAL NOT NULL DEFAULT 5.0,
    auth_bearer     TEXT,
    auth_cookie     TEXT,
    allow_domains   TEXT NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'queued',
    runner          TEXT,
    created_at      REAL NOT NULL,
    claimed_at      REAL,
    finished_at     REAL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 3,
    num_findings    INTEGER NOT NULL DEFAULT 0,
    severity_counts TEXT NOT NULL DEFAULT '{}',
    error           TEXT,
    findings_json   TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS runners (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    created_at   REAL NOT NULL,
    last_seen_at REAL
);

CREATE TABLE IF NOT EXISTS schedules (
    id               TEXT PRIMARY KEY,
    project_id       TEXT NOT NULL,
    target           TEXT NOT NULL,
    engine           TEXT NOT NULL DEFAULT 'http',
    profile          TEXT,
    rps              REAL NOT NULL DEFAULT 5.0,
    auth_bearer      TEXT,
    auth_cookie      TEXT,
    allow_domains    TEXT NOT NULL DEFAULT '[]',
    interval_minutes INTEGER NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       REAL NOT NULL,
    last_run_at      REAL,
    next_run_at      REAL NOT NULL
);
"""

# Columns added after the initial release, applied to pre-existing DBs on open.
_JOB_MIGRATIONS = {"attempts": "INTEGER NOT NULL DEFAULT 0", "max_attempts": "INTEGER NOT NULL DEFAULT 3"}


@dataclass
class ProjectRow:
    id: str
    name: str
    created_at: float


@dataclass
class RunnerRow:
    id: str
    project_id: str
    name: str
    created_at: float
    last_seen_at: float | None = None


@dataclass
class ScheduleRow:
    id: str
    project_id: str
    target: str
    engine: str
    profile: str | None
    rps: float
    auth_bearer: str | None
    auth_cookie: str | None
    allow_domains: list[str]
    interval_minutes: int
    enabled: bool
    created_at: float
    last_run_at: float | None
    next_run_at: float

    def spec(self) -> JobSpec:
        return JobSpec(
            target=self.target,
            engine=self.engine,
            profile=self.profile or "",
            rps=self.rps,
            auth_bearer=self.auth_bearer or "",
            auth_cookie=self.auth_cookie or "",
            allow_domains=self.allow_domains,
        )


@dataclass
class JobRow:
    id: str
    project_id: str
    target: str
    engine: str
    profile: str | None
    rps: float
    auth_bearer: str | None
    auth_cookie: str | None
    allow_domains: list[str]
    status: str  # queued | running | done | error
    runner: str | None
    created_at: float
    claimed_at: float | None = None
    finished_at: float | None = None
    attempts: int = 0
    num_findings: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    def spec(self) -> JobSpec:
        return JobSpec(
            target=self.target,
            engine=self.engine,
            profile=self.profile or "",
            rps=self.rps,
            auth_bearer=self.auth_bearer or "",
            auth_cookie=self.auth_cookie or "",
            allow_domains=self.allow_domains,
        )


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = dict.fromkeys(_SEVERITIES, 0)
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    return counts


class Store:
    def __init__(self, db_path: str | Path) -> None:
        self._db = open_database(str(db_path))
        self._db.executescript(_SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        if self._db.dialect == "postgres":
            for name, decl in _JOB_MIGRATIONS.items():
                self._db.execute(f"ALTER TABLE jobs ADD COLUMN IF NOT EXISTS {name} {decl}")
        else:
            existing = {row["name"] for row in self._db.query("PRAGMA table_info(jobs)")}
            for name, decl in _JOB_MIGRATIONS.items():
                if name not in existing:
                    self._db.execute(f"ALTER TABLE jobs ADD COLUMN {name} {decl}")

    def close(self) -> None:
        self._db.close()

    # --- projects & keys ---------------------------------------------------------------

    def create_project(self, name: str) -> tuple[str, str]:
        """Create a project and its first API key. Returns (project_id, api_key).

        The plaintext key is returned once here and never stored — only its hash is.
        """
        project_id = uuid.uuid4().hex[:12]
        api_key = "dast_" + secrets.token_urlsafe(24)
        now = time.time()
        with self._db.transaction() as tx:
            tx.execute("INSERT INTO projects (id, name, created_at) VALUES (?, ?, ?)", (project_id, name, now))
            tx.execute(
                "INSERT INTO api_keys (key_hash, project_id, created_at) VALUES (?, ?, ?)",
                (_hash_key(api_key), project_id, now),
            )
        return project_id, api_key

    def project_for_key(self, api_key: str) -> str | None:
        row = self._db.query_one("SELECT project_id FROM api_keys WHERE key_hash=?", (_hash_key(api_key),))
        return row["project_id"] if row else None

    def get_project(self, project_id: str) -> ProjectRow | None:
        row = self._db.query_one("SELECT * FROM projects WHERE id=?", (project_id,))
        return ProjectRow(id=row["id"], name=row["name"], created_at=row["created_at"]) if row else None

    # --- jobs --------------------------------------------------------------------------

    def _row_to_job(self, row: Mapping[str, Any]) -> JobRow:
        return JobRow(
            id=row["id"],
            project_id=row["project_id"],
            target=row["target"],
            engine=row["engine"],
            profile=row["profile"],
            rps=row["rps"],
            auth_bearer=row["auth_bearer"],
            auth_cookie=row["auth_cookie"],
            allow_domains=json.loads(row["allow_domains"] or "[]"),
            status=row["status"],
            runner=row["runner"],
            created_at=row["created_at"],
            claimed_at=row["claimed_at"],
            finished_at=row["finished_at"],
            attempts=row["attempts"],
            num_findings=row["num_findings"],
            severity_counts=json.loads(row["severity_counts"] or "{}"),
            error=row["error"],
        )

    def enqueue_job(self, project_id: str, spec: JobSpec) -> str:
        job_id = uuid.uuid4().hex[:12]
        self._db.execute(
            "INSERT INTO jobs (id, project_id, target, engine, profile, rps, auth_bearer, auth_cookie, "
            "allow_domains, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?)",
            (
                job_id,
                project_id,
                spec.target,
                spec.engine,
                spec.profile or None,
                spec.rps,
                spec.auth_bearer or None,
                spec.auth_cookie or None,
                json.dumps(spec.allow_domains),
                time.time(),
            ),
        )
        return job_id

    def list_jobs(self, project_id: str, limit: int = 100) -> list[JobRow]:
        rows = self._db.query(
            "SELECT * FROM jobs WHERE project_id=? ORDER BY created_at DESC LIMIT ?", (project_id, limit)
        )
        return [self._row_to_job(row) for row in rows]

    def get_job(self, project_id: str, job_id: str) -> JobRow | None:
        row = self._db.query_one("SELECT * FROM jobs WHERE id=? AND project_id=?", (job_id, project_id))
        return self._row_to_job(row) if row else None

    def get_findings(self, project_id: str, job_id: str) -> list[Finding]:
        row = self._db.query_one("SELECT findings_json FROM jobs WHERE id=? AND project_id=?", (job_id, project_id))
        if not row:
            return []
        return [Finding.model_validate(item) for item in json.loads(row["findings_json"])]

    def claim_job(self, project_id: str, runner: str) -> JobRow | None:
        """Atomically hand the oldest queued job to a runner (marks it running, counts the
        attempt). On Postgres this is a single `FOR UPDATE SKIP LOCKED` statement, so many
        control-plane instances can claim concurrently without handing out the same job."""
        now = time.time()
        if self._db.dialect == "postgres":
            row = self._db.query_one(
                "UPDATE jobs SET status='running', runner=?, claimed_at=?, attempts=attempts+1 "
                "WHERE id = (SELECT id FROM jobs WHERE project_id=? AND status='queued' "
                "ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *",
                (runner, now, project_id),
            )
            return self._row_to_job(row) if row else None

        with self._db.transaction() as tx:
            row = tx.query_one(
                "SELECT * FROM jobs WHERE project_id=? AND status='queued' ORDER BY created_at LIMIT 1",
                (project_id,),
            )
            if row is None:
                return None
            tx.execute(
                "UPDATE jobs SET status='running', runner=?, claimed_at=?, attempts=attempts+1 WHERE id=?",
                (runner, now, row["id"]),
            )
            job = self._row_to_job(row)
            job.status, job.runner, job.claimed_at, job.attempts = "running", runner, now, row["attempts"] + 1
            return job

    def complete_job(self, project_id: str, job_id: str, findings: list[Finding]) -> bool:
        counts = _severity_counts(findings)
        findings_json = json.dumps([f.model_dump(mode="json") for f in findings], ensure_ascii=False)
        return (
            self._db.execute(
                "UPDATE jobs SET status='done', finished_at=?, num_findings=?, severity_counts=?, "
                "findings_json=? WHERE id=? AND project_id=? AND status='running'",
                (time.time(), len(findings), json.dumps(counts), findings_json, job_id, project_id),
            )
            > 0
        )

    def fail_job(self, project_id: str, job_id: str, error: str) -> bool:
        return (
            self._db.execute(
                "UPDATE jobs SET status='error', finished_at=?, error=? "
                "WHERE id=? AND project_id=? AND status='running'",
                (time.time(), error, job_id, project_id),
            )
            > 0
        )

    def requeue_stale_jobs(self, visibility_timeout: float, now: float | None = None) -> int:
        """Recover jobs a runner claimed but never finished within ``visibility_timeout``
        seconds (it crashed or vanished): put them back on the queue if attempts remain,
        else fail them. Returns how many jobs moved. Run periodically by the scheduler."""
        now = time.time() if now is None else now
        cutoff = now - visibility_timeout
        with self._db.transaction() as tx:
            failed = tx.execute(
                "UPDATE jobs SET status='error', finished_at=?, error='timed out: no result from runner' "
                "WHERE status='running' AND claimed_at < ? AND attempts >= max_attempts",
                (now, cutoff),
            )
            requeued = tx.execute(
                "UPDATE jobs SET status='queued', runner=NULL, claimed_at=NULL "
                "WHERE status='running' AND claimed_at < ? AND attempts < max_attempts",
                (cutoff,),
            )
        return failed + requeued

    # --- runners -----------------------------------------------------------------------

    def create_runner(self, project_id: str, name: str) -> tuple[str, str]:
        """Register a runner and mint its token. Returns (runner_id, token).

        Runner tokens are distinct from the project API key: they can only claim jobs
        and post results, not enqueue jobs or manage the project.
        """
        runner_id = uuid.uuid4().hex[:12]
        token = "dastr_" + secrets.token_urlsafe(24)
        self._db.execute(
            "INSERT INTO runners (id, project_id, name, token_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (runner_id, project_id, name, _hash_key(token), time.time()),
        )
        return runner_id, token

    def runner_for_token(self, token: str) -> RunnerRow | None:
        row = self._db.query_one("SELECT * FROM runners WHERE token_hash=?", (_hash_key(token),))
        return self._row_to_runner(row) if row else None

    def touch_runner(self, runner_id: str) -> None:
        self._db.execute("UPDATE runners SET last_seen_at=? WHERE id=?", (time.time(), runner_id))

    def list_runners(self, project_id: str) -> list[RunnerRow]:
        rows = self._db.query("SELECT * FROM runners WHERE project_id=? ORDER BY created_at DESC", (project_id,))
        return [self._row_to_runner(row) for row in rows]

    @staticmethod
    def _row_to_runner(row: Mapping[str, Any]) -> RunnerRow:
        return RunnerRow(
            id=row["id"],
            project_id=row["project_id"],
            name=row["name"],
            created_at=row["created_at"],
            last_seen_at=row["last_seen_at"],
        )

    # --- schedules ---------------------------------------------------------------------

    def _row_to_schedule(self, row: Mapping[str, Any]) -> ScheduleRow:
        return ScheduleRow(
            id=row["id"],
            project_id=row["project_id"],
            target=row["target"],
            engine=row["engine"],
            profile=row["profile"],
            rps=row["rps"],
            auth_bearer=row["auth_bearer"],
            auth_cookie=row["auth_cookie"],
            allow_domains=json.loads(row["allow_domains"] or "[]"),
            interval_minutes=row["interval_minutes"],
            enabled=bool(row["enabled"]),
            created_at=row["created_at"],
            last_run_at=row["last_run_at"],
            next_run_at=row["next_run_at"],
        )

    def create_schedule(self, project_id: str, spec: ScheduleCreate, now: float) -> str:
        schedule_id = uuid.uuid4().hex[:12]
        interval = max(1, spec.interval_minutes)
        self._db.execute(
            "INSERT INTO schedules (id, project_id, target, engine, profile, rps, auth_bearer, auth_cookie, "
            "allow_domains, interval_minutes, enabled, created_at, next_run_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (
                schedule_id,
                project_id,
                spec.target,
                spec.engine,
                spec.profile or None,
                spec.rps,
                spec.auth_bearer or None,
                spec.auth_cookie or None,
                json.dumps(spec.allow_domains),
                interval,
                now,
                now + interval * 60,
            ),
        )
        return schedule_id

    def list_schedules(self, project_id: str) -> list[ScheduleRow]:
        rows = self._db.query("SELECT * FROM schedules WHERE project_id=? ORDER BY created_at DESC", (project_id,))
        return [self._row_to_schedule(row) for row in rows]

    def get_schedule(self, project_id: str, schedule_id: str) -> ScheduleRow | None:
        row = self._db.query_one("SELECT * FROM schedules WHERE id=? AND project_id=?", (schedule_id, project_id))
        return self._row_to_schedule(row) if row else None

    def due_schedules(self, now: float) -> list[ScheduleRow]:
        rows = self._db.query("SELECT * FROM schedules WHERE enabled=1 AND next_run_at<=?", (now,))
        return [self._row_to_schedule(row) for row in rows]

    def mark_schedule_ran(self, schedule_id: str, last_run_at: float, next_run_at: float) -> None:
        self._db.execute(
            "UPDATE schedules SET last_run_at=?, next_run_at=? WHERE id=?", (last_run_at, next_run_at, schedule_id)
        )

    def set_schedule_enabled(self, project_id: str, schedule_id: str, enabled: bool) -> None:
        self._db.execute(
            "UPDATE schedules SET enabled=? WHERE id=? AND project_id=?",
            (1 if enabled else 0, schedule_id, project_id),
        )

    def delete_schedule(self, project_id: str, schedule_id: str) -> None:
        self._db.execute("DELETE FROM schedules WHERE id=? AND project_id=?", (schedule_id, project_id))
