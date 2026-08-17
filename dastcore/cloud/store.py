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
from dastcore.web.diff import diff_findings

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

CREATE TABLE IF NOT EXISTS users (
    email         TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    project_id    TEXT NOT NULL,
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
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
    mode            TEXT NOT NULL DEFAULT 'scan',
    max_pages       INTEGER NOT NULL DEFAULT 200,
    victim_bearer   TEXT,
    victim_refs     TEXT NOT NULL DEFAULT '[]',
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
    mode             TEXT NOT NULL DEFAULT 'scan',
    max_pages        INTEGER NOT NULL DEFAULT 200,
    victim_bearer    TEXT,
    victim_refs      TEXT NOT NULL DEFAULT '[]',
    interval_minutes INTEGER NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       REAL NOT NULL,
    last_run_at      REAL,
    next_run_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    project_id   TEXT PRIMARY KEY,
    webhook_url  TEXT NOT NULL,
    format       TEXT NOT NULL DEFAULT 'slack',
    on_event     TEXT NOT NULL DEFAULT 'regression',
    min_severity TEXT NOT NULL DEFAULT 'high',
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   REAL NOT NULL
);
"""

# Columns added after the initial release, applied to pre-existing DBs on open.
_JOB_MIGRATIONS = {"attempts": "INTEGER NOT NULL DEFAULT 0", "max_attempts": "INTEGER NOT NULL DEFAULT 3"}
# Notification trigger mode, added after notifications shipped.
_NOTIFICATION_MIGRATIONS = {"on_event": "TEXT NOT NULL DEFAULT 'regression'"}
# Embedded-chatbot ("ai" mode) columns, added to both jobs and schedules.
_AI_MIGRATIONS = {
    "mode": "TEXT NOT NULL DEFAULT 'scan'",
    "max_pages": "INTEGER NOT NULL DEFAULT 200",
    "victim_bearer": "TEXT",
    "victim_refs": "TEXT NOT NULL DEFAULT '[]'",
}


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
class NotificationRow:
    project_id: str
    webhook_url: str
    format: str
    notify_on: str
    min_severity: str
    enabled: bool


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
    mode: str = "scan"
    max_pages: int = 200
    victim_bearer: str | None = None
    victim_refs: list[str] = field(default_factory=list)

    def spec(self) -> JobSpec:
        return JobSpec(
            target=self.target,
            mode="ai" if self.mode == "ai" else "scan",
            engine=self.engine,
            profile=self.profile or "",
            rps=self.rps,
            auth_bearer=self.auth_bearer or "",
            auth_cookie=self.auth_cookie or "",
            allow_domains=self.allow_domains,
            max_pages=self.max_pages,
            victim_bearer=self.victim_bearer or "",
            victim_refs=self.victim_refs,
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
    mode: str = "scan"
    max_pages: int = 200
    victim_bearer: str | None = None
    victim_refs: list[str] = field(default_factory=list)

    def spec(self) -> JobSpec:
        return JobSpec(
            target=self.target,
            mode="ai" if self.mode == "ai" else "scan",
            engine=self.engine,
            profile=self.profile or "",
            rps=self.rps,
            auth_bearer=self.auth_bearer or "",
            auth_cookie=self.auth_cookie or "",
            allow_domains=self.allow_domains,
            max_pages=self.max_pages,
            victim_bearer=self.victim_bearer or "",
            victim_refs=self.victim_refs,
        )


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _hash_password(password: str) -> str:
    """Salted scrypt (stdlib) — slow by design, so a leaked DB can't be brute-forced cheaply."""
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${derived.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_hex, hash_hex = stored.split("$", 2)
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    derived = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=32)
    return secrets.compare_digest(derived.hex(), hash_hex)


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
        columns = {
            "jobs": {**_JOB_MIGRATIONS, **_AI_MIGRATIONS},
            "schedules": dict(_AI_MIGRATIONS),
            "notifications": dict(_NOTIFICATION_MIGRATIONS),
        }
        for table, migrations in columns.items():
            if self._db.dialect == "postgres":
                for name, decl in migrations.items():
                    self._db.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {name} {decl}")
            else:
                existing = {row["name"] for row in self._db.query(f"PRAGMA table_info({table})")}
                for name, decl in migrations.items():
                    if name not in existing:
                        self._db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

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

    def regenerate_api_key(self, project_id: str) -> str:
        """Issue a fresh API key for a project and invalidate the old one(s). Returned once."""
        api_key = "dast_" + secrets.token_urlsafe(24)
        with self._db.transaction() as tx:
            tx.execute("DELETE FROM api_keys WHERE project_id=?", (project_id,))
            tx.execute(
                "INSERT INTO api_keys (key_hash, project_id, created_at) VALUES (?, ?, ?)",
                (_hash_key(api_key), project_id, time.time()),
            )
        return api_key

    # --- self-service accounts (email + password) --------------------------------------

    def email_exists(self, email: str) -> bool:
        return self._db.query_one("SELECT 1 FROM users WHERE email=?", (email.strip().lower(),)) is not None

    def create_account(self, email: str, password: str, project_name: str = "") -> tuple[str, str]:
        """Register a user and their own project atomically. Returns (project_id, api_key)."""
        email = email.strip().lower()
        project_id = uuid.uuid4().hex[:12]
        api_key = "dast_" + secrets.token_urlsafe(24)
        now = time.time()
        with self._db.transaction() as tx:  # a duplicate email violates the users PK -> rolls back the project
            tx.execute(
                "INSERT INTO users (email, password_hash, project_id, created_at) VALUES (?, ?, ?, ?)",
                (email, _hash_password(password), project_id, now),
            )
            tx.execute(
                "INSERT INTO projects (id, name, created_at) VALUES (?, ?, ?)",
                (project_id, project_name.strip() or email, now),
            )
            tx.execute(
                "INSERT INTO api_keys (key_hash, project_id, created_at) VALUES (?, ?, ?)",
                (_hash_key(api_key), project_id, now),
            )
        return project_id, api_key

    def account_project(self, email: str, password: str) -> str | None:
        """Return the project id for valid email+password credentials, else None."""
        row = self._db.query_one("SELECT password_hash, project_id FROM users WHERE email=?", (email.strip().lower(),))
        if row is None:
            return None
        return row["project_id"] if _verify_password(password, row["password_hash"]) else None

    # --- UI sessions (decoupled from the raw API key) ----------------------------------

    def create_session(self, project_id: str) -> str:
        token = secrets.token_urlsafe(24)
        self._db.execute(
            "INSERT INTO sessions (token_hash, project_id, created_at) VALUES (?, ?, ?)",
            (_hash_key(token), project_id, time.time()),
        )
        return token

    def project_for_session(self, token: str) -> str | None:
        if not token:
            return None
        row = self._db.query_one("SELECT project_id FROM sessions WHERE token_hash=?", (_hash_key(token),))
        return row["project_id"] if row else None

    def delete_session(self, token: str) -> None:
        if token:
            self._db.execute("DELETE FROM sessions WHERE token_hash=?", (_hash_key(token),))

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
            mode=row["mode"] if "mode" in row.keys() else "scan",
            max_pages=row["max_pages"] if "max_pages" in row.keys() else 200,
            victim_bearer=row["victim_bearer"] if "victim_bearer" in row.keys() else None,
            victim_refs=json.loads(row["victim_refs"] or "[]") if "victim_refs" in row.keys() else [],
        )

    def enqueue_job(self, project_id: str, spec: JobSpec) -> str:
        job_id = uuid.uuid4().hex[:12]
        self._db.execute(
            "INSERT INTO jobs (id, project_id, target, engine, profile, rps, auth_bearer, auth_cookie, "
            "allow_domains, mode, max_pages, victim_bearer, victim_refs, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?)",
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
                spec.mode,
                spec.max_pages,
                spec.victim_bearer or None,
                json.dumps(spec.victim_refs),
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
            mode=row["mode"] if "mode" in row.keys() else "scan",
            max_pages=row["max_pages"] if "max_pages" in row.keys() else 200,
            victim_bearer=row["victim_bearer"] if "victim_bearer" in row.keys() else None,
            victim_refs=json.loads(row["victim_refs"] or "[]") if "victim_refs" in row.keys() else [],
        )

    def create_schedule(self, project_id: str, spec: ScheduleCreate, now: float) -> str:
        schedule_id = uuid.uuid4().hex[:12]
        interval = max(1, spec.interval_minutes)
        self._db.execute(
            "INSERT INTO schedules (id, project_id, target, engine, profile, rps, auth_bearer, auth_cookie, "
            "allow_domains, mode, max_pages, victim_bearer, victim_refs, interval_minutes, enabled, created_at, "
            "next_run_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
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
                spec.mode,
                spec.max_pages,
                spec.victim_bearer or None,
                json.dumps(spec.victim_refs),
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

    # --- notifications & regression detection ------------------------------------------

    def set_notification(
        self, project_id: str, webhook_url: str, fmt: str, notify_on: str, min_severity: str, enabled: bool
    ) -> None:
        """Create or replace the project's alert webhook (one per project)."""
        now = time.time()
        values = (project_id, webhook_url, fmt, notify_on, min_severity, 1 if enabled else 0, now)
        if self._db.dialect == "postgres":
            self._db.execute(
                "INSERT INTO notifications "
                "(project_id, webhook_url, format, on_event, min_severity, enabled, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (project_id) DO UPDATE SET "
                "webhook_url=EXCLUDED.webhook_url, format=EXCLUDED.format, on_event=EXCLUDED.on_event, "
                "min_severity=EXCLUDED.min_severity, enabled=EXCLUDED.enabled",
                values,
            )
        else:
            self._db.execute(
                "INSERT OR REPLACE INTO notifications "
                "(project_id, webhook_url, format, on_event, min_severity, enabled, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                values,
            )

    def get_notification(self, project_id: str) -> NotificationRow | None:
        row = self._db.query_one("SELECT * FROM notifications WHERE project_id=?", (project_id,))
        if row is None:
            return None
        return NotificationRow(
            project_id=row["project_id"],
            webhook_url=row["webhook_url"],
            format=row["format"],
            notify_on=row["on_event"] if "on_event" in row.keys() else "regression",
            min_severity=row["min_severity"],
            enabled=bool(row["enabled"]),
        )

    def delete_notification(self, project_id: str) -> None:
        self._db.execute("DELETE FROM notifications WHERE project_id=?", (project_id,))

    def trend_points(self, project_id: str, limit: int = 200) -> list[dict[str, Any]]:
        """Completed scans for a project, oldest→newest, as lightweight points for trend charts:
        id, target, finished_at, num_findings, severity_counts. Bounded by ``limit``."""
        rows = self._db.query(
            "SELECT id, target, finished_at, num_findings, severity_counts FROM jobs "
            "WHERE project_id=? AND status='done' ORDER BY finished_at ASC, id ASC LIMIT ?",
            (project_id, limit),
        )
        return [
            {
                "id": row["id"],
                "target": row["target"],
                "finished_at": row["finished_at"],
                "num_findings": row["num_findings"],
                "severity_counts": json.loads(row["severity_counts"] or "{}"),
            }
            for row in rows
        ]

    def new_findings_since_last(self, project_id: str, job_id: str) -> list[Finding]:
        """Findings present in ``job_id`` but not in the project's previous completed scan of
        the same target — the regression set. Empty for the first scan of a target (no prior
        baseline to compare against) and when nothing new appeared. Compares by stable finding
        id, exactly like the CLI ``dastcore diff``."""
        job = self.get_job(project_id, job_id)
        if job is None:
            return []
        previous = self._db.query_one(
            "SELECT findings_json FROM jobs WHERE project_id=? AND target=? AND status='done' "
            "AND id!=? AND created_at<=? ORDER BY created_at DESC, id DESC LIMIT 1",
            (project_id, job.target, job_id, job.created_at),
        )
        if previous is None:
            return []  # first completed scan of this target → establishes the baseline, no alert
        baseline = [Finding.model_validate(item) for item in json.loads(previous["findings_json"])]
        current = self.get_findings(project_id, job_id)
        return diff_findings(baseline, current).new
