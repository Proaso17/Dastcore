"""SQLite persistence for the control-plane.

Multi-tenant: every job belongs to a project, and a project's API key scopes all
access to it. API keys are stored hashed (only the plaintext, shown once at
creation, can authenticate). Access is serialized behind a lock — the control
plane is a single process and each request does a short DB op.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from dastcore.cloud.models import JobSpec
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
    num_findings    INTEGER NOT NULL DEFAULT 0,
    severity_counts TEXT NOT NULL DEFAULT '{}',
    error           TEXT,
    findings_json   TEXT NOT NULL DEFAULT '[]'
);
"""


@dataclass
class ProjectRow:
    id: str
    name: str
    created_at: float


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

    # --- projects & keys ---------------------------------------------------------------

    def create_project(self, name: str) -> tuple[str, str]:
        """Create a project and its first API key. Returns (project_id, api_key).

        The plaintext key is returned once here and never stored — only its hash is.
        """
        project_id = uuid.uuid4().hex[:12]
        api_key = "dast_" + secrets.token_urlsafe(24)
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute("INSERT INTO projects (id, name, created_at) VALUES (?, ?, ?)", (project_id, name, now))
            self._conn.execute(
                "INSERT INTO api_keys (key_hash, project_id, created_at) VALUES (?, ?, ?)",
                (_hash_key(api_key), project_id, now),
            )
        return project_id, api_key

    def project_for_key(self, api_key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT project_id FROM api_keys WHERE key_hash=?", (_hash_key(api_key),)
            ).fetchone()
        return row["project_id"] if row else None

    def get_project(self, project_id: str) -> ProjectRow | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        return ProjectRow(id=row["id"], name=row["name"], created_at=row["created_at"]) if row else None

    # --- jobs --------------------------------------------------------------------------

    def _row_to_job(self, row: sqlite3.Row) -> JobRow:
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
            num_findings=row["num_findings"],
            severity_counts=json.loads(row["severity_counts"] or "{}"),
            error=row["error"],
        )

    def enqueue_job(self, project_id: str, spec: JobSpec) -> str:
        job_id = uuid.uuid4().hex[:12]
        with self._lock, self._conn:
            self._conn.execute(
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
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM jobs WHERE project_id=? ORDER BY created_at DESC LIMIT ?", (project_id, limit)
            ).fetchall()
        return [self._row_to_job(row) for row in rows]

    def get_job(self, project_id: str, job_id: str) -> JobRow | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM jobs WHERE id=? AND project_id=?", (job_id, project_id)).fetchone()
        return self._row_to_job(row) if row else None

    def get_findings(self, project_id: str, job_id: str) -> list[Finding]:
        with self._lock:
            row = self._conn.execute(
                "SELECT findings_json FROM jobs WHERE id=? AND project_id=?", (job_id, project_id)
            ).fetchone()
        if not row:
            return []
        return [Finding.model_validate(item) for item in json.loads(row["findings_json"])]

    def claim_job(self, project_id: str, runner: str) -> JobRow | None:
        """Atomically hand the oldest queued job to a runner (marks it running)."""
        now = time.time()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT * FROM jobs WHERE project_id=? AND status='queued' ORDER BY created_at LIMIT 1",
                (project_id,),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute(
                "UPDATE jobs SET status='running', runner=?, claimed_at=? WHERE id=?",
                (runner, now, row["id"]),
            )
            job = self._row_to_job(row)
            job.status = "running"
            job.runner = runner
            job.claimed_at = now
            return job

    def complete_job(self, project_id: str, job_id: str, findings: list[Finding]) -> bool:
        counts = _severity_counts(findings)
        findings_json = json.dumps([f.model_dump(mode="json") for f in findings], ensure_ascii=False)
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE jobs SET status='done', finished_at=?, num_findings=?, severity_counts=?, "
                "findings_json=? WHERE id=? AND project_id=? AND status='running'",
                (time.time(), len(findings), json.dumps(counts), findings_json, job_id, project_id),
            )
            return cur.rowcount > 0

    def fail_job(self, project_id: str, job_id: str, error: str) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE jobs SET status='error', finished_at=?, error=? WHERE id=? AND project_id=? AND status='running'",
                (time.time(), error, job_id, project_id),
            )
            return cur.rowcount > 0
