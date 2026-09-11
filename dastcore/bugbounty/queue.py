"""Persistent review queue for bounty submission candidates — the human gate.

Every triaged candidate the bot finds lands here as ``pending``. The bot never advances a row past
``pending``: moving a candidate to ``approved`` (a draft you vetted), recording it ``submitted``, or
``dismissed`` is always a human action. Dedup by ``(program, signature)`` keeps the queue continuous
across runs — re-finding the same issue bumps its variant count and ``last_seen`` without resetting a
status a human already set, and without ever creating a duplicate row. This is what lets the bot run
continuously (P1) while a human stays in control of what gets sent (a hard platform-ToS requirement).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dastcore.bugbounty.triage import BountyFinding
from dastcore.core.models import Finding

CandidateStatus = Literal["pending", "approved", "submitted", "dismissed"]
_STATUSES: frozenset[str] = frozenset({"pending", "approved", "submitted", "dismissed"})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS candidates (
    program TEXT NOT NULL,
    signature TEXT NOT NULL,
    finding TEXT NOT NULL,
    vrt_category TEXT,
    vrt_priority TEXT,
    priority_score REAL NOT NULL DEFAULT 0,
    variants INTEGER NOT NULL DEFAULT 1,
    checklist_passes INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (program, signature)
)
"""


@dataclass
class QueuedCandidate:
    """One submission candidate as stored in the review queue."""

    program: str
    signature: str
    finding: Finding
    vrt_category: str
    vrt_priority: str
    priority_score: float
    variants: int
    checklist_passes: bool
    status: str
    first_seen: float
    last_seen: float


class ReviewQueue:
    """SQLite-backed queue of bounty candidates awaiting human review. Never auto-submits."""

    def __init__(self, db_path: str | Path = ".dastcore/review_queue.db") -> None:
        path = Path(db_path)
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def upsert_candidate(self, program: str, bf: BountyFinding, now: float) -> bool:
        """File a triaged candidate. Returns True if it is new to the queue.

        An existing row is refreshed (latest finding/VRT/variants + ``last_seen``) but its human-set
        ``status`` is preserved — re-finding an ``approved``/``submitted``/``dismissed`` issue never drags
        it back to ``pending``. ``first_seen`` is kept, so the queue records when the issue first appeared.
        """
        finding_json = bf.finding.model_dump_json()
        passes = 1 if bf.checklist.passes else 0
        existing = self._conn.execute(
            "SELECT 1 FROM candidates WHERE program = ? AND signature = ?", (program, bf.signature)
        ).fetchone()
        if existing is None:
            self._conn.execute(
                "INSERT INTO candidates (program, signature, finding, vrt_category, vrt_priority, "
                "priority_score, variants, checklist_passes, status, first_seen, last_seen) "
                "VALUES (?,?,?,?,?,?,?,?,'pending',?,?)",
                (program, bf.signature, finding_json, bf.vrt_category, bf.vrt_priority,
                 bf.priority_score, bf.variants, passes, now, now),
            )
            self._conn.commit()
            return True
        self._conn.execute(
            "UPDATE candidates SET finding = ?, vrt_category = ?, vrt_priority = ?, priority_score = ?, "
            "variants = ?, checklist_passes = ?, last_seen = ? WHERE program = ? AND signature = ?",
            (finding_json, bf.vrt_category, bf.vrt_priority, bf.priority_score, bf.variants, passes, now,
             program, bf.signature),
        )
        self._conn.commit()
        return False

    def set_status(self, program: str, signature: str, status: CandidateStatus) -> bool:
        """Human action: move a candidate to a new status. Returns True if a row changed."""
        if status not in _STATUSES:
            raise ValueError(f"invalid candidate status: {status!r} (must be one of {sorted(_STATUSES)})")
        cur = self._conn.execute(
            "UPDATE candidates SET status = ? WHERE program = ? AND signature = ?", (status, program, signature)
        )
        self._conn.commit()
        return cur.rowcount > 0

    def _row_to_candidate(self, row: sqlite3.Row) -> QueuedCandidate:
        return QueuedCandidate(
            program=row["program"],
            signature=row["signature"],
            finding=Finding.model_validate(json.loads(row["finding"])),
            vrt_category=row["vrt_category"] or "",
            vrt_priority=row["vrt_priority"] or "",
            priority_score=row["priority_score"],
            variants=row["variants"],
            checklist_passes=bool(row["checklist_passes"]),
            status=row["status"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )

    def candidates(self, program: str | None = None, *, status: str | None = None) -> list[QueuedCandidate]:
        """Candidates, highest priority first. Filter by program and/or status."""
        clauses: list[str] = []
        args: list[object] = []
        if program is not None:
            clauses.append("program = ?")
            args.append(program)
        if status is not None:
            clauses.append("status = ?")
            args.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM candidates{where} ORDER BY priority_score DESC, last_seen DESC", args
        ).fetchall()
        return [self._row_to_candidate(row) for row in rows]

    def get(self, program: str, signature: str) -> QueuedCandidate | None:
        row = self._conn.execute(
            "SELECT * FROM candidates WHERE program = ? AND signature = ?", (program, signature)
        ).fetchone()
        return self._row_to_candidate(row) if row is not None else None

    def pending(self, program: str | None = None) -> list[QueuedCandidate]:
        """Candidates still awaiting human review."""
        return self.candidates(program, status="pending")

    def counts(self, program: str | None = None) -> dict[str, int]:
        """How many candidates sit in each status (0-filled for every status)."""
        where = " WHERE program = ?" if program is not None else ""
        args = (program,) if program is not None else ()
        rows = self._conn.execute(
            f"SELECT status, COUNT(*) AS n FROM candidates{where} GROUP BY status", args
        ).fetchall()
        counts = dict.fromkeys(_STATUSES, 0)
        for row in rows:
            counts[row["status"]] = row["n"]
        return counts

    def close(self) -> None:
        self._conn.close()
