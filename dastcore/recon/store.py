"""Persistent asset store (SQLite) with dedupe and first_seen/last_seen — the basis for
attack-surface monitoring over time."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from dastcore.recon.models import Asset

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    key TEXT PRIMARY KEY,
    host TEXT NOT NULL, ip TEXT, port INTEGER, url TEXT, source TEXT,
    tech TEXT, status_code INTEGER, title TEXT,
    first_seen REAL NOT NULL, last_seen REAL NOT NULL
)
"""


class AssetStore:
    def __init__(self, db_path: str | Path = ".dastcore/assets.db") -> None:
        path = Path(db_path)
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def upsert(self, asset: Asset, now: float) -> bool:
        """Insert a new asset or refresh an existing one (last_seen + merged fields). Returns True if new."""
        key = asset.dedupe_key()
        tech = json.dumps(asset.tech)
        existing = self._conn.execute("SELECT key FROM assets WHERE key = ?", (key,)).fetchone()
        if existing is None:
            self._conn.execute(
                "INSERT INTO assets VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    key,
                    asset.host,
                    asset.ip,
                    asset.port,
                    asset.url,
                    asset.source,
                    tech,
                    asset.status_code,
                    asset.title,
                    now,
                    now,
                ),
            )
            self._conn.commit()
            return True
        self._conn.execute(
            "UPDATE assets SET last_seen = ?, ip = COALESCE(?, ip), port = COALESCE(?, port), "
            "url = COALESCE(?, url), status_code = COALESCE(?, status_code), title = COALESCE(?, title), "
            "tech = CASE WHEN ? <> '[]' THEN ? ELSE tech END WHERE key = ?",
            (now, asset.ip, asset.port, asset.url, asset.status_code, asset.title, tech, tech, key),
        )
        self._conn.commit()
        return False

    def _row_to_asset(self, row: sqlite3.Row) -> Asset:
        return Asset(
            host=row["host"],
            ip=row["ip"],
            port=row["port"],
            url=row["url"],
            source=row["source"],
            tech=json.loads(row["tech"] or "[]"),
            status_code=row["status_code"],
            title=row["title"],
        )

    def all(self) -> list[Asset]:
        rows = self._conn.execute("SELECT * FROM assets ORDER BY host, port").fetchall()
        return [self._row_to_asset(row) for row in rows]

    def live(self) -> list[Asset]:
        """Assets a live-host probe reached (they have a URL) — the input the hunt pipeline scans."""
        rows = self._conn.execute("SELECT * FROM assets WHERE url IS NOT NULL ORDER BY host").fetchall()
        return [self._row_to_asset(row) for row in rows]

    def close(self) -> None:
        self._conn.close()
