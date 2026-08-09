"""Database adapter for the control-plane: SQLite (default) or PostgreSQL.

The control-plane speaks one small SQL dialect (``?`` placeholders, plain ANSI DDL)
and this layer maps it to whichever backend is configured. SQLite is the zero-setup
default and the one the test suite runs against; PostgreSQL is the durable, multi-
instance option for a real deployment — selected by passing a ``postgresql://`` DSN.

Both backends serialize access behind a lock (the control-plane is a single process),
return rows as mappings (``row["col"]``), and expose the same `Database` surface, so
`Store` is written once. The one dialect-specific spot — an atomic job claim under
concurrency (``FOR UPDATE SKIP LOCKED`` on Postgres) — is handled in `Store`.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol

Params = Sequence[Any]


class Cursor(Protocol):
    """Statement runner available inside a transaction."""

    def query_one(self, sql: str, params: Params = ()) -> Mapping[str, Any] | None: ...
    def execute(self, sql: str, params: Params = ()) -> int: ...


class Database(Protocol):
    dialect: str

    def executescript(self, ddl: str) -> None: ...
    def query(self, sql: str, params: Params = ()) -> list[Mapping[str, Any]]: ...
    def query_one(self, sql: str, params: Params = ()) -> Mapping[str, Any] | None: ...
    def execute(self, sql: str, params: Params = ()) -> int: ...
    def transaction(self) -> Any: ...  # contextmanager yielding a Cursor
    def close(self) -> None: ...


def is_postgres_dsn(dsn: str) -> bool:
    return dsn.startswith(("postgresql://", "postgres://"))


def open_database(dsn: str) -> Database:
    """Open the backend selected by ``dsn`` — a ``postgresql://`` URL, or a file path."""
    if is_postgres_dsn(dsn):
        return _PostgresDatabase(dsn)
    return _SqliteDatabase(dsn)


# --- SQLite ---------------------------------------------------------------------------------


class _SqliteCursor:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def query_one(self, sql: str, params: Params = ()) -> Mapping[str, Any] | None:
        return self._conn.execute(sql, params).fetchone()

    def execute(self, sql: str, params: Params = ()) -> int:
        return self._conn.execute(sql, params).rowcount


class _SqliteDatabase:
    dialect = "sqlite"

    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def executescript(self, ddl: str) -> None:
        with self._lock, self._conn:
            self._conn.executescript(ddl)

    def query(self, sql: str, params: Params = ()) -> list[Mapping[str, Any]]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: Params = ()) -> Mapping[str, Any] | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def execute(self, sql: str, params: Params = ()) -> int:
        with self._lock, self._conn:
            return self._conn.execute(sql, params).rowcount

    @contextmanager
    def transaction(self) -> Iterator[Cursor]:
        with self._lock, self._conn:
            yield _SqliteCursor(self._conn)

    def close(self) -> None:
        self._conn.close()


# --- PostgreSQL -----------------------------------------------------------------------------


def _to_pg(sql: str) -> str:
    """Translate ``?`` placeholders to psycopg's ``%s``."""
    return sql.replace("?", "%s")


class _PostgresCursor:
    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def query_one(self, sql: str, params: Params = ()) -> Mapping[str, Any] | None:
        return self._conn.execute(_to_pg(sql), params).fetchone()

    def execute(self, sql: str, params: Params = ()) -> int:
        return self._conn.execute(_to_pg(sql), params).rowcount


class _PostgresDatabase:
    """PostgreSQL backend via psycopg 3. Single locked connection (the control-plane is
    one process); durability and multi-instance safety come from Postgres itself."""

    dialect = "postgres"

    def __init__(self, dsn: str) -> None:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ModuleNotFoundError as exc:  # pragma: no cover - optional dependency
            raise ModuleNotFoundError(
                "PostgreSQL support needs psycopg. Install with: pip install 'dastcore[pg]'"
            ) from exc
        self._lock = threading.Lock()
        self._conn = psycopg.connect(dsn, autocommit=True, row_factory=dict_row)

    def executescript(self, ddl: str) -> None:
        # SQLite REAL loses precision on unix timestamps in Postgres — use double precision.
        ddl = ddl.replace(" REAL", " DOUBLE PRECISION")
        with self._lock:
            for statement in filter(str.strip, ddl.split(";")):
                self._conn.execute(statement)

    def query(self, sql: str, params: Params = ()) -> list[Mapping[str, Any]]:
        with self._lock:
            return self._conn.execute(_to_pg(sql), params).fetchall()

    def query_one(self, sql: str, params: Params = ()) -> Mapping[str, Any] | None:
        with self._lock:
            return self._conn.execute(_to_pg(sql), params).fetchone()

    def execute(self, sql: str, params: Params = ()) -> int:
        with self._lock:
            return self._conn.execute(_to_pg(sql), params).rowcount

    @contextmanager
    def transaction(self) -> Iterator[Cursor]:
        with self._lock, self._conn.transaction():
            yield _PostgresCursor(self._conn)

    def close(self) -> None:
        self._conn.close()
