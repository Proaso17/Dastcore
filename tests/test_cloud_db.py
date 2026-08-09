"""Database adapter routing (SQLite vs PostgreSQL selection)."""

from __future__ import annotations

import importlib.util

import pytest

from dastcore.cloud.db import is_postgres_dsn, open_database


def test_dsn_detection() -> None:
    assert is_postgres_dsn("postgresql://user:pw@db:5432/dastcore")
    assert is_postgres_dsn("postgres://user@localhost/dastcore")
    assert not is_postgres_dsn("/var/lib/dastcore/cloud.db")
    assert not is_postgres_dsn(":memory:")


def test_sqlite_backend_opens() -> None:
    db = open_database(":memory:")
    assert db.dialect == "sqlite"
    db.executescript("CREATE TABLE t (id INTEGER)")
    db.execute("INSERT INTO t (id) VALUES (?)", (1,))
    assert db.query_one("SELECT id FROM t")["id"] == 1
    db.close()


@pytest.mark.skipif(importlib.util.find_spec("psycopg") is not None, reason="psycopg is installed")
def test_postgres_backend_reports_missing_driver() -> None:
    with pytest.raises(ModuleNotFoundError, match="psycopg"):
        open_database("postgresql://user@localhost/dastcore")
