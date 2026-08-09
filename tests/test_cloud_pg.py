"""Control-plane store against a *real* PostgreSQL backend.

The rest of the cloud suite runs on SQLite; this closes the honesty gap by exercising
the Postgres-specific code paths (FOR UPDATE SKIP LOCKED claim, RETURNING, the
requeue-stale query, DOUBLE PRECISION timestamps, dict_row) on an actual server.

Runs only when DASTCORE_TEST_PG_DSN points at a Postgres instance (the CI `cloud-pg`
job provides one); skipped otherwise so the default suite stays zero-setup.
"""

from __future__ import annotations

import os
import time

import pytest

from dastcore.cloud.models import JobSpec
from dastcore.cloud.store import Store
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_DSN = os.environ.get("DASTCORE_TEST_PG_DSN", "")
_TABLES = ("schedules", "runners", "jobs", "api_keys", "projects")

pytestmark = pytest.mark.skipif(not _DSN, reason="set DASTCORE_TEST_PG_DSN to run the Postgres backend tests")


@pytest.fixture
def pg_store():
    pytest.importorskip("psycopg")
    from dastcore.cloud.db import open_database

    # Clean slate: drop the app tables so each test starts empty on the shared server.
    db = open_database(_DSN)
    for table in _TABLES:
        db.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    db.close()

    store = Store(_DSN)
    yield store
    store.close()


def _finding() -> Finding:
    request = HttpRequest(method="GET", url="http://t.test/search", params={"q": "1'"})
    point = InjectionPoint(location="query", name="q", request_template=request)
    return Finding(
        id="sqli-injection:GET:/search:query:q",
        rule_id="sqli-injection",
        name="SQL Injection",
        severity="high",
        cwe="CWE-89",
        owasp="WSTG-INPV-05",
        injection_point=point,
        evidence=[Evidence(type="response_match", data="SQL syntax", confidence="high")],
        request=request,
        response=HttpResponse(status_code=500, text="SQL syntax error"),
        remediation="Use parameterized queries.",
        family="sqli",
    )


def test_backend_is_postgres(pg_store: Store) -> None:
    assert pg_store._db.dialect == "postgres"


def test_project_and_api_key_roundtrip(pg_store: Store) -> None:
    project_id, api_key = pg_store.create_project("acme")
    assert pg_store.project_for_key(api_key) == project_id
    assert pg_store.project_for_key("wrong-key") is None
    assert pg_store.get_project(project_id).name == "acme"


def test_job_claim_complete_and_findings_roundtrip(pg_store: Store) -> None:
    project_id, _ = pg_store.create_project("acme")
    job_id = pg_store.enqueue_job(project_id, JobSpec(target="http://t.test/"))

    # the Postgres claim path (single UPDATE ... FOR UPDATE SKIP LOCKED ... RETURNING)
    claimed = pg_store.claim_job(project_id, "runner-1")
    assert claimed is not None and claimed.id == job_id
    assert claimed.status == "running" and claimed.runner == "runner-1" and claimed.attempts == 1

    # a second runner finds nothing to claim
    assert pg_store.claim_job(project_id, "runner-2") is None

    assert pg_store.complete_job(project_id, job_id, [_finding()]) is True
    done = pg_store.get_job(project_id, job_id)
    assert done.status == "done"
    findings = pg_store.get_findings(project_id, job_id)
    assert len(findings) == 1 and findings[0].rule_id == "sqli-injection"


def test_stale_job_requeue_and_retry_exhaustion(pg_store: Store) -> None:
    project_id, _ = pg_store.create_project("acme")
    job_id = pg_store.enqueue_job(project_id, JobSpec(target="http://t.test/"))
    # An explicit far-future `now` makes any claimed job look abandoned regardless of
    # the platform's clock resolution — deterministic, unlike relying on claimed_at < now.
    future = time.time() + 3600

    pg_store.claim_job(project_id, "runner-1")
    assert pg_store.requeue_stale_jobs(visibility_timeout=1e9) == 0  # huge window -> not stale
    assert pg_store.requeue_stale_jobs(visibility_timeout=0.0, now=future) == 1  # abandoned -> requeued
    back = pg_store.get_job(project_id, job_id)
    assert back.status == "queued" and back.runner is None and back.attempts == 1

    # default max_attempts is 3: after three abandoned claims it fails permanently
    for _ in range(2):
        assert pg_store.claim_job(project_id, "r") is not None
        pg_store.requeue_stale_jobs(visibility_timeout=0.0, now=future)
    assert pg_store.get_job(project_id, job_id).status == "error"


def test_runner_token_roundtrip(pg_store: Store) -> None:
    project_id, _ = pg_store.create_project("acme")
    runner_id, token = pg_store.create_runner(project_id, "edge-1")
    row = pg_store.runner_for_token(token)
    assert row is not None and row.id == runner_id and row.project_id == project_id
