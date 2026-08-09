"""Durable job queue: attempts, stale-job requeue (visibility timeout), and retries.

Exercised against SQLite (the CI backend); the same code paths run on PostgreSQL,
which additionally claims with FOR UPDATE SKIP LOCKED for multi-instance safety.
"""

from __future__ import annotations

import pytest

from dastcore.cloud.models import JobSpec
from dastcore.cloud.store import Store


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "q.sqlite")
    yield s
    s.close()


def _project_with_job(store: Store) -> tuple[str, str]:
    project_id, _ = store.create_project("acme")
    job_id = store.enqueue_job(project_id, JobSpec(target="http://t.test/"))
    return project_id, job_id


def test_claim_counts_the_attempt(store: Store) -> None:
    project_id, job_id = _project_with_job(store)
    job = store.claim_job(project_id, "runner-1")
    assert job is not None and job.attempts == 1
    assert store.get_job(project_id, job_id).attempts == 1


def test_stale_running_job_is_requeued_for_retry(store: Store) -> None:
    project_id, job_id = _project_with_job(store)
    store.claim_job(project_id, "runner-1")  # attempts -> 1, status running

    # nothing is stale yet
    assert store.requeue_stale_jobs(visibility_timeout=1e9) == 0
    assert store.get_job(project_id, job_id).status == "running"

    # a very small timeout makes the claim look abandoned -> back to the queue
    assert store.requeue_stale_jobs(visibility_timeout=0.0) == 1
    job = store.get_job(project_id, job_id)
    assert job.status == "queued" and job.runner is None and job.claimed_at is None
    assert job.attempts == 1  # the attempt still counts

    # it can be claimed again by another runner
    reclaimed = store.claim_job(project_id, "runner-2")
    assert reclaimed is not None and reclaimed.runner == "runner-2" and reclaimed.attempts == 2


def test_retries_are_exhausted_into_error(store: Store) -> None:
    project_id, job_id = _project_with_job(store)
    # default max_attempts is 3: claim + requeue three times, then it fails
    for _ in range(3):
        assert store.claim_job(project_id, "r") is not None
        store.requeue_stale_jobs(visibility_timeout=0.0)
    job = store.get_job(project_id, job_id)
    assert job.status == "error" and "timed out" in (job.error or "")
    # exhausted -> not handed out again
    assert store.claim_job(project_id, "r") is None


def test_completed_job_is_not_reaped(store: Store) -> None:
    project_id, job_id = _project_with_job(store)
    store.claim_job(project_id, "r")
    assert store.complete_job(project_id, job_id, [])
    assert store.requeue_stale_jobs(visibility_timeout=0.0) == 0
    assert store.get_job(project_id, job_id).status == "done"
