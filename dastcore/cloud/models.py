"""Wire models for the control-plane API and the runner protocol."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class JobSpec(BaseModel):
    """What to scan — the payload a user enqueues and a runner receives."""

    target: str
    mode: Literal["scan", "ai"] = "scan"  # "scan" = web/API; "ai" = embedded-chatbot (OWASP LLM)
    engine: str = "http"
    profile: str = ""
    rps: float = 5.0
    auth_bearer: str = ""
    auth_cookie: str = ""
    allow_domains: list[str] = Field(default_factory=list)
    # Embedded-chatbot ("ai") scans only:
    max_pages: int = 200
    victim_bearer: str = ""  # a second identity for the cross-tenant (BOLA/BFLA) checks
    victim_refs: list[str] = Field(default_factory=list)  # how to name the victim tenant


class JobResult(BaseModel):
    """What a runner posts back after finishing (or failing) a job."""

    status: Literal["done", "error"] = "done"
    findings: list[dict] = Field(default_factory=list)  # serialized Finding objects
    error: str = ""


class ProjectCreate(BaseModel):
    name: str


class RunnerCreate(BaseModel):
    name: str = "runner"


class ScheduleCreate(JobSpec):
    """A recurring job: a JobSpec plus how often to enqueue it (minutes)."""

    interval_minutes: int = 1440
