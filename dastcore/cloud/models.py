"""Wire models for the control-plane API and the runner protocol."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class JobSpec(BaseModel):
    """What to scan — the payload a user enqueues and a runner receives."""

    target: str
    engine: str = "http"
    profile: str = ""
    rps: float = 5.0
    auth_bearer: str = ""
    auth_cookie: str = ""
    allow_domains: list[str] = Field(default_factory=list)


class JobResult(BaseModel):
    """What a runner posts back after finishing (or failing) a job."""

    status: Literal["done", "error"] = "done"
    findings: list[dict] = Field(default_factory=list)  # serialized Finding objects
    error: str = ""


class ProjectCreate(BaseModel):
    name: str
