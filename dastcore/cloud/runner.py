"""Self-hosted runner agent.

Runs inside the customer's network. It claims queued jobs from the control-plane
with a project API key, runs each scan locally using the normal engine, and posts
the findings back. Because the scan runs here, it can reach internal/staging
targets the cloud never could — and the intrusive traffic stays on-premises.

`run_once`/`run_forever` take an httpx client (pointed at the control-plane) so
they can be driven in tests over an in-process transport.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from dastcore.cli import _Budget, _build_auth_config, _run_scan
from dastcore.cloud.models import JobSpec
from dastcore.config import OutputConfig, RateLimitConfig, ScanConfig, ScopeConfig
from dastcore.core.models import Finding

_log = logging.getLogger(__name__)

# Profile -> (engine, max_pages), mirroring the CLI's convenience defaults.
_PROFILE_DEFAULTS = {"quick": ("http", 40), "full": ("both", 200), "api": ("http", 80)}


def _config_for(spec: JobSpec) -> tuple[ScanConfig, str, int]:
    engine, max_pages = spec.engine, 200
    if spec.profile in _PROFILE_DEFAULTS:
        engine, max_pages = _PROFILE_DEFAULTS[spec.profile]
    auth = _build_auth_config(
        auth_cookie=[spec.auth_cookie] if spec.auth_cookie else [],
        auth_header=[],
        auth_bearer=spec.auth_bearer,
        login_url="",
        login_field=[],
        oauth_token_url="",
        oauth_client_id="",
        oauth_client_secret="",
        oauth_scope="",
    )
    config = ScanConfig(
        target=spec.target,  # type: ignore[arg-type]
        scope=ScopeConfig(allow_domains=list(spec.allow_domains)),
        auth=auth,
        rate_limit=RateLimitConfig(requests_per_second=spec.rps if spec.rps > 0 else 5.0),
        output=OutputConfig(format="json"),
        i_have_authorization=True,
    )
    return config, engine, max_pages


async def _run_job(spec: JobSpec) -> list[Finding]:
    config, engine, max_pages = _config_for(spec)
    return await _run_scan(config, max_pages, engine, budget=_Budget(None, None))


async def register_runner(client: httpx.AsyncClient, project_key: str, name: str = "runner") -> str:
    """Register a runner with a project API key and return its (runner) token."""
    resp = await client.post("/api/runners", json={"name": name}, headers={"Authorization": f"Bearer {project_key}"})
    resp.raise_for_status()
    return resp.json()["token"]


async def run_once(client: httpx.AsyncClient, token: str) -> bool:
    """Claim and run a single job if one is queued. Returns True if a job was handled.

    ``token`` is a runner token; the runner's identity is derived from it server-side.
    """
    headers = {"Authorization": f"Bearer {token}"}
    claim = await client.post("/api/runner/claim", headers=headers)
    if claim.status_code == 204:
        return False
    claim.raise_for_status()
    job = claim.json()
    job_id = job["id"]
    spec = JobSpec.model_validate(job["spec"])

    try:
        findings = await _run_job(spec)
        payload: dict = {"status": "done", "findings": [f.model_dump(mode="json") for f in findings]}
        _log.info("job %s done: %d finding(s)", job_id, len(findings))
    except Exception as exc:  # noqa: BLE001 — report the failure to the control-plane, keep the runner alive
        payload = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
        _log.warning("job %s failed: %s", job_id, exc)

    result = await client.post(f"/api/runner/jobs/{job_id}/result", json=payload, headers=headers)
    result.raise_for_status()
    return True


async def run_forever(client: httpx.AsyncClient, token: str, *, poll_seconds: float = 5.0) -> None:
    """Continuously claim and run jobs, heartbeating and sleeping when idle."""
    headers = {"Authorization": f"Bearer {token}"}
    while True:
        try:
            worked = await run_once(client, token)
            if not worked:
                await client.post("/api/runner/heartbeat", headers=headers)
        except httpx.HTTPError as exc:
            _log.warning("control-plane request failed: %s", exc)
            worked = False
        if not worked:
            await asyncio.sleep(poll_seconds)
