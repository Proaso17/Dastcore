"""SaaS regression alerting: baseline diff + webhook/Slack notifications.

When a cloud job finishes with findings that are NEW versus the project's previous scan of the
same target, the control-plane POSTs an alert to the project's webhook. Covered here: the
store's new-vs-last diff and notification CRUD (unit), the Slack/generic payload builders and
severity filter (unit), and the full path through the runner result endpoint to a real capture
webhook (integration) — including that the first scan establishes a baseline without alerting.
"""

from __future__ import annotations

import socket
import threading

import httpx
from httpx import ASGITransport
from werkzeug.serving import make_server

from dastcore.cloud.app import create_app
from dastcore.cloud.models import JobSpec
from dastcore.cloud.notify import build_generic_payload, build_slack_payload, filter_by_severity
from dastcore.cloud.store import JobRow, Store
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

ADMIN = "admintok"


def _finding(fid: str, *, severity: str = "high") -> Finding:
    request = HttpRequest(method="POST", url="http://t.test/api", params={"id": "1"})
    point = InjectionPoint(location="query", name="id", request_template=request)
    return Finding(
        id=fid,
        rule_id=fid.split(":")[0],
        name=fid.split(":")[0].upper(),
        severity=severity,  # type: ignore[arg-type]
        cwe="CWE-89",
        owasp="WSTG-INPV-05",
        injection_point=point,
        evidence=[Evidence(type="differential", data="x")],
        request=request,
        response=HttpResponse(status_code=200),
        remediation="fix",
    )


def _complete(store: Store, project_id: str, target: str, findings: list[Finding]) -> str:
    job_id = store.enqueue_job(project_id, JobSpec(target=target))
    store.claim_job(project_id, "r1")
    assert store.complete_job(project_id, job_id, findings)
    return job_id


# --- store: diff + notification CRUD ---------------------------------------------------


def test_new_findings_since_last_diffs_against_previous_scan(tmp_path) -> None:
    store = Store(tmp_path / "c.db")
    project_id, _ = store.create_project("acme")
    job1 = _complete(store, project_id, "http://t.test", [_finding("sqli:1")])
    job2 = _complete(store, project_id, "http://t.test", [_finding("sqli:1"), _finding("xss:1")])

    assert store.new_findings_since_last(project_id, job1) == []  # first scan → baseline, no alert
    new = store.new_findings_since_last(project_id, job2)
    assert [f.id for f in new] == ["xss:1"]  # only the newly-introduced finding


def test_new_findings_scoped_per_target(tmp_path) -> None:
    store = Store(tmp_path / "c.db")
    project_id, _ = store.create_project("acme")
    _complete(store, project_id, "http://a.test", [_finding("sqli:1")])
    job_b = _complete(store, project_id, "http://b.test", [_finding("xss:1")])
    # b.test has no prior scan of its own → treated as a first scan, not diffed against a.test
    assert store.new_findings_since_last(project_id, job_b) == []


def test_notification_crud_upserts(tmp_path) -> None:
    store = Store(tmp_path / "c.db")
    project_id, _ = store.create_project("acme")
    assert store.get_notification(project_id) is None
    store.set_notification(project_id, "http://hook.test/a", "slack", "regression", "high", True)
    store.set_notification(project_id, "http://hook.test/b", "generic", "any", "medium", False)  # replace
    row = store.get_notification(project_id)
    assert row is not None and row.webhook_url == "http://hook.test/b" and row.enabled is False
    assert row.notify_on == "any" and row.min_severity == "medium"
    store.delete_notification(project_id)
    assert store.get_notification(project_id) is None


# --- notify: payloads + severity filter ------------------------------------------------


def _job() -> JobRow:
    return JobRow(
        id="job1",
        project_id="p1",
        target="http://t.test",
        engine="http",
        profile=None,
        rps=5.0,
        auth_bearer=None,
        auth_cookie=None,
        allow_domains=[],
        status="done",
        runner="r1",
        created_at=0.0,
    )


def test_filter_by_severity_drops_below_floor() -> None:
    findings = [_finding("a:1", severity="high"), _finding("b:1", severity="low")]
    kept = filter_by_severity(findings, "high")
    assert [f.id for f in kept] == ["a:1"]


def test_slack_payload_names_the_findings() -> None:
    payload = build_slack_payload("acme", _job(), [_finding("sqli:1", severity="critical")])
    assert "text" in payload and "blocks" in payload
    assert "acme" in payload["text"] and "SQLI" in payload["text"]


def test_generic_payload_event_varies() -> None:
    regression = build_generic_payload("p1", "acme", _job(), [_finding("sqli:1")])
    assert regression["event"] == "regression" and regression["findings_count"] == 1
    assert regression["findings"][0]["rule_id"] == "sqli"
    completed = build_generic_payload("p1", "acme", _job(), [], event="completed")
    assert completed["event"] == "scan_completed" and completed["findings_count"] == 0


# --- integration: full alert path through the runner result endpoint -------------------


class _Capture:
    def __init__(self) -> None:
        self.received: list[dict] = []


def _capture_app(capture: _Capture):
    from flask import Flask, request

    app = Flask(__name__)

    @app.post("/hook")
    def hook():
        capture.received.append(request.get_json(silent=True) or {})
        return "", 200

    return app


def _serve(app) -> tuple[str, object]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}", server


async def _runner_complete(client, runner_token: str, findings: list[Finding]) -> None:
    claim = await client.post("/api/runner/claim", headers={"Authorization": f"Bearer {runner_token}"})
    job_id = claim.json()["id"]
    await client.post(
        f"/api/runner/jobs/{job_id}/result",
        json={"status": "done", "findings": [f.model_dump(mode="json") for f in findings]},
        headers={"Authorization": f"Bearer {runner_token}"},
    )


async def test_regression_triggers_webhook_second_scan_only(tmp_path) -> None:
    # A real local capture server receives the alert; wire it to a full control-plane app.
    cap = _Capture()
    url, server = _serve(_capture_app(cap))
    try:
        app = create_app(tmp_path / "cloud.db", admin_token=ADMIN)
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://cp") as client:
            key = (
                await client.post("/api/projects", json={"name": "acme"}, headers={"Authorization": f"Bearer {ADMIN}"})
            ).json()["api_key"]
            token = (
                await client.post("/api/runners", json={"name": "r1"}, headers={"Authorization": f"Bearer {key}"})
            ).json()["token"]
            await client.put(
                "/api/notifications",
                json={"webhook_url": f"{url}/hook", "format": "generic", "min_severity": "high"},
                headers={"Authorization": f"Bearer {key}"},
            )

            # First scan: establishes the baseline, must NOT alert.
            await client.post("/api/jobs", json={"target": "http://t.test"}, headers={"Authorization": f"Bearer {key}"})
            await _runner_complete(client, token, [_finding("sqli:1")])
            assert cap.received == []

            # Second scan introduces a new finding → alert fires with only that finding.
            await client.post("/api/jobs", json={"target": "http://t.test"}, headers={"Authorization": f"Bearer {key}"})
            await _runner_complete(client, token, [_finding("sqli:1"), _finding("cmdi:1", severity="critical")])
    finally:
        server.shutdown()

    assert len(cap.received) == 1
    alert = cap.received[0]
    assert alert["event"] == "regression" and alert["findings_count"] == 1
    assert alert["findings"][0]["rule_id"] == "cmdi"


async def test_any_mode_alerts_on_every_completed_job(tmp_path) -> None:
    cap = _Capture()
    url, server = _serve(_capture_app(cap))
    try:
        app = create_app(tmp_path / "cloud.db", admin_token=ADMIN)
        async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://cp") as client:
            key = (
                await client.post("/api/projects", json={"name": "acme"}, headers={"Authorization": f"Bearer {ADMIN}"})
            ).json()["api_key"]
            token = (
                await client.post("/api/runners", json={"name": "r1"}, headers={"Authorization": f"Bearer {key}"})
            ).json()["token"]
            await client.put(
                "/api/notifications",
                json={"webhook_url": f"{url}/hook", "format": "generic", "notify_on": "any", "min_severity": "high"},
                headers={"Authorization": f"Bearer {key}"},
            )
            # Even the FIRST scan of a target alerts under "any" (no baseline needed).
            await client.post("/api/jobs", json={"target": "http://t.test"}, headers={"Authorization": f"Bearer {key}"})
            await _runner_complete(client, token, [_finding("sqli:1")])
    finally:
        server.shutdown()

    assert len(cap.received) == 1
    assert cap.received[0]["event"] == "scan_completed" and cap.received[0]["findings_count"] == 1


async def test_ui_form_sets_and_clears_the_webhook(tmp_path) -> None:
    app = create_app(tmp_path / "cloud.db", admin_token=ADMIN)
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://cp") as client:
        key = (
            await client.post("/api/projects", json={"name": "acme"}, headers={"Authorization": f"Bearer {ADMIN}"})
        ).json()["api_key"]
        client.cookies.set("dast_key", key)  # UI auth via the project-key cookie
        await client.post(
            "/ui/notifications",
            data={"webhook_url": "http://hook.test/x", "format": "generic", "min_severity": "medium"},
        )
        got = (await client.get("/api/notifications", headers={"Authorization": f"Bearer {key}"})).json()
        assert got["notification"]["webhook_url"] == "http://hook.test/x"
        assert got["notification"]["min_severity"] == "medium"
        # an empty URL clears it
        await client.post("/ui/notifications", data={"webhook_url": "", "format": "slack", "min_severity": "high"})
        got = (await client.get("/api/notifications", headers={"Authorization": f"Bearer {key}"})).json()
        assert got["notification"] is None
