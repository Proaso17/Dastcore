"""Continuous-monitoring delta alerts: NEW-since-last findings are POSTed to a webhook (Slack/Discord/
generic), and only above the configured severity. Payload shapes are pure; delivery is best-effort."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.notify import (
    build_discord_payload,
    build_generic_payload,
    build_slack_payload,
    filter_by_severity,
    send_alert,
)
from dastcore.web.jobs import ScanManager
from dastcore.web.store import Store


def _finding(fid: str, severity: str = "high", name: str = "SQL Injection") -> Finding:
    req = HttpRequest(method="GET", url="http://t.test/x", params={"q": "1"})
    point = InjectionPoint(location="query", name="q", base_value="1", request_template=req)
    return Finding(
        id=fid, rule_id="sqli-injection", name=name, severity=severity, cwe="CWE-89", owasp="WSTG-INPV-05",
        family="sqli", injection_point=point,
        evidence=[Evidence(type="differential", data="x", confidence="high")],
        request=req, response=HttpResponse(status_code=500), remediation="parametrize",
    )


# --- pure payload shapes -----------------------------------------------------------------------


def test_slack_payload_lists_findings() -> None:
    p = build_slack_payload("t.test", [_finding("a"), _finding("b", "critical", "RCE")])
    assert "2 hallazgo(s) nuevo(s)" in p["text"] and "RCE" in p["text"] and "blocks" in p


def test_discord_payload_uses_content_and_bold() -> None:
    p = build_discord_payload("t.test", [_finding("a")])
    assert set(p) == {"content"} and "**" in p["content"] and "SQL Injection" in p["content"]


def test_generic_payload_is_structured_json() -> None:
    p = build_generic_payload("t.test", [_finding("a"), _finding("b")])
    assert p["event"] == "regression" and p["findings_count"] == 2
    assert p["severity_counts"]["high"] == 2 and p["findings"][0]["rule_id"] == "sqli-injection"


def test_filter_by_severity_applies_the_floor() -> None:
    findings = [_finding("a", "low"), _finding("b", "high"), _finding("c", "critical")]
    assert {f.id for f in filter_by_severity(findings, "high")} == {"b", "c"}


# --- delivery (best-effort) --------------------------------------------------------------------


@pytest.fixture()
def capture_server() -> Iterator[tuple[str, list]]:
    from flask import Flask, request

    received: list = []
    app = Flask(__name__)

    @app.post("/hook")
    def hook():
        received.append(request.get_json(force=True))
        return "", 200

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}/hook", received
    server.shutdown()


async def test_send_alert_posts_and_reports_success(capture_server) -> None:
    url, received = capture_server
    ok = await send_alert(url, "generic", "t.test", [_finding("a")])
    assert ok is True and len(received) == 1 and received[0]["target"] == "t.test"


async def test_send_alert_is_best_effort_on_a_dead_webhook() -> None:
    # An unroutable URL must return False, never raise.
    assert await send_alert("http://127.0.0.1:1/nope", "slack", "t.test", [_finding("a")]) is False


async def test_send_alert_skips_when_nothing_to_report(capture_server) -> None:
    url, received = capture_server
    assert await send_alert(url, "slack", "t.test", []) is False and received == []


# --- store + manager delta ---------------------------------------------------------------------


def test_alert_settings_roundtrip_and_previous_findings(tmp_path) -> None:
    store = Store(db_path=tmp_path / "db.sqlite")
    assert store.get_alert_settings().enabled is False  # default
    store.set_alert_settings("http://h/hook", "discord", "high", True)
    got = store.get_alert_settings()
    assert (got.webhook_url, got.fmt, got.min_severity, got.enabled) == ("http://h/hook", "discord", "high", True)

    store.insert_running("old", "http://t.test", "http", None, 1.0)
    store.mark_done("old", 2.0, 1.0, [_finding("a")])
    store.insert_running("new", "http://t.test", "http", None, 3.0)
    store.mark_done("new", 4.0, 1.0, [_finding("a"), _finding("b")])
    prev = store.previous_findings_for_target("http://t.test", "new")
    assert {f.id for f in prev} == {"a"}  # the older run's findings are the baseline


async def test_manager_notify_delta_alerts_only_on_new_findings(tmp_path, capture_server) -> None:
    url, received = capture_server
    store = Store(db_path=tmp_path / "db.sqlite")
    store.set_alert_settings(url, "generic", "medium", True)
    store.insert_running("old", "http://t.test", "http", None, 1.0)
    store.mark_done("old", 2.0, 1.0, [_finding("a")])
    store.insert_running("new", "http://t.test", "http", None, 3.0)
    current = [_finding("a"), _finding("b", "high", "New XSS")]
    store.mark_done("new", 4.0, 1.0, current)

    await ScanManager(store)._notify_delta("new", "http://t.test", current)
    assert len(received) == 1
    payload = received[0]
    assert payload["findings_count"] == 1 and payload["findings"][0]["name"] == "New XSS"  # only the NEW one


async def test_manager_notify_delta_is_silent_when_disabled(tmp_path, capture_server) -> None:
    url, received = capture_server
    store = Store(db_path=tmp_path / "db.sqlite")
    store.set_alert_settings(url, "generic", "medium", False)  # disabled
    await ScanManager(store)._notify_delta("x", "http://t.test", [_finding("a")])
    assert received == []
