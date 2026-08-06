"""Web dashboard: end-to-end scan flow through the ASGI app against the vuln target.

Uses an async httpx client over ASGITransport so the background scan task runs on
the same event loop as the test (and progresses during ``await asyncio.sleep``).
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from httpx import ASGITransport

from dastcore.web.app import create_app
from dastcore.web.store import Store, severity_counts


@pytest.fixture
def client(tmp_path):
    app = create_app(db_path=tmp_path / "db.sqlite")
    transport = ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


async def _wait_done(client: httpx.AsyncClient, scan_id: str, timeout_s: float = 60.0) -> httpx.Response:
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        resp = await client.get(f"/scans/{scan_id}/panel")
        if resp.headers.get("X-Scan-Done") == "1":
            return resp
        await asyncio.sleep(0.5)
    raise AssertionError("scan did not finish in time")


async def test_dashboard_loads_empty(client: httpx.AsyncClient) -> None:
    async with client:
        resp = await client.get("/")
    assert resp.status_code == 200
    assert "Nuevo escaneo" in resp.text
    assert "Aún no hay escaneos" in resp.text


async def test_start_scan_requires_authorization(client: httpx.AsyncClient, vuln_app_url: str) -> None:
    async with client:
        resp = await client.post("/scans", data={"target": vuln_app_url, "engine": "http"})
    assert resp.status_code == 400
    assert "autorización" in resp.text.lower()


async def test_full_scan_flow_finds_planted_vulns(client: httpx.AsyncClient, vuln_app_url: str) -> None:
    async with client:
        resp = await client.post(
            "/scans",
            data={"target": vuln_app_url, "engine": "http", "rps": "50", "authorization": "on"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        scan_id = resp.headers["location"].rsplit("/", 1)[-1]

        panel = await _wait_done(client, scan_id)
        assert "Completado" in panel.text
        assert "SQL Injection" in panel.text  # planted vuln surfaced in the results table

        # history shows the finished run
        home = await client.get("/")
        assert scan_id in home.text
        assert "done" in home.text

        # findings are downloadable and non-empty
        as_json = await client.get(f"/scans/{scan_id}/findings.json")
        assert as_json.status_code == 200
        assert as_json.json()  # array of findings

        report = await client.get(f"/scans/{scan_id}/report")
        assert report.status_code == 200
        assert "<title>" in report.text


async def test_retest_from_ui_marks_unchanged_target_open(client: httpx.AsyncClient, vuln_app_url: str) -> None:
    async with client:
        # 1) an initial scan to retest
        resp = await client.post(
            "/scans",
            data={"target": vuln_app_url, "engine": "http", "rps": "50", "authorization": "on"},
            follow_redirects=False,
        )
        scan_id = resp.headers["location"].rsplit("/", 1)[-1]
        await _wait_done(client, scan_id)

        # retest requires the authorization checkbox
        denied = await client.post(f"/scans/{scan_id}/retest", data={})
        assert denied.status_code == 400

        # 2) launch the retest
        resp = await client.post(
            f"/scans/{scan_id}/retest", data={"rps": "50", "authorization": "on"}, follow_redirects=False
        )
        assert resp.status_code == 303
        retest_id = resp.headers["location"].rsplit("/", 1)[-1]
        assert retest_id != scan_id

        panel = await _wait_done(client, retest_id)
        # target is untouched -> every prior finding is still open, nothing fixed
        assert "Reverificación completada" in panel.text
        assert "ABIERTO" in panel.text
        assert "corregidos: 0" in panel.text
        # the retest links back to its parent scan
        assert scan_id in panel.text

        # history distinguishes the retest run
        home = await client.get("/")
        assert "retest" in home.text


async def test_retest_missing_scan_is_404(client: httpx.AsyncClient) -> None:
    async with client:
        resp = await client.post("/scans/deadbeef/retest", data={"authorization": "on"})
    assert resp.status_code == 404


async def test_bad_target_rerenders_form_with_error(client: httpx.AsyncClient) -> None:
    async with client:
        resp = await client.post("/scans", data={"target": "not-a-url", "authorization": "on"})
    assert resp.status_code == 400
    assert "no se pudo iniciar" in resp.text.lower()


def test_severity_counts_covers_all_levels() -> None:
    assert severity_counts([]) == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def test_store_marks_running_as_interrupted(tmp_path) -> None:
    store = Store(tmp_path / "db.sqlite")
    store.insert_running("abc", "http://t.test", "http", None, 1.0)
    store.mark_interrupted_running()
    assert store.get_scan("abc").status == "interrupted"
    store.close()
