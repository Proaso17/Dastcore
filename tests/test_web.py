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


async def _wait_done(client: httpx.AsyncClient, scan_id: str, timeout_s: float = 300.0) -> httpx.Response:
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
    assert "Chatbot embebido" in resp.text  # the AI scan mode is offered in the form


async def test_dashboard_sets_security_headers(client: httpx.AsyncClient) -> None:
    """dastcore's own app must pass dastcore's passive checks (dogfooding)."""
    async with client:
        resp = await client.get("/")
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert "default-src" in resp.headers["content-security-policy"]
    assert resp.headers.get("referrer-policy") == "no-referrer"


async def test_start_scan_requires_authorization(client: httpx.AsyncClient, mini_target_url: str) -> None:
    async with client:
        resp = await client.post("/scans", data={"target": mini_target_url, "engine": "http"})
    assert resp.status_code == 400
    assert "autorización" in resp.text.lower()


async def test_full_scan_flow_finds_planted_vulns(client: httpx.AsyncClient, mini_target_url: str) -> None:
    async with client:
        resp = await client.post(
            "/scans",
            data={"target": mini_target_url, "engine": "http", "rps": "50", "authorization": "on"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        scan_id = resp.headers["location"].rsplit("/", 1)[-1]

        panel = await _wait_done(client, scan_id)
        assert "Completado" in panel.text
        assert "SQL Injection" in panel.text  # planted vuln surfaced in the results table
        # each issue carries an inline, actionable remediation guide
        assert "Cómo solucionarlo" in panel.text
        assert "parameterized queries" in panel.text  # a concrete fix step
        assert "cheatsheetseries.owasp.org" in panel.text  # a reference link

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


async def test_ai_chatbot_scan_from_dashboard(client: httpx.AsyncClient, chatbot_app_url: str, monkeypatch) -> None:
    """The 'Chatbot embebido (IA)' mode: launch from the form, discover the bot and run the
    LLM checks (incl. cross-tenant with a second identity), and surface them in the panel.

    The static crawler can't reach a JS-driven chat XHR, so we feed it the requests the
    headless engine would have captured (same shim used in the CLI discovery tests)."""
    import dastcore.cli as cli
    from dastcore.core.models import HttpRequest

    auth_a = {"Authorization": "Bearer tok-a"}
    candidates = [
        HttpRequest(method="POST", url=f"{chatbot_app_url}/api/chat", headers=auth_a, json_body={"message": "hola"}),
        HttpRequest(method="POST", url=f"{chatbot_app_url}/api/messages", headers=auth_a, json_body={"text": "n"}),
    ]

    class _FakeCrawler:
        def __init__(self, http_client, max_pages=200):
            pass

        async def crawl(self, start_url):
            return candidates

    monkeypatch.setattr(cli, "HttpCrawler", _FakeCrawler)
    async with client:
        resp = await client.post(
            "/scans",
            data={
                "target": chatbot_app_url,
                "mode": "ai",
                "rps": "50",
                "auth_bearer": "tok-a",
                "victim_bearer": "tok-b",
                "victim_ref": "unit 4B",
                "authorization": "on",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        scan_id = resp.headers["location"].rsplit("/", 1)[-1]

        panel = await _wait_done(client, scan_id)
        assert "Completado" in panel.text
        assert "Injection" in panel.text  # stored / second-order prompt injection surfaced
        assert "Cross-Tenant" in panel.text  # BOLA/BFLA via the assistant surfaced

        home = await client.get("/")
        assert "chatbot IA" in home.text  # history labels the run as an AI scan


async def test_retest_from_ui_marks_unchanged_target_open(client: httpx.AsyncClient, mini_target_url: str) -> None:
    async with client:
        # 1) an initial scan to retest
        resp = await client.post(
            "/scans",
            data={"target": mini_target_url, "engine": "http", "rps": "50", "authorization": "on"},
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


async def test_triage_accepts_finding_and_exports_ignore_file(client: httpx.AsyncClient, mini_target_url: str) -> None:
    async with client:
        resp = await client.post(
            "/scans",
            data={"target": mini_target_url, "engine": "http", "rps": "50", "authorization": "on"},
            follow_redirects=False,
        )
        scan_id = resp.headers["location"].rsplit("/", 1)[-1]
        await _wait_done(client, scan_id)

        # the SQLi issue is active before triage
        before = await client.get(f"/scans/{scan_id}/panel")
        assert "SQL Injection" in before.text
        assert "Aceptados" not in before.text

        # accept (suppress) the SQLi rule as a false positive
        supp = await client.post(
            "/suppress",
            data={"rule_id": "sqli-injection", "reason": "revisado: parametrizado", "scan_id": scan_id},
            follow_redirects=False,
        )
        assert supp.status_code == 303

        # now it shows under "Aceptados", not the active table's triage control
        after = await client.get(f"/scans/{scan_id}/panel")
        assert "Aceptados" in after.text

        # it is exported into a downloadable .dastcore-ignore
        ignore = await client.get("/dastcore-ignore")
        assert ignore.status_code == 200
        assert "sqli-injection" in ignore.text
        assert "revisado: parametrizado" in ignore.text

        # the triage page lists it, and it can be deleted
        page = await client.get("/suppressions")
        assert "sqli-injection" in page.text
        row_id = page.text.split("/suppress/")[1].split("/delete")[0]
        deleted = await client.post(f"/suppress/{row_id}/delete", follow_redirects=False)
        assert deleted.status_code == 303
        assert "sqli-injection" not in (await client.get("/suppressions")).text


async def test_diff_two_scans_of_unchanged_target(client: httpx.AsyncClient, mini_target_url: str) -> None:
    async with client:
        ids = []
        for _ in range(2):
            resp = await client.post(
                "/scans",
                data={"target": mini_target_url, "engine": "http", "rps": "50", "authorization": "on"},
                follow_redirects=False,
            )
            sid = resp.headers["location"].rsplit("/", 1)[-1]
            await _wait_done(client, sid)
            ids.append(sid)

        base, head = ids
        # the newer scan's detail offers a compare control against the older one
        detail = await client.get(f"/scans/{head}")
        assert "Comparar" in detail.text
        assert base in detail.text

        diff = await client.get(f"/diff?base={base}&head={head}")
        assert diff.status_code == 200
        # unchanged target -> identical id sets -> everything persistent, nothing new/fixed
        assert "nuevos: 0" in diff.text
        assert "corregidos: 0" in diff.text
        assert "Nada nuevo respecto al escaneo base." in diff.text


async def test_diff_missing_scan_is_404(client: httpx.AsyncClient) -> None:
    async with client:
        resp = await client.get("/diff?base=nope&head=nada")
    assert resp.status_code == 404


async def test_dashboard_counts_reflect_triage(client: httpx.AsyncClient, mini_target_url: str) -> None:
    async with client:
        resp = await client.post(
            "/scans",
            data={"target": mini_target_url, "engine": "http", "rps": "50", "authorization": "on"},
            follow_redirects=False,
        )
        scan_id = resp.headers["location"].rsplit("/", 1)[-1]
        await _wait_done(client, scan_id)

        before = await client.get("/")
        assert "aceptado(s)" not in before.text

        # accept the SQLi rule -> the dashboard row now shows it as accepted, off the count
        await client.post("/suppress", data={"rule_id": "sqli-injection", "reason": "fp", "scan_id": scan_id})
        after = await client.get("/")
        assert "aceptado(s)" in after.text


async def test_suppress_without_selector_is_ignored(client: httpx.AsyncClient) -> None:
    async with client:
        resp = await client.post("/suppress", data={"reason": "nada"}, follow_redirects=False)
        assert resp.status_code == 303
        page = await client.get("/suppressions")
    assert "Sin reglas de triaje" in page.text


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
