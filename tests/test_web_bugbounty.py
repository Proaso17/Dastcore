"""Dashboard bug-bounty: create/list/delete a program via the UI, and launch a hunt as a background
job. The hunt here uses a seedless program so recon does nothing (fully offline)."""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest
from httpx import ASGITransport

from dastcore.bugbounty.program import Program, ProgramScope
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.web.app import create_app


@pytest.fixture
def app_client(tmp_path):
    app = create_app(db_path=tmp_path / "db.sqlite")
    transport = ASGITransport(app=app)
    return app, httpx.AsyncClient(transport=transport, base_url="http://test")


async def _wait_done(client: httpx.AsyncClient, scan_id: str, timeout_s: float = 60.0) -> httpx.Response:
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        resp = await client.get(f"/scans/{scan_id}/panel")
        if resp.headers.get("X-Scan-Done") == "1":
            return resp
        await asyncio.sleep(0.2)
    raise AssertionError("hunt did not finish in time")


async def test_bug_bounty_nav_and_empty_state(app_client) -> None:
    _, client = app_client
    async with client:
        resp = await client.get("/programs")
        home = await client.get("/")
    assert resp.status_code == 200
    assert "Nuevo objetivo" in resp.text and "Aún no tienes objetivos" in resp.text
    assert 'href="/programs"' in home.text  # nav links the bug-bounty area


async def test_create_list_and_delete_program(app_client) -> None:
    app, client = app_client
    async with client:
        created = await client.post(
            "/programs",
            data={
                "handle": "Acme",
                "in_scope": "acme.com\n*.acme.com",
                "out_of_scope": "blog.acme.com",
                "allow_active": "on",
            },
            follow_redirects=False,
        )
        assert created.status_code == 303
        page = await client.get("/programs")
        assert "Acme" in page.text and "acme.com" in page.text

        # the program was stored with the scope classified (wildcard vs domain)
        rows = app.state.store.list_programs()
        assert len(rows) == 1
        scope = rows[0].program.scope
        assert scope.domains == ["acme.com"] and scope.wildcards == ["*.acme.com"]
        assert "acme.com" in rows[0].program.seeds  # seeds derived from the in-scope hosts

        deleted = await client.post(f"/programs/{rows[0].id}/delete", follow_redirects=False)
        assert deleted.status_code == 303
        assert app.state.store.list_programs() == []


async def test_create_program_requires_scope(app_client) -> None:
    _, client = app_client
    async with client:
        resp = await client.post("/programs", data={"handle": "x", "in_scope": "", "allow_active": "on"})
    assert "al menos un dominio" in resp.text.lower()


async def test_hunt_requires_authorization_and_runs(app_client) -> None:
    app, client = app_client
    # A seedless program: recon has nothing to enumerate -> no network, completes instantly.
    program_id = app.state.store.add_program(
        Program(handle="local", scope=ProgramScope(domains=["127.0.0.1"]), seeds=[])
    )
    async with client:
        denied = await client.post(f"/programs/{program_id}/hunt", data={})
        assert "autorización" in denied.text.lower()

        launched = await client.post(
            f"/programs/{program_id}/hunt", data={"authorization": "on"}, follow_redirects=False
        )
        assert launched.status_code == 303
        scan_id = launched.headers["location"].rsplit("/", 1)[-1]
        await _wait_done(client, scan_id)

    scan = app.state.store.get_scan(scan_id)
    assert scan.kind == "hunt" and scan.status == "done"


def _sqli_finding() -> Finding:
    req = HttpRequest(method="GET", url="http://api.acme.com/search", params={"q": "1"})
    point = InjectionPoint(location="query", name="q", base_value="1", request_template=req)
    return Finding(
        id="sqli-injection:api.acme.com:q", rule_id="sqli-injection", name="SQL Injection", severity="critical",
        cwe="CWE-89", owasp="x", cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", family="sqli",
        injection_point=point, evidence=[Evidence(type="differential", data="TRUE/FALSE differed", confidence="high")],
        request=req, response=HttpResponse(status_code=500), remediation="Usa consultas parametrizadas.",
    )


async def test_bounty_report_page_renders_a_draft(app_client) -> None:
    app, client = app_client
    store = app.state.store
    store.insert_running("scan1", "http://api.acme.com", "hunt", None, time.time(), kind="hunt")
    store.mark_done("scan1", time.time(), 1.0, [_sqli_finding()])
    async with client:
        page = await client.get("/scans/scan1/bounty?platform=hackerone")
    assert page.status_code == 200
    assert "Crear informe para reportar" in page.text
    assert "SQL Injection" in page.text and "P1" in page.text
    assert "Steps To Reproduce" in page.text  # the HackerOne draft layout is rendered
