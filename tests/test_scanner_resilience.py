"""Scanner resilience against flaky/hostile third-party targets — a server that disconnects mid-scan
(RemoteProtocolError) must not abort the whole active-scan phase; the failing probe is skipped and every
other request is still tested. This is the exact failure a real bWAPP/PHP target surfaced."""

from __future__ import annotations

import httpx

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.engine.rule_engine import Rule
from dastcore.engine.scanner import Scanner
from dastcore.validation.oracles import OracleCheck, OracleSpec


def _response(url: str) -> HttpResponse:
    return HttpResponse(status_code=200, headers={}, text="clean", elapsed_ms=1.0, url=url)


def _rule() -> Rule:
    return Rule(
        id="r", name="R", family="test", severity="high", cwe="CWE-0", owasp="T-0",
        inject_into=["query"], payloads=["x"],
        oracle=OracleSpec(type="any_of", checks=[OracleCheck(type="response_match", part="body", patterns=["ZZZ"])]),
        confirm_reproducible=True, remediation="n/a",
    )


class _DisconnectingClient:
    """Raises RemoteProtocolError for one host, serves a clean 200 for everything else."""

    def __init__(self, bad_url: str) -> None:
        self._bad = bad_url
        self.calls = 0

    async def request(self, method: str, url: str, **kwargs: object) -> HttpResponse:
        self.calls += 1
        if url == self._bad:
            raise httpx.RemoteProtocolError("Server disconnected without sending a response.")
        return _response(url)


async def test_scan_request_survives_a_disconnect() -> None:
    scanner = Scanner(_DisconnectingClient("http://bad/x"), [_rule()], active_checks=False)
    # The base request disconnects -> no response -> no findings, and crucially: no exception.
    assert await scanner.scan_request(HttpRequest(method="GET", url="http://bad/x", params={"q": "1"})) == []


async def test_disconnect_on_one_request_does_not_abort_the_phase() -> None:
    good = HttpRequest(method="GET", url="http://good/x", params={"q": "1"})
    bad = HttpRequest(method="GET", url="http://bad/x", params={"q": "1"})
    scanner = Scanner(_DisconnectingClient("http://bad/x"), [_rule()], active_checks=False, concurrency=3)

    done: list[str] = []
    findings = await scanner.scan_inband([bad, good, bad], on_request_done=lambda r, _f: done.append(r.url))

    # Every request in the batch was processed — the disconnects were isolated, not fatal to the gather.
    assert done.count("http://bad/x") == 2 and done.count("http://good/x") == 1
    assert isinstance(findings, list)


def test_a_hanging_check_is_timed_out_not_frozen(vuln_app_url, monkeypatch) -> None:
    # A check that hangs on a stuck socket/DNS (never attempting a new request, so the request-budget
    # can't catch it) must be cancelled by the per-phase timeout — not freeze the entire scan forever.
    import asyncio
    import json

    from typer.testing import CliRunner

    from dastcore import cli

    monkeypatch.setattr(cli, "_PHASE_TIMEOUT_S", 3.0)  # low cap so the test is fast

    async def _hang(*_a, **_k):
        await asyncio.sleep(120)  # simulate a hung phase (would freeze the scan without the fix)
        return []

    monkeypatch.setattr(cli, "run_nosql_checks", _hang)

    result = CliRunner().invoke(
        cli.app,
        ["scan", vuln_app_url, "--i-have-authorization", "--rps", "80", "--fail-on", "none", "--quiet", "-f", "json"],
    )
    assert result.exit_code == 0, result.stdout  # the scan COMPLETED despite the hang
    data = json.loads(result.stdout)
    cov = [f for f in data if f.get("rule_id") == "scan-coverage"]
    assert cov, "expected a partial-coverage advisory when a phase is skipped"
    assert "nosql" in json.dumps(cov[0])  # the hung phase was recorded as skipped
