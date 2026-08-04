"""Unit tests for the Scanner orchestrator, using a fake in-process HTTP client.

No real network/target involved here — these tests exist to pin down the
`confirm_reproducible` gate itself (the noise-suppression mechanism), which
is much easier to prove deterministically with scripted fake responses than
against a real server.
"""
from __future__ import annotations

import asyncio

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.engine.rule_engine import Rule
from dastcore.engine.scanner import Scanner
from dastcore.validation.oracles import OracleCheck, OracleSpec


class _FakeHttpClient:
    """Duck-typed stand-in for HttpClient: returns responses from a fixed script."""

    def __init__(self, responses: list[HttpResponse]) -> None:
        self._responses = list(responses)
        self.calls = 0

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        response = self._responses[self.calls]
        self.calls += 1
        return response


def _response(**overrides) -> HttpResponse:
    defaults = dict(status_code=200, headers={}, text="clean", elapsed_ms=1.0, url="http://x/test")
    defaults.update(overrides)
    return HttpResponse(**defaults)


def _flaky_rule() -> Rule:
    return Rule(
        id="test-rule",
        name="Test Rule",
        family="test",
        severity="high",
        cwe="CWE-0",
        owasp="TEST-0",
        inject_into=["query"],
        payloads=["x"],
        oracle=OracleSpec(type="any_of", checks=[OracleCheck(type="response_match", part="body", patterns=["FLAKY_MARKER"])]),
        confirm_reproducible=True,
        remediation="n/a",
    )


def _request() -> HttpRequest:
    return HttpRequest(method="GET", url="http://x/test", params={"q": "1"})


async def test_non_reproducible_hit_is_suppressed() -> None:
    responses = [
        _response(text="clean base"),  # base request
        _response(text="contains FLAKY_MARKER once"),  # first mutated attempt: matches
        _response(text="clean again"),  # confirmation attempt: does NOT match
    ]
    client = _FakeHttpClient(responses)
    scanner = Scanner(client, [_flaky_rule()])

    findings = await scanner.scan_request(_request())

    assert client.calls == 3
    assert not any(f.id.startswith("test-rule:") for f in findings)


async def test_reproducible_hit_is_reported() -> None:
    responses = [
        _response(text="clean base"),
        _response(text="contains FLAKY_MARKER once"),
        _response(text="contains FLAKY_MARKER again"),
    ]
    client = _FakeHttpClient(responses)
    scanner = Scanner(client, [_flaky_rule()])

    findings = await scanner.scan_request(_request())

    rule_findings = [f for f in findings if f.id.startswith("test-rule:")]
    assert len(rule_findings) == 1
    assert rule_findings[0].severity == "high"
    assert len(rule_findings[0].evidence) == 2  # one from detection, one from confirmation


async def test_no_finding_when_oracle_never_matches() -> None:
    responses = [
        _response(text="clean base"),
        _response(text="still clean"),  # never matches -> no confirm attempt needed
    ]
    client = _FakeHttpClient(responses)
    scanner = Scanner(client, [_flaky_rule()])

    findings = await scanner.scan_request(_request())

    assert client.calls == 2
    assert not any(f.id.startswith("test-rule:") for f in findings)


async def test_rule_skipped_when_injection_location_not_applicable() -> None:
    rule = _flaky_rule()
    rule = rule.model_copy(update={"inject_into": ["json"]})  # request only has a query param
    responses = [_response(text="clean base")]
    client = _FakeHttpClient(responses)
    scanner = Scanner(client, [rule])

    findings = await scanner.scan_request(_request())

    assert client.calls == 1  # only the base fetch, no mutation attempts at all
    assert not any(f.id.startswith("test-rule:") for f in findings)


class _ConcurrencyTrackingClient:
    """Fake client that records the peak number of simultaneously in-flight requests."""

    def __init__(self) -> None:
        self.in_flight = 0
        self.peak = 0

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            await asyncio.sleep(0.02)  # hold the "connection" so overlap is observable
            return _response(text="clean", url=url)
        finally:
            self.in_flight -= 1


async def test_scan_runs_requests_concurrently() -> None:
    client = _ConcurrencyTrackingClient()
    scanner = Scanner(client, [], concurrency=5)  # no rules: one base request per input
    requests = [HttpRequest(method="GET", url=f"http://x/p{i}") for i in range(10)]

    await scanner.scan_inband(requests)

    assert client.peak > 1  # requests genuinely overlapped
    assert client.peak <= 5  # but never exceeded the configured concurrency


async def test_scan_concurrency_one_is_sequential() -> None:
    client = _ConcurrencyTrackingClient()
    scanner = Scanner(client, [], concurrency=1)
    requests = [HttpRequest(method="GET", url=f"http://x/p{i}") for i in range(5)]

    await scanner.scan_inband(requests)

    assert client.peak == 1  # strictly one at a time
