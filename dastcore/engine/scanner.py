"""Scanner: orchestrates passive checks, in-band active injection, and OOB probing.

For each discovered request: run the passive detectors on its base response,
then for each injection point try every applicable in-band rule. An in-band rule
only ever produces a `Finding` if its oracle fires — and, when
`confirm_reproducible` is set, fires *again* on a second, independent request.
That reproducibility gate keeps a flaky oracle from becoming a false positive.

Out-of-band (OOB) rules can't be judged from a single response, so they take a
separate path: each payload embeds a unique OAST callback; after all requests
are sent, the scanner polls the OAST provider and only reports a finding when a
correlated interaction actually arrived. No callback, no finding.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.detectors.active_checks import check_cors_reflection
from dastcore.detectors.passive import run_passive_checks
from dastcore.engine.injection_points import extract_injection_points
from dastcore.engine.oast import OastProvider, substitute_oast
from dastcore.engine.rule_engine import Rule, applicable_payloads, build_mutated_request, oob_payload_templates
from dastcore.validation.oracles import evaluate_oracle


@dataclass
class _OobProbe:
    """A pending OOB payload awaiting a correlated callback."""

    token: str
    rule: Rule
    point: InjectionPoint
    request: HttpRequest
    response: HttpResponse


class Scanner:
    """Runs passive + in-band active + OOB checks over a set of discovered requests."""

    def __init__(
        self,
        http_client: HttpClient,
        rules: list[Rule],
        oast: OastProvider | None = None,
        *,
        concurrency: int = 1,
        active_checks: bool = True,
        oob_poll_attempts: int = 4,
        oob_poll_delay: float = 0.5,
    ) -> None:
        self._http = http_client
        self._rules = rules
        self._oast = oast
        self._concurrency = max(1, concurrency)
        self._active_checks = active_checks
        self._oob_poll_attempts = oob_poll_attempts
        self._oob_poll_delay = oob_poll_delay

    async def _send(self, request: HttpRequest) -> HttpResponse | None:
        try:
            return await self._http.request(
                request.method,
                request.url,
                params=request.params,
                headers=request.headers or None,
                cookies=request.cookies or None,
                data=request.data,
                json=request.json_body,
            )
        except (OutOfScopeError, BudgetExceededError):
            return None
        except (httpx.InvalidURL, httpx.LocalProtocolError):
            # A mutated payload produced a request httpx refuses to send (e.g. illegal
            # header value). Skip it rather than aborting the whole scan.
            return None

    def _oast_active(self) -> bool:
        return self._oast is not None and self._oast.is_available()

    async def scan_request(self, request: HttpRequest) -> list[Finding]:
        base_response = await self._send(request)
        if base_response is None:
            return []

        findings = run_passive_checks(request, base_response)

        for point in extract_injection_points(request):
            for rule in self._rules:
                if rule.is_oob or point.location not in rule.inject_into:
                    continue
                finding = await self._try_rule(rule, point, base_response)
                if finding is not None:
                    findings.append(finding)

        # Active per-request check that needs a crafted header rather than a fuzzed param.
        if self._active_checks and request.method == "GET":
            findings.extend(await check_cors_reflection(self._http, request))

        return findings

    async def scan_inband(
        self,
        requests: list[HttpRequest],
        *,
        on_request_done: Callable[[HttpRequest, list[Finding]], None] | None = None,
    ) -> list[Finding]:
        """Run in-band + passive checks over requests with bounded concurrency (no OOB).

        `on_request_done` is invoked (on the event loop) after each request finishes,
        with that request and its findings — used to drive progress and resume state.
        """
        semaphore = asyncio.Semaphore(self._concurrency)

        async def _worker(request: HttpRequest) -> list[Finding]:
            async with semaphore:
                request_findings = await self.scan_request(request)
            if on_request_done is not None:
                on_request_done(request, request_findings)
            return request_findings

        results = await asyncio.gather(*(_worker(request) for request in requests))
        return [finding for group in results for finding in group]

    async def scan(
        self,
        requests: list[HttpRequest],
        *,
        on_request_done: Callable[[HttpRequest, list[Finding]], None] | None = None,
    ) -> list[Finding]:
        """Full scan: concurrent in-band + passive, then OOB correlation."""
        findings = await self.scan_inband(requests, on_request_done=on_request_done)
        findings.extend(await self.run_oob(requests))
        return findings

    async def run_oob(self, requests: list[HttpRequest]) -> list[Finding]:
        """Probe every request's OOB rules and report only those with a correlated callback."""
        if not self._oast_active():
            return []
        pending_oob: list[_OobProbe] = []
        for request in requests:
            pending_oob.extend(await self._probe_oob(request))
        if not pending_oob:
            return []
        return await self._correlate_oob(pending_oob)

    async def _try_rule(self, rule: Rule, point, base_response: HttpResponse) -> Finding | None:
        for payload in applicable_payloads(rule):
            mutated_request = build_mutated_request(point, payload.value)
            mutated_response = await self._send(mutated_request)
            if mutated_response is None:
                continue

            evidence = evaluate_oracle(
                rule.oracle, base_response=base_response, mutated_response=mutated_response, payload=payload.value
            )
            if not evidence:
                continue

            if rule.confirm_reproducible:
                confirm_response = await self._send(mutated_request)
                if confirm_response is None:
                    continue
                confirm_evidence = evaluate_oracle(
                    rule.oracle, base_response=base_response, mutated_response=confirm_response, payload=payload.value
                )
                if not confirm_evidence:
                    continue
                evidence = evidence + confirm_evidence

            return self._build_finding(rule, point, evidence, mutated_request, mutated_response)

        return None

    # --- OOB ---------------------------------------------------------------------------

    async def _probe_oob(self, request: HttpRequest) -> list[_OobProbe]:
        assert self._oast is not None
        probes: list[_OobProbe] = []
        points = extract_injection_points(request)
        for rule in self._rules:
            if not rule.is_oob:
                continue
            for point in points:
                if point.location not in rule.inject_into:
                    continue
                for template in oob_payload_templates(rule):
                    handle = self._oast.new_handle()
                    value = substitute_oast(template, handle)
                    mutated_request = build_mutated_request(point, value)
                    response = await self._send(mutated_request)
                    if response is None:
                        continue
                    probes.append(
                        _OobProbe(token=handle.token, rule=rule, point=point, request=mutated_request, response=response)
                    )
        return probes

    async def _correlate_oob(self, pending: list[_OobProbe]) -> list[Finding]:
        assert self._oast is not None
        matched: set[str] = set()
        for attempt in range(self._oob_poll_attempts):
            for interaction in await self._oast.poll():
                for probe in pending:
                    if probe.token == interaction.token or probe.token in interaction.raw:
                        matched.add(probe.token)
            if len(matched) >= len(pending):
                break
            if attempt < self._oob_poll_attempts - 1:
                await asyncio.sleep(self._oob_poll_delay)

        findings: list[Finding] = []
        emitted: set[str] = set()
        for probe in pending:
            if probe.token not in matched:
                continue
            key = f"{probe.rule.id}:{urlsplit(probe.request.url).path}:{probe.point.location}:{probe.point.name}"
            if key in emitted:
                continue
            emitted.add(key)
            evidence = [
                Evidence(
                    type="oob",
                    data=f"target made an out-of-band callback correlated to payload token {probe.token}",
                    confidence="high",
                )
            ]
            findings.append(self._build_finding(probe.rule, probe.point, evidence, probe.request, probe.response))
        return findings

    # --- shared ------------------------------------------------------------------------

    @staticmethod
    def _build_finding(rule: Rule, point, evidence, request: HttpRequest, response: HttpResponse) -> Finding:
        path = urlsplit(request.url).path or "/"
        return Finding(
            id=f"{rule.id}:{request.method}:{path}:{point.location}:{point.name}",
            rule_id=rule.id,
            name=rule.name,
            severity=rule.severity,
            cwe=rule.cwe,
            owasp=rule.owasp,
            injection_point=point,
            evidence=evidence,
            request=request,
            response=response,
            remediation=rule.remediation,
        )
