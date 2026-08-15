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
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from dastcore.ai.payload_gen import AiPayloadGenerator
from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.detectors.active_checks import check_cors_reflection
from dastcore.detectors.exposure import check_source_map
from dastcore.detectors.fingerprint import looks_blocked
from dastcore.detectors.passive import run_passive_checks
from dastcore.engine.injection_points import extract_injection_points
from dastcore.engine.oast import OastInteraction, OastProvider, substitute_oast
from dastcore.engine.rule_engine import (
    Rule,
    build_mutated_request,
    inband_payloads,
    oob_payload_templates,
    render_payload_template,
)
from dastcore.engine.waf import tampered_variants
from dastcore.report.correlation import cross_correlate
from dastcore.validation.baseline import BaselineProfile, build_baseline, responses_similar
from dastcore.validation.oracles import OracleSpec, evaluate_oracle
from dastcore.validation.reflection import analyze_reflection


def _reflection_excerpt(body: str, marker: str, window: int = 120) -> str:
    """A short slice of the response around where ``marker`` reflected, for the AI to see the
    exact surrounding markup/quotes. Empty if the marker isn't present."""
    idx = body.find(marker)
    if idx == -1:
        return ""
    start = max(0, idx - window)
    end = min(len(body), idx + len(marker) + window)
    return body[start:end]


def _time_based_checks(rule: Rule) -> list:
    """The rule's time-based oracle checks that carry a templated sleep payload."""
    if rule.oracle is None:
        return []
    return [c for c in rule.oracle.checks if c.type == "time_based" and c.payload]


def _oracle_without_timing(oracle: OracleSpec | None) -> OracleSpec:
    """A copy of the oracle with its time-based checks removed (timing is confirmed
    separately). An oracle that was *only* time-based becomes an empty check list, which
    evaluates to no in-band evidence."""
    if oracle is None:
        return OracleSpec(type="any_of", checks=[])
    return OracleSpec(type=oracle.type, checks=[c for c in oracle.checks if c.type != "time_based"])


@dataclass
class _OobProbe:
    """A pending OOB payload awaiting a correlated callback."""

    token: str
    rule: Rule
    point: InjectionPoint
    request: HttpRequest
    response: HttpResponse


@dataclass
class _StoredProbe:
    """A canary XSS payload injected at one point, to look for later on other pages."""

    token: str
    payload: str
    origin: HttpRequest
    point: InjectionPoint


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
        baseline_samples: int = 2,
        stored_scan: bool = False,
        waf_evasion: bool = False,
        ai_payloads: AiPayloadGenerator | None = None,
        ai_payload_budget: int = 15,
    ) -> None:
        self._http = http_client
        self._rules = rules
        self._oast = oast
        self._concurrency = max(1, concurrency)
        self._active_checks = active_checks
        self._oob_poll_attempts = oob_poll_attempts
        self._oob_poll_delay = oob_poll_delay
        self._baseline_samples = max(1, baseline_samples)
        self._stored_scan = stored_scan
        # When a raw payload is blocked, retry with encoding/case tampers to see if the vuln
        # is real but WAF-masked. Intrusive/noisy → opt-in (--waf-evasion), off in `quick`.
        self._waf_evasion = waf_evasion
        # Optional AI-assisted payload generation: when the declared payloads don't fire but the
        # input *reflects*, the AI proposes context-aware payloads. The rule's own oracle still
        # confirms every one (the AI never confirms). Bounded by a per-scan LLM-call budget.
        self._ai_payloads = ai_payloads
        self._ai_budget = ai_payload_budget
        self._ai_used = 0
        # Extra baseline samples pay off for two blind oracles: timing (to measure jitter)
        # and boolean-blind (to check the page is stable enough to trust a TRUE/FALSE diff).
        # Skip them otherwise to keep request volume down.
        self._needs_baseline = any(
            check.type == "time_based" for rule in rules if rule.oracle for check in rule.oracle.checks
        ) or any(rule.is_boolean for rule in rules)

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

        samples = [base_response]
        if self._needs_baseline:
            for _ in range(self._baseline_samples - 1):
                extra = await self._send(request)
                if extra is not None:
                    samples.append(extra)
        baseline = build_baseline(samples)

        for point in extract_injection_points(request):
            for rule in self._rules:
                if rule.is_oob or point.location not in rule.inject_into:
                    continue
                finding = (
                    await self._try_boolean(rule, point, baseline)
                    if rule.is_boolean
                    else await self._try_rule(rule, point, baseline)
                )
                if finding is None and _time_based_checks(rule):
                    finding = await self._try_time_based(rule, point, baseline)
                if finding is not None:
                    findings.append(finding)

        # Active per-request check that needs a crafted header rather than a fuzzed param.
        if self._active_checks and request.method == "GET":
            findings.extend(await check_cors_reflection(self._http, request))
            findings.extend(await check_source_map(self._http, request, base_response))

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
        """Full scan: concurrent in-band + passive, then OOB and (optional) stored correlation,
        finally cross-technique correlation over the whole set."""
        findings = await self.scan_inband(requests, on_request_done=on_request_done)
        findings.extend(await self.run_oob(requests))
        findings.extend(await self.run_stored(requests))
        return cross_correlate(findings)

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

    async def _try_rule(self, rule: Rule, point, baseline: BaselineProfile) -> Finding | None:
        base_response = baseline.primary
        # Timing checks are confirmed separately (proportional delay), so strip them from
        # the in-band evaluation — a declared payload should never be judged by timing here.
        inband_oracle = _oracle_without_timing(rule.oracle)
        for payload in inband_payloads(rule):
            request = build_mutated_request(point, payload.value)
            response = await self._send(request)
            if response is None:
                continue

            value = payload.value
            evidence = evaluate_oracle(
                inband_oracle, base_response=base_response, mutated_response=response, payload=value, baseline=baseline
            )
            note: str | None = None

            # If the raw payload was blocked and nothing fired, try to evade the WAF and confirm.
            if not evidence and self._waf_evasion and looks_blocked(response) is not None:
                evaded = await self._try_waf_evasion(inband_oracle, point, value, base_response, baseline, rule.family)
                if evaded is not None:
                    request, response, value, evidence, note = evaded

            if not evidence:
                continue

            if rule.catch_all_guard and await self._is_catch_all(point, response, baseline):
                continue  # endpoint returns the same thing for junk — a soft-404, not a hit

            if rule.confirm_reproducible:
                confirm_response = await self._send(request)
                if confirm_response is None:
                    continue
                confirm_evidence = evaluate_oracle(
                    inband_oracle,
                    base_response=base_response,
                    mutated_response=confirm_response,
                    payload=value,
                    baseline=baseline,
                )
                if not confirm_evidence:
                    continue
                evidence = evidence + confirm_evidence

            if note is not None:
                evidence = evidence + [Evidence(type="differential", data=note, confidence="high")]
            return self._build_finding(rule, point, evidence, request, response)

        # None of the declared payloads fired. If AI assistance is enabled and this point
        # reflects input, let the model propose context-aware payloads (oracle still confirms).
        if self._ai_payloads is not None and self._ai_used < self._ai_budget:
            return await self._try_ai_payloads(rule, point, baseline, inband_oracle)
        return None

    async def _try_ai_payloads(self, rule: Rule, point, baseline: BaselineProfile, inband_oracle: OracleSpec):
        """AI-assisted payloads: proposed by the model from the reflection context, confirmed by
        the rule's oracle. The AI never confirms — a payload is a finding only if `evaluate_oracle`
        fires on it (and reproduces), exactly like a declared payload."""
        if rule.oracle is None:
            return None
        canary = "dcaix" + secrets.token_hex(5)
        probe = await self._send(build_mutated_request(point, canary))
        if probe is None:
            return None
        info = analyze_reflection(probe.text, canary)
        if not (info.reflected or info.escaped):
            return None  # input isn't reflected here → no context for the model to tailor to

        self._ai_used += 1  # count the LLM call against the per-scan budget
        excerpt = _reflection_excerpt(probe.text, canary)
        context = (
            f"HTML context={info.context}; {'escaped/inert' if info.escaped and not info.reflected else 'raw/verbatim'}"
        )
        tried = [p.value for p in inband_payloads(rule)]
        try:
            payloads = await self._ai_payloads.suggest(rule.family, context, excerpt, tried)
        except Exception:  # noqa: BLE001 — a failed suggestion just means no AI payloads
            return None

        base_response = baseline.primary
        for value in payloads:
            request = build_mutated_request(point, value)
            response = await self._send(request)
            if response is None:
                continue
            evidence = evaluate_oracle(
                inband_oracle, base_response=base_response, mutated_response=response, payload=value, baseline=baseline
            )
            if not evidence:
                continue
            if rule.catch_all_guard and await self._is_catch_all(point, response, baseline):
                continue
            if rule.confirm_reproducible:
                confirm = await self._send(request)
                if confirm is None:
                    continue
                confirm_evidence = evaluate_oracle(
                    inband_oracle,
                    base_response=base_response,
                    mutated_response=confirm,
                    payload=value,
                    baseline=baseline,
                )
                if not confirm_evidence:
                    continue
                evidence = evidence + confirm_evidence
            evidence = evidence + [
                Evidence(
                    type="differential",
                    data=(
                        "payload propuesto por la IA a partir del contexto de reflexión y confirmado por el "
                        "oráculo — la IA no confirma hallazgos, solo amplía los inputs probados"
                    ),
                    confidence="high",
                )
            ]
            return self._build_finding(rule, point, evidence, request, response)
        return None

    async def _try_waf_evasion(
        self,
        oracle: OracleSpec,
        point,
        payload_value: str,
        base_response: HttpResponse,
        baseline: BaselineProfile,
        family: str = "",
    ) -> tuple[HttpRequest, HttpResponse, str, list[Evidence], str] | None:
        """Retry a blocked payload with encoding/case tampers (plus family-specific equivalents);
        return the first variant that gets past the WAF and fires the oracle (with a note), else None."""
        for name, tampered in tampered_variants(payload_value, family):
            request = build_mutated_request(point, tampered)
            response = await self._send(request)
            if response is None or looks_blocked(response) is not None:
                continue  # still blocked (or failed) — try the next tamper
            evidence = evaluate_oracle(
                oracle, base_response=base_response, mutated_response=response, payload=tampered, baseline=baseline
            )
            if evidence:
                note = f"WAF-evaded: the raw payload was blocked, confirmed via the {name!r} tamper (masked, not fixed)"
                return request, response, tampered, evidence, note
        return None

    @staticmethod
    def _junk_value() -> str:
        """A value that shouldn't match any real file/id, to learn the catch-all response."""
        return "dastcore-missing-" + secrets.token_hex(6)

    async def _is_catch_all(self, point, mutated_response: HttpResponse, baseline: BaselineProfile) -> bool:
        """True if the endpoint returns essentially the same response for a random junk
        value — i.e. it ignores this parameter, so the oracle hit is a soft-404 artifact."""
        junk = await self._send(build_mutated_request(point, self._junk_value()))
        return junk is not None and responses_similar(mutated_response, junk, baseline)

    async def _try_boolean(self, rule: Rule, point, baseline: BaselineProfile) -> Finding | None:
        """Boolean-based blind confirmation: send a TRUE and a FALSE condition and report
        only when the TRUE one behaves like the baseline while the FALSE one differs.

        Gated on baseline stability: if the page isn't identical across repeated identical
        requests (after masking known volatile regions), its own noise could masquerade as
        the FALSE-vs-baseline difference — so we abstain rather than risk a false positive.
        """
        if not baseline.stable:
            return None
        base = baseline.primary
        for pair in rule.boolean_pairs:
            true_value = pair.when_true.replace("{{base}}", point.base_value)
            false_value = pair.when_false.replace("{{base}}", point.base_value)
            true_request = build_mutated_request(point, true_value)
            false_request = build_mutated_request(point, false_value)
            true_response = await self._send(true_request)
            false_response = await self._send(false_request)
            if true_response is None or false_response is None:
                continue
            if not self._boolean_confirms(base, true_response, false_response, baseline):
                continue

            if rule.confirm_reproducible:
                retry_true = await self._send(true_request)
                retry_false = await self._send(false_request)
                if (
                    retry_true is None
                    or retry_false is None
                    or not self._boolean_confirms(base, retry_true, retry_false, baseline)
                ):
                    continue

            evidence = [
                Evidence(
                    type="differential",
                    data=(
                        f"boolean-based blind: TRUE ({true_value!r}) matches the baseline "
                        f"while FALSE ({false_value!r}) diverges"
                    )[:200],
                    confidence="high",
                )
            ]
            return self._build_finding(rule, point, evidence, true_request, true_response)
        return None

    @staticmethod
    def _boolean_confirms(
        base: HttpResponse, true_response: HttpResponse, false_response: HttpResponse, baseline: BaselineProfile
    ) -> bool:
        return responses_similar(base, true_response, baseline) and not responses_similar(
            base, false_response, baseline
        )

    # --- time-based (blind) ------------------------------------------------------------

    async def _timed_probe(self, point, payload_template: str, delay: float) -> HttpResponse | None:
        """Send the timing payload rendered with a specific `{{delay}}` and return the response."""
        value = render_payload_template(payload_template, delay=delay)
        return await self._send(build_mutated_request(point, value))

    async def _try_time_based(self, rule: Rule, point, baseline: BaselineProfile) -> Finding | None:
        """Confirm time-based blind injection by *proportional delay*, not a single slow hit.

        A slow response alone is weak: a constantly-slow endpoint, network spikes, or heavy
        parsing of a long payload all fake it. Instead we send the same injection with three
        sleep values — 0 (control), D and 2D — and require the *added* delay to both clear the
        threshold/jitter and to scale with the injected time (SLEEP(2D) adds clearly more than
        SLEEP(D)). Only a backend actually executing our SLEEP produces that proportionality,
        so constant or parse-driven slowness can't false-positive.
        """
        floor = 3 * baseline.jitter_ms
        for check in _time_based_checks(rule):
            assert check.payload is not None and check.delay is not None
            delay, threshold = float(check.delay), check.threshold_ms or 0.0

            slow = await self._timed_probe(point, check.payload, delay)
            if slow is None:
                continue
            control = await self._timed_probe(point, check.payload, 0)  # same payload, no sleep
            if control is None:
                continue
            added = slow.elapsed_ms - control.elapsed_ms
            if added < threshold or added < floor:
                continue  # not slow enough beyond the app's own baseline/noise

            double = await self._timed_probe(point, check.payload, delay * 2)
            if double is None:
                continue
            added_double = double.elapsed_ms - control.elapsed_ms
            if added_double < 1.5 * added:  # doubling the sleep must add clearly more time
                continue  # delay doesn't scale with the injected sleep — not a real injection

            evidence = [
                Evidence(
                    type="time_based",
                    data=(
                        f"time-based blind confirmed by proportional delay: SLEEP({delay:.0f}) added "
                        f"{added:.0f}ms and SLEEP({delay * 2:.0f}) added {added_double:.0f}ms over a "
                        f"zero-delay control (threshold {threshold:.0f}ms)"
                    )[:200],
                    confidence="high",
                )
            ]
            request = build_mutated_request(point, render_payload_template(check.payload, delay=delay))
            return self._build_finding(rule, point, evidence, request, slow)
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
                        _OobProbe(
                            token=handle.token, rule=rule, point=point, request=mutated_request, response=response
                        )
                    )
        return probes

    async def _correlate_oob(self, pending: list[_OobProbe]) -> list[Finding]:
        assert self._oast is not None
        # token -> the interaction that matched it, so we can classify the callback.
        matched: dict[str, OastInteraction] = {}
        for attempt in range(self._oob_poll_attempts):
            for interaction in await self._oast.poll():
                for probe in pending:
                    if probe.token == interaction.token or probe.token in interaction.raw:
                        matched.setdefault(probe.token, interaction)
            if len(matched) >= len(pending):
                break
            if attempt < self._oob_poll_attempts - 1:
                await asyncio.sleep(self._oob_poll_delay)

        findings: list[Finding] = []
        emitted: set[str] = set()
        for probe in pending:
            interaction = matched.get(probe.token)
            if interaction is None:
                continue
            key = f"{probe.rule.id}:{urlsplit(probe.request.url).path}:{probe.point.location}:{probe.point.name}"
            if key in emitted:
                continue
            emitted.add(key)
            # Classify by protocol: an HTTP callback means the server actually made a
            # request (a full server-side fetch — SSRF/RCE); a DNS-only lookup is a weaker
            # but still confirming signal (typical of blind XXE / Log4Shell resolvers).
            proto = interaction.protocol.upper()
            source = interaction.remote_addr or "the target"
            kind = "server-side fetch" if interaction.protocol.lower() == "http" else "DNS resolution"
            evidence = [
                Evidence(
                    type="oob",
                    data=f"out-of-band {proto} callback ({kind}) from {source} — token {probe.token}"[:200],
                    confidence="high",
                )
            ]
            findings.append(self._build_finding(probe.rule, probe.point, evidence, probe.request, probe.response))
        return findings

    # --- stored / second-order ---------------------------------------------------------

    async def run_stored(self, requests: list[HttpRequest]) -> list[Finding]:
        """Inject unique XSS canaries everywhere, then re-fetch pages and report any that
        surface — i.e. input persisted server-side and rendered on another request (stored
        XSS). A single-response oracle can't see this; re-crawling is what confirms it.

        A no-op unless the scanner was built with ``stored_scan=True`` (it is expensive:
        it injects a canary at every point and re-fetches every page)."""
        if not self._stored_scan:
            return []
        probes = await self._probe_stored(requests)
        if not probes:
            return []
        return await self._correlate_stored(probes, requests)

    async def _probe_stored(self, requests: list[HttpRequest]) -> list[_StoredProbe]:
        probes: list[_StoredProbe] = []
        for request in requests:
            for point in extract_injection_points(request, include_headers=False):
                token = "dcstored" + secrets.token_hex(6)
                payload = f'"><svg onload=alert(1)>{token}'
                if await self._send(build_mutated_request(point, payload)) is not None:
                    probes.append(_StoredProbe(token=token, payload=payload, origin=request, point=point))
        return probes

    async def _correlate_stored(self, probes: list[_StoredProbe], requests: list[HttpRequest]) -> list[Finding]:
        findings: list[Finding] = []
        emitted: set[str] = set()
        for page in requests:
            if page.method != "GET":
                continue
            # Re-fetch the page with its *original* values — no payload in this request,
            # so a canary in the body can only be there because it was stored.
            response = await self._send(page)
            if response is None:
                continue
            for probe in probes:
                if probe.token not in response.text:
                    continue
                # Only report when the stored payload actually executes in the page's context.
                info = analyze_reflection(response.text, probe.payload)
                if not info.executable:
                    continue
                key = f"{probe.point.location}:{probe.point.name}->{page.signature()}"
                if key in emitted:
                    continue
                emitted.add(key)
                findings.append(self._build_stored_finding(probe, page, response, info.context))
        return findings

    @staticmethod
    def _build_stored_finding(probe: _StoredProbe, page: HttpRequest, response: HttpResponse, context: str) -> Finding:
        origin_path = urlsplit(probe.origin.url).path or "/"
        surfaced_path = urlsplit(page.url).path or "/"
        injected = build_mutated_request(probe.point, probe.payload)
        return Finding(
            id=f"stored-xss:{probe.origin.method}:{origin_path}:{probe.point.location}:{probe.point.name}->{surfaced_path}",
            rule_id="stored-xss",
            name="Stored / Second-Order Cross-Site Scripting (XSS)",
            severity="high",
            cwe="CWE-79",
            owasp="WSTG-INPV-02",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
            family="xss",
            injection_point=probe.point,
            evidence=[
                Evidence(
                    type="reflected",
                    data=(
                        f"input at {probe.origin.method} {origin_path} ({probe.point.name}) persisted and "
                        f"executes at GET {surfaced_path} ({context} context)"
                    )[:200],
                    confidence="high",
                )
            ],
            request=injected,
            response=response,
            remediation=(
                "Escapa/valida la entrada del usuario al *renderizarla*, no solo al guardarla: aplica "
                "output encoding contextual en cada punto donde se muestra el dato almacenado."
            ),
        )

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
            cvss=rule.cvss,
            family=rule.family,
        )
