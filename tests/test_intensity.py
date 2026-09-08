"""Intensity boost: when the adaptive planner marks a family as a priority for the target, the scanner
tries that rule's ``intensive_payloads`` and turns on WAF evasion automatically — more coverage for the
classes the target is likely vulnerable to. The rule's own oracle still confirms every payload, so more
payloads never means more false positives; that invariant is the point of these tests."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.engine.rule_engine import Rule, inband_payloads, load_rules, oob_payload_templates
from dastcore.engine.scanner import Scanner
from dastcore.validation.oracles import OracleCheck, OracleSpec


def _sqli_rule(*, intensive: list[str] | None = None, payloads: list[str] | None = None) -> Rule:
    return Rule(
        id="sqli-injection", name="SQL Injection", family="sqli", severity="high",
        cwe="CWE-89", owasp="WSTG-INPV-05", inject_into=["query"],
        payloads=payloads if payloads is not None else ["'"],
        intensive_payloads=intensive or [],
        oracle=OracleSpec(
            type="any_of", checks=[OracleCheck(type="response_match", part="body", patterns=["SQL syntax error"])]
        ),
        remediation="parameterize",
    )


# --- rule_engine: intensive_payloads are opt-in via the `intensive` flag -----------------------------


def test_inband_payloads_appends_intensive_only_when_requested() -> None:
    rule = _sqli_rule(payloads=["a"], intensive=["b", "c"])
    assert [p.value for p in inband_payloads(rule)] == ["a"]                      # default: declared only
    assert [p.value for p in inband_payloads(rule, intensive=True)] == ["a", "b", "c"]


def test_inband_payloads_dedups_when_intensive_repeats_a_declared_one() -> None:
    rule = _sqli_rule(payloads=["a", "b"], intensive=["b", "d"])
    assert [p.value for p in inband_payloads(rule, intensive=True)] == ["a", "b", "d"]  # no duplicate "b"


def test_oob_templates_include_intensive_oast_payloads_only_when_requested() -> None:
    rule = Rule(
        id="cmdi-oob", name="cmdi", family="cmdi", severity="critical", cwe="CWE-78", owasp="WSTG-INPV-12",
        inject_into=["query"], payloads=["curl {{oast_url}}"],
        intensive_payloads=["|| curl {{oast_url}}", "plain-no-oast"],  # the non-OAST one is filtered out
        oracle=OracleSpec(type="any_of", checks=[OracleCheck(type="oob")]), confirm_reproducible=False,
        remediation="n/a",
    )
    assert oob_payload_templates(rule) == ["curl {{oast_url}}"]
    assert oob_payload_templates(rule, intensive=True) == ["curl {{oast_url}}", "|| curl {{oast_url}}"]


# --- scanner: an intensive-only payload is found ONLY when the family is a priority ------------------


class _OnlyIntensiveVuln:
    """Injectable only by the intensive payload ``')`` — a benign base payload never triggers the error."""

    async def request(self, method: str, url: str, **kwargs: object) -> HttpResponse:
        value = str((kwargs.get("params") or {}).get("q", ""))  # type: ignore[union-attr]
        if "')" in value:
            return HttpResponse(status_code=500, text="You have an SQL syntax error near '...'", url=url)
        return HttpResponse(status_code=200, text="ok", url=url)


def _request() -> HttpRequest:
    return HttpRequest(method="GET", url="http://x/item", params={"q": "1"})


async def test_intensive_payload_found_when_family_is_priority() -> None:
    rule = _sqli_rule(payloads=["benign"], intensive=["')"])
    scanner = Scanner(_OnlyIntensiveVuln(), [rule], active_checks=False, priority_families=("sqli",))
    hits = [f for f in await scanner.scan_request(_request()) if f.rule_id == "sqli-injection"]
    assert len(hits) == 1  # the planner flagged sqli -> the intensive payload was tried and confirmed


async def test_intensive_payload_not_tried_without_priority() -> None:
    rule = _sqli_rule(payloads=["benign"], intensive=["')"])
    scanner = Scanner(_OnlyIntensiveVuln(), [rule], active_checks=False)  # no plan -> base payloads only
    assert not any(f.rule_id == "sqli-injection" for f in await scanner.scan_request(_request()))


# --- scanner: a priority family turns on WAF evasion even without the global --waf-evasion flag -------


class _NaiveWafClient:
    """Blocks any 'q' containing 'SELECT' (case-sensitive) with 403; the app errors on a quote otherwise."""

    async def request(self, method: str, url: str, **kwargs: object) -> HttpResponse:
        value = str((kwargs.get("params") or {}).get("q", ""))  # type: ignore[union-attr]
        if "SELECT" in value:
            return HttpResponse(status_code=403, text="Request blocked by WAF", url=url)
        if "'" in value:
            return HttpResponse(status_code=500, text="You have an SQL syntax error near '...'", url=url)
        return HttpResponse(status_code=200, text="ok", url=url)


async def test_priority_family_auto_evades_waf_without_the_flag() -> None:
    # waf_evasion is OFF, but sqli is a priority -> the blocked raw payload is retried with tampers and
    # the case-swapped variant slips past, confirming the WAF-masked SQLi. Intensity, not the flag.
    rule = _sqli_rule(payloads=["' OR SELECT"])
    scanner = Scanner(_NaiveWafClient(), [rule], active_checks=False, waf_evasion=False,
                      priority_families=("sqli",))
    hits = [f for f in await scanner.scan_request(_request()) if f.rule_id == "sqli-injection"]
    assert len(hits) == 1
    assert any("WAF-evaded" in e.data for e in hits[0].evidence)


async def test_non_priority_family_does_not_auto_evade() -> None:
    # Neither the flag nor a priority for sqli -> the masked SQLi stays hidden (no over-claim).
    rule = _sqli_rule(payloads=["' OR SELECT"])
    scanner = Scanner(_NaiveWafClient(), [rule], active_checks=False, waf_evasion=False,
                      priority_families=("lfi",))  # some *other* family is the priority
    assert not any(f.rule_id == "sqli-injection" for f in await scanner.scan_request(_request()))


# --- the invariant: intensive payloads never false-positive on a clean response ---------------------


class _CleanApp:
    """A well-behaved app: 200 OK, no reflection, no error strings — nothing should ever be flagged."""

    async def request(self, method: str, url: str, **kwargs: object) -> HttpResponse:
        return HttpResponse(status_code=200, text="<html><body>welcome</body></html>", url=url)


async def test_real_intensive_banks_do_not_false_positive_on_a_clean_page() -> None:
    # Load the SHIPPED rules, mark every family a priority (so all intensive banks fire), and scan a clean
    # app. Every intensive payload is still oracle-gated, so a benign response must produce zero findings.
    rules = [r for r in load_rules() if r.intensive_payloads and not r.is_oob]
    assert rules, "expected shipped rules to carry intensive_payloads"
    families = tuple({r.family for r in rules})
    scanner = Scanner(_CleanApp(), rules, active_checks=False, priority_families=families)
    findings = await scanner.scan_request(_request())
    injection_ids = {r.id for r in rules}  # ignore passive header checks that also run on the base response
    assert [f for f in findings if f.rule_id in injection_ids] == []
