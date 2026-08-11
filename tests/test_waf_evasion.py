"""WAF-evasion confirmation (Module 13): payload tampers (pure), and the scanner using them
to confirm a vulnerability the WAF masks — the raw payload is blocked (403), a tampered
variant slips through and fires the oracle, so the finding is reported as WAF-evaded."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.engine.rule_engine import Rule
from dastcore.engine.scanner import Scanner
from dastcore.engine.waf import _swap_case, _url_encode, tampered_variants
from dastcore.validation.oracles import OracleCheck, OracleSpec


def test_case_swap_keeps_meaning_changes_signature() -> None:
    out = _swap_case("1' OR 1=1")
    assert out != "1' OR 1=1" and out.lower() == "1' or 1=1"  # only case changed


def test_url_encode_hides_special_chars() -> None:
    assert _url_encode("' OR 1=1") == "%27%20OR%201%3D1"


def test_tampered_variants_are_distinct_and_nonempty() -> None:
    variants = tampered_variants("' OR SELECT 1")
    values = [v for _, v in variants]
    assert values and len(values) == len(set(values)) and "' OR SELECT 1" not in values


# --- scanner integration: a naive WAF that blocks the raw SQLi keyword -------------------


def _sqli_rule() -> Rule:
    return Rule(
        id="sqli-injection",
        name="SQL Injection",
        family="sqli",
        severity="high",
        cwe="CWE-89",
        owasp="WSTG-INPV-05",
        inject_into=["query"],
        payloads=["' OR SELECT"],
        oracle=OracleSpec(
            type="any_of", checks=[OracleCheck(type="response_match", part="body", patterns=["SQL syntax error"])]
        ),
        remediation="parameterize",
    )


class _NaiveWafClient:
    """Blocks any request whose 'q' contains the literal 'SELECT' (case-sensitive) with a 403;
    otherwise the underlying app is vulnerable and returns a SQL error for a quote."""

    def __init__(self) -> None:
        self.calls = 0

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        self.calls += 1
        value = (kwargs.get("params") or {}).get("q", "")
        if "SELECT" in value:  # case-sensitive signature filter (the naive WAF)
            return HttpResponse(status_code=403, text="Request blocked by WAF", url=url)
        if "'" in value:  # the app itself is injectable
            return HttpResponse(status_code=500, text="You have an SQL syntax error near '...'", url=url)
        return HttpResponse(status_code=200, text="ok", url=url)


def _request() -> HttpRequest:
    return HttpRequest(method="GET", url="http://x/item", params={"q": "1"})


async def test_waf_evasion_confirms_masked_sqli() -> None:
    scanner = Scanner(_NaiveWafClient(), [_sqli_rule()], active_checks=False, waf_evasion=True)
    findings = await scanner.scan_request(_request())
    hits = [f for f in findings if f.rule_id == "sqli-injection"]
    assert len(hits) == 1
    assert any("WAF-evaded" in e.data for e in hits[0].evidence)  # noted as masked, not fixed


async def test_without_flag_the_masked_sqli_is_not_confirmed() -> None:
    # No --waf-evasion: the raw payload is blocked and the vuln stays hidden (no over-claim).
    scanner = Scanner(_NaiveWafClient(), [_sqli_rule()], active_checks=False, waf_evasion=False)
    findings = await scanner.scan_request(_request())
    assert not any(f.rule_id == "sqli-injection" for f in findings)
