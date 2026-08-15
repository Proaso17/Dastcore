"""WAF-evasion confirmation (Module 13): payload tampers (pure), and the scanner using them
to confirm a vulnerability the WAF masks — the raw payload is blocked (403), a tampered
variant slips through and fires the oracle, so the finding is reported as WAF-evaded."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.engine.rule_engine import Rule
from dastcore.engine.scanner import Scanner
from dastcore.engine.waf import (
    _cmdi_ifs,
    _cmdi_quote_insert,
    _sql_ws_comment,
    _swap_case,
    _url_encode,
    tampered_variants,
)
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


def test_family_tampers_are_appended_only_for_that_family() -> None:
    generic = {name for name, _ in tampered_variants("; cat /etc/passwd")}
    cmdi = {name for name, _ in tampered_variants("; cat /etc/passwd", "cmdi")}
    assert "ifs" not in generic and {"ifs", "quote-insert", "cmd-backslash"} <= cmdi


def test_cmdi_equivalents_keep_the_command_valid() -> None:
    assert _cmdi_ifs("cat /etc/passwd") == "cat${IFS}/etc/passwd"  # shell still splits on ${IFS}
    assert _cmdi_quote_insert("id") == 'i""d'  # bash strips the quotes and runs id
    assert _sql_ws_comment("UNION SELECT 1") == "UNION/**/SELECT/**/1"  # keywords intact -> valid SQL


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


# --- family-aware evasion: a space-blocking WAF only ${IFS} slips past -----------------------


def _cmdi_rule() -> Rule:
    return Rule(
        id="cmdi-inband",
        name="OS Command Injection (in-band)",
        family="cmdi",
        severity="critical",
        cwe="CWE-78",
        owasp="WSTG-INPV-12",
        inject_into=["query"],
        payloads=["; cat /etc/passwd"],
        oracle=OracleSpec(
            type="any_of", checks=[OracleCheck(type="response_match", part="body", patterns=["root:.*:0:0:"])]
        ),
        remediation="avoid shelling out with user input",
    )


class _SpaceBlockingWaf:
    """Blocks any 'q' with a literal space (403). The backend runs the command only when the
    separator survives as a real shell split — a raw space (blocked) or ``${IFS}`` (evasion)."""

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        value = (kwargs.get("params") or {}).get("q", "")
        if " " in value:  # the WAF signature: no spaces allowed here
            return HttpResponse(status_code=403, text="Request blocked by WAF", url=url)
        if "cat" in value and "passwd" in value and "${IFS}" in value:  # command actually executed
            return HttpResponse(status_code=200, text="root:x:0:0:root:/root:/bin/bash\n", url=url)
        return HttpResponse(status_code=200, text="pong", url=url)


async def test_family_aware_evasion_confirms_masked_cmdi() -> None:
    scanner = Scanner(_SpaceBlockingWaf(), [_cmdi_rule()], active_checks=False, waf_evasion=True)
    findings = await scanner.scan_request(_request())
    hits = [f for f in findings if f.rule_id == "cmdi-inband"]
    assert len(hits) == 1  # only the cmdi-specific ${IFS} tamper both evades the WAF and executes
    assert any("WAF-evaded" in e.data and "ifs" in e.data for e in hits[0].evidence)


async def test_generic_tampers_alone_do_not_confirm_the_space_blocked_cmdi() -> None:
    # Sanity: with no family match the generic tampers can't produce a working ${IFS} split,
    # so the space-blocked command injection is not confirmed — proving the family tamper is what did it.
    from dastcore.engine.waf import tampered_variants as tv

    generic_values = [v for _, v in tv("; cat /etc/passwd")]  # family="" -> generic only
    assert not any("${IFS}" in v for v in generic_values)
