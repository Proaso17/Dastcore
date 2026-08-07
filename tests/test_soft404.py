"""Soft-404 / catch-all guard: suppress signature hits on endpoints that ignore the param."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.engine.rule_engine import Rule
from dastcore.engine.scanner import Scanner
from dastcore.validation.oracles import OracleCheck, OracleSpec

SIG_PAGE = "<h1>Descargas</h1><pre>[build-system]\nconfig de ejemplo</pre>"
NORMAL = "<h1>readme</h1><p>bienvenido</p>"


def _lfi_rule(*, guard: bool) -> Rule:
    return Rule(
        id="path-traversal-lfi",
        name="LFI",
        family="lfi",
        severity="high",
        cwe="CWE-22",
        owasp="WSTG-ATHZ-01",
        inject_into=["query"],
        payloads=["../../../../etc/passwd", "pyproject.toml"],
        oracle=OracleSpec(
            type="any_of",
            checks=[OracleCheck(type="response_match", part="body", patterns=["\\[build-system\\]"])],
        ),
        catch_all_guard=guard,
        confirm_reproducible=False,
        remediation="x",
    )


def _request() -> HttpRequest:
    return HttpRequest(method="GET", url="http://x/file", params={"name": "readme.txt"})


class _CatchAllClient:
    """Returns the same signature-matching help page for ANY value (ignores the param)."""

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        return HttpResponse(status_code=200, text=SIG_PAGE, url=url)


class _RealLfiClient:
    """Returns the signature only for a genuine file read; junk/base look different."""

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        value = (kwargs.get("params") or {}).get("name", "")
        if "etc/passwd" in value or "pyproject" in value:
            return HttpResponse(status_code=200, text=SIG_PAGE, url=url)
        return HttpResponse(status_code=404, text=NORMAL, url=url)


def _lfi_findings(findings) -> list:
    return [f for f in findings if f.rule_id == "path-traversal-lfi"]


async def test_catch_all_is_suppressed_with_guard() -> None:
    scanner = Scanner(_CatchAllClient(), [_lfi_rule(guard=True)], active_checks=False)
    findings = await scanner.scan_request(_request())
    assert _lfi_findings(findings) == []  # soft-404: no finding


async def test_catch_all_would_false_positive_without_guard() -> None:
    # Same endpoint, guard off -> the signature match is (wrongly) reported. Proves the guard matters.
    scanner = Scanner(_CatchAllClient(), [_lfi_rule(guard=False)], active_checks=False)
    findings = await scanner.scan_request(_request())
    assert len(_lfi_findings(findings)) == 1


async def test_real_lfi_is_still_reported_with_guard() -> None:
    scanner = Scanner(_RealLfiClient(), [_lfi_rule(guard=True)], active_checks=False)
    findings = await scanner.scan_request(_request())
    assert len(_lfi_findings(findings)) == 1  # genuine read differs from junk -> reported
