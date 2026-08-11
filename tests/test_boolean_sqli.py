"""Boolean-based blind SQLi confirmation, driven by a scripted fake HTTP client."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.engine.rule_engine import BooleanPair, Rule
from dastcore.engine.scanner import Scanner

TRUE_PAGE = "<h1>Producto</h1><p>en stock</p>"
FALSE_PAGE = "<h1>Producto</h1><p>no encontrado</p>"


class _ScriptedClient:
    """Returns a body chosen by whether the request's `id` encodes a true condition."""

    def __init__(self) -> None:
        self.calls = 0

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        self.calls += 1
        value = (kwargs.get("params") or {}).get("id", "1")
        # base '1' (no condition) and any TRUE condition -> the "in stock" page.
        true_like = ("1=1" in value) or ("'1'='1" in value) or ("and" not in value.lower())
        return HttpResponse(status_code=200, text=TRUE_PAGE if true_like else FALSE_PAGE, url=url)


def _boolean_rule() -> Rule:
    return Rule(
        id="sqli-boolean-blind",
        name="SQLi (boolean blind)",
        family="sqli",
        severity="high",
        cwe="CWE-89",
        owasp="WSTG-INPV-05",
        inject_into=["query"],
        boolean_pairs=[BooleanPair(when_true="{{base}} AND 1=1", when_false="{{base}} AND 1=2")],
        remediation="parameterize",
    )


def _request() -> HttpRequest:
    return HttpRequest(method="GET", url="http://x/api/item", params={"id": "1"})


async def test_boolean_blind_is_detected() -> None:
    scanner = Scanner(_ScriptedClient(), [_boolean_rule()], active_checks=False)
    findings = await scanner.scan_request(_request())
    hits = [f for f in findings if f.rule_id == "sqli-boolean-blind"]
    assert len(hits) == 1
    assert hits[0].severity == "high"
    assert "boolean-based blind" in hits[0].evidence[0].data


class _StaticClient:
    """Always returns the same page regardless of the payload (not injectable)."""

    def __init__(self) -> None:
        self.calls = 0

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        self.calls += 1
        return HttpResponse(status_code=200, text=TRUE_PAGE, url=url)


async def test_no_false_positive_when_true_and_false_behave_the_same() -> None:
    # TRUE and FALSE both look like the baseline -> no boolean differential -> no finding.
    scanner = Scanner(_StaticClient(), [_boolean_rule()], active_checks=False)
    findings = await scanner.scan_request(_request())
    assert not any(f.rule_id == "sqli-boolean-blind" for f in findings)


class _EchoClient:
    """Echoes the injected value into the page (like a search box) -> TRUE != baseline."""

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        value = (kwargs.get("params") or {}).get("id", "1")
        return HttpResponse(status_code=200, text=f"<h1>Buscando {value}</h1>", url=url)


async def test_no_false_positive_when_input_is_echoed() -> None:
    # The echoed condition makes TRUE differ from the baseline, so it isn't confirmed.
    scanner = Scanner(_EchoClient(), [_boolean_rule()], active_checks=False)
    findings = await scanner.scan_request(_request())
    assert not any(f.rule_id == "sqli-boolean-blind" for f in findings)


class _UnstablePageClient:
    """A page with a rotating banner (unstable), where TRUE happens to match one baseline
    sample and FALSE differs — exactly the shape that would fool a naive boolean oracle."""

    def __init__(self) -> None:
        self.base_calls = 0

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        value = (kwargs.get("params") or {}).get("id", "1")
        if "and" not in value.lower():  # the base request (no condition), sampled repeatedly
            self.base_calls += 1
            banner = "" if self.base_calls == 1 else "<aside>promo of the day: buy one get one</aside>"
            return HttpResponse(status_code=200, text=TRUE_PAGE + banner, url=url)
        page = TRUE_PAGE if "1=1" in value else FALSE_PAGE
        return HttpResponse(status_code=200, text=page, url=url)


async def test_no_false_positive_when_baseline_is_unstable() -> None:
    # Without the stability gate this confirms (TRUE == first baseline sample, FALSE differs);
    # with it, the unstable baseline makes the scanner abstain — the page's own noise is not
    # a reliable TRUE/FALSE signal.
    scanner = Scanner(_UnstablePageClient(), [_boolean_rule()], active_checks=False)
    findings = await scanner.scan_request(_request())
    assert not any(f.rule_id == "sqli-boolean-blind" for f in findings)
