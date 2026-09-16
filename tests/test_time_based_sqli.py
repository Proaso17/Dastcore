"""Time-based blind SQLi confirmation by proportional delay, driven by a fake client that
sets response timing from the injected SLEEP(n) value — no real sleeping in the test.

The point: a real injection (delay scales with the injected sleep) is confirmed, while the
classic false-positive shapes — a constantly-slow endpoint and a fixed extra delay that
doesn't scale — are rejected."""

from __future__ import annotations

import re

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.engine.rule_engine import Rule
from dastcore.engine.scanner import Scanner
from dastcore.validation.oracles import OracleCheck, OracleSpec

_SLEEP = re.compile(r"SLEEP\((\d+)\)", re.IGNORECASE)
# Delay value across every supported backend's time payload (MySQL SLEEP, Postgres PG_SLEEP,
# MSSQL WAITFOR DELAY '0:0:n', Oracle DBMS_PIPE.RECEIVE_MESSAGE('a',n)).
_DELAY = re.compile(
    r"SLEEP\((\d+)\)|PG_SLEEP\((\d+)\)|WAITFOR\s+DELAY\s+'0:0:(\d+)'|RECEIVE_MESSAGE\('a',\s*(\d+)\)",
    re.IGNORECASE,
)


def _sleep_value(params: dict) -> int:
    for v in params.values():
        m = _SLEEP.search(str(v))
        if m:
            return int(m.group(1))
    return 0


def _delay_value(params: dict, pattern: re.Pattern[str] = _DELAY) -> int:
    for v in params.values():
        m = pattern.search(str(v))
        if m:
            return int(next(g for g in m.groups() if g is not None))
    return 0


class _TimingClient:
    """Returns a response whose elapsed_ms is computed by `timing(sleep_n)`."""

    def __init__(self, timing) -> None:
        self._timing = timing

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        n = _sleep_value(kwargs.get("params") or {})
        return HttpResponse(status_code=200, text="<h1>ok</h1>", url=url, elapsed_ms=self._timing(n))


def _time_rule() -> Rule:
    return Rule(
        id="sqli-injection",
        name="SQL Injection",
        family="sqli",
        severity="high",
        cwe="CWE-89",
        owasp="WSTG-INPV-05",
        inject_into=["query"],
        payloads=["'"],  # a declared in-band payload (won't be slow)
        oracle=OracleSpec(
            type="any_of",
            checks=[OracleCheck(type="time_based", payload="1 OR SLEEP({{delay}})-- -", delay=3, threshold_ms=2500)],
        ),
        remediation="parameterize",
    )


def _request() -> HttpRequest:
    return HttpRequest(method="GET", url="http://x/item", params={"id": "1"})


async def _scan(timing) -> list:
    scanner = Scanner(_TimingClient(timing), [_time_rule()], active_checks=False)
    findings = await scanner.scan_request(_request())
    return [f for f in findings if f.rule_id == "sqli-injection"]


async def test_real_injection_delay_scales_and_is_confirmed() -> None:
    # elapsed = 50ms + n seconds -> SLEEP(3) ~3s, SLEEP(6) ~6s: proportional.
    hits = await _scan(lambda n: 50.0 + n * 1000.0)
    assert len(hits) == 1
    assert hits[0].evidence[0].type == "time_based" and "proportional" in hits[0].evidence[0].data


async def test_constantly_slow_endpoint_is_not_flagged() -> None:
    # Always ~5s regardless of the injected sleep -> added delay ~0 -> no injection.
    assert await _scan(lambda n: 5000.0) == []


async def test_fixed_non_proportional_delay_is_not_flagged() -> None:
    # Adds a fixed 3s whenever any sleep is present but doesn't scale with its value.
    assert await _scan(lambda n: 50.0 + (3000.0 if n > 0 else 0.0)) == []


async def test_fast_endpoint_is_not_flagged() -> None:
    assert await _scan(lambda n: 40.0) == []


def test_shipped_sqli_rule_covers_all_major_databases() -> None:
    """General coverage: the shipped time-based SQLi oracle must fire on MySQL, PostgreSQL, MSSQL and
    Oracle (each uses a different sleep primitive) — not MySQL only, which was the gap."""
    from dastcore.engine.rule_engine import load_rules

    rule = next(r for r in load_rules() if r.id == "sqli-injection")
    payloads = " ".join(c.payload or "" for c in rule.oracle.checks if c.type == "time_based").upper()
    assert "SLEEP(" in payloads          # MySQL / MariaDB
    assert "PG_SLEEP(" in payloads       # PostgreSQL
    assert "WAITFOR DELAY" in payloads   # Microsoft SQL Server
    assert "DBMS_PIPE" in payloads       # Oracle


async def test_postgres_pg_sleep_injection_is_confirmed() -> None:
    """A Postgres-only backend (error-suppressed, no boolean signal): the pg_sleep payload must confirm
    via the same proportional-delay oracle — the cross-DB coverage this change adds."""
    from dastcore.validation.oracles import OracleCheck, OracleSpec

    rule = Rule(
        id="sqli-injection", name="SQL Injection", family="sqli", severity="high", cwe="CWE-89",
        owasp="WSTG-INPV-05", inject_into=["query"], payloads=["'"],
        oracle=OracleSpec(type="any_of", checks=[
            OracleCheck(type="time_based",
                        payload="' AND {{delay}}=(SELECT {{delay}} FROM PG_SLEEP({{delay}}))-- -",
                        delay=3, threshold_ms=2500),
        ]),
        remediation="parameterize",
    )

    class _PgTimingClient:
        async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
            n = _delay_value(kwargs.get("params") or {})  # scales only with PG_SLEEP(n)
            return HttpResponse(status_code=200, text="<h1>ok</h1>", url=url, elapsed_ms=50.0 + n * 1000.0)

    scanner = Scanner(_PgTimingClient(), [rule], active_checks=False)
    hits = [f for f in await scanner.scan_request(_request()) if f.rule_id == "sqli-injection"]
    assert len(hits) == 1 and hits[0].evidence[0].type == "time_based"
