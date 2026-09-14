"""sqlmap integration: the output parser (pure) and the subprocess runner driven by a stub 'sqlmap'
that prints canned output — so it runs deterministically without sqlmap installed."""

from __future__ import annotations

import sys
from pathlib import Path

from dastcore.core.models import HttpRequest
from dastcore.integrations.sqlmap import (
    build_sqlmap_args,
    parse_sqlmap_output,
    run_sqlmap_scan,
    sqlmap_available,
)

_VULN_OUTPUT = """\
        ___
       __H__
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3699=3699
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: id=1 AND SLEEP(5)
---
[INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
banner: '5.7.34-log'
current user: 'root@localhost'
current database: 'testdb'
"""

_SAFE_OUTPUT = "[CRITICAL] all tested parameters do not appear to be injectable.\n"


def test_parser_extracts_injection_dbms_and_impact() -> None:
    r = parse_sqlmap_output(_VULN_OUTPUT)
    assert r.injectable is True
    assert r.params == ["id"]
    assert "boolean-based blind" in r.techniques and "time-based blind" in r.techniques
    assert r.dbms == "MySQL >= 5.0.12"
    assert r.banner == "5.7.34-log"
    assert r.current_user == "root@localhost"
    assert r.current_db == "testdb"


def test_parser_reports_not_injectable() -> None:
    r = parse_sqlmap_output(_SAFE_OUTPUT)
    assert r.injectable is False and r.params == []


def test_build_args_stays_on_one_url_without_dump_or_crawl() -> None:
    req = HttpRequest(method="GET", url="http://t.test/item", params={"id": "1"})
    args = build_sqlmap_args(req, cookie="s=1", level=2, risk=2)
    assert "--batch" in args and "--flush-session" in args
    assert "--dump" not in args and "--crawl" not in args  # never exfiltrate / wander
    assert "--cookie" in args and "s=1" in args
    assert any(a.startswith("http://t.test/item?") and "id=1" in a for a in args)


def _stub(tmp_path: Path, output: str) -> list[str]:
    stub = tmp_path / "fake_sqlmap.py"
    stub.write_text(f"import sys\nsys.stdout.write({output!r})\n", encoding="utf-8")
    return [sys.executable, str(stub)]


def test_sqlmap_available_detects_a_real_path(tmp_path: Path) -> None:
    real = tmp_path / "sqlmap"
    real.write_text("x", encoding="utf-8")
    assert sqlmap_available([str(real)]) is True
    assert sqlmap_available([str(tmp_path / "nope")]) is False


async def test_runner_emits_finding_when_sqlmap_confirms(tmp_path: Path) -> None:
    cmd = _stub(tmp_path, _VULN_OUTPUT)
    req = HttpRequest(method="GET", url="http://t.test/item", params={"id": "1"})
    findings = await run_sqlmap_scan([req], cmd=cmd)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "sqli-sqlmap" and f.cwe == "CWE-89" and f.severity == "critical"
    assert "MySQL" in (f.impact or "") and "root@localhost" in (f.impact or "")


async def test_runner_no_finding_when_not_injectable(tmp_path: Path) -> None:
    cmd = _stub(tmp_path, _SAFE_OUTPUT)
    req = HttpRequest(method="GET", url="http://t.test/item", params={"id": "1"})
    assert await run_sqlmap_scan([req], cmd=cmd) == []


async def test_runner_no_finding_when_binary_missing() -> None:
    req = HttpRequest(method="GET", url="http://t.test/item", params={"id": "1"})
    assert await run_sqlmap_scan([req], cmd=["___definitely_not_sqlmap___"]) == []


async def test_runner_respects_scope() -> None:
    req = HttpRequest(method="GET", url="http://out.test/item", params={"id": "1"})
    # in_scope rejects everything -> sqlmap is never invoked
    assert await run_sqlmap_scan([req], cmd=["sqlmap"], in_scope=lambda url: False) == []
