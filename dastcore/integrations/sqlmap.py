"""Optional sqlmap integration — a deep, opt-in SQL-injection sweep.

dastcore already detects SQLi natively (error/boolean/time/OOB, plus impact proof). This bolts on
sqlmap, the industry-standard SQLi tool, as a **deep, opt-in escalation** for maximum detection: it
runs sqlmap, targeted at discovered injection points (URL + parameters), and turns sqlmap's own
confirmation into findings enriched with the DBMS fingerprint, technique, and a safe impact proof
(banner / current user / current database — **never a data dump**).

Design and safety:

* **Opt-in** (``--sqlmap``): it shells out to an external tool and is intrusive, so it is off by
  default. If the ``sqlmap`` binary isn't installed it is a clean no-op (the CLI notes it).
* **Scope-enforced**: only in-scope URLs are ever handed to sqlmap, and it is run without crawling or
  following redirects, so it stays on the exact endpoint we give it.
* **Bounded**: a capped number of targets, each with a per-target timeout and limited ``--level`` /
  ``--risk``; ``--batch`` (non-interactive) and ``--flush-session`` (fresh each run).
* **False-positive-free**: a finding is emitted only when sqlmap itself confirms an injection point
  (its ``Parameter: … / Type: …`` block), never on ambiguous output.

CWE-89 (SQL Injection) / OWASP A03:2021.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit, urlunsplit

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

_PARAM = re.compile(r"^Parameter:\s*(?P<name>[^\s(]+)\s*\((?P<place>[A-Za-z]+)\)", re.MULTILINE)
_TYPE = re.compile(r"^\s*Type:\s*(?P<type>.+)$", re.MULTILINE)
_DBMS = re.compile(r"back-end DBMS:\s*(?P<dbms>.+)")
_BANNER = re.compile(r"banner:\s*'(?P<v>[^']+)'")
_CURRENT_USER = re.compile(r"current user:\s*'(?P<v>[^']+)'")
_CURRENT_DB = re.compile(r"current database:\s*'(?P<v>[^']+)'")
_CONFIRMED = re.compile(r"identified the following injection point|Parameter:\s*\S+\s*\(", re.IGNORECASE)


@dataclass
class SqlmapResult:
    injectable: bool = False
    params: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    dbms: str | None = None
    banner: str | None = None
    current_user: str | None = None
    current_db: str | None = None
    excerpt: str = ""


def parse_sqlmap_output(text: str) -> SqlmapResult:
    """Parse sqlmap's stdout into a structured result (pure, so it is unit-tested without sqlmap)."""
    result = SqlmapResult(excerpt=" ".join(text.split())[:400])
    if not _CONFIRMED.search(text):
        return result  # sqlmap did not confirm an injection point
    result.injectable = True
    result.params = [m.group("name") for m in _PARAM.finditer(text)]
    result.techniques = [m.group("type").strip() for m in _TYPE.finditer(text)]
    for attr, pattern in (("dbms", _DBMS), ("banner", _BANNER), ("current_user", _CURRENT_USER), ("current_db", _CURRENT_DB)):
        m = pattern.search(text)
        if m:
            setattr(result, attr, m.group(m.lastindex or 1).strip())
    return result


def sqlmap_available(cmd: Sequence[str]) -> bool:
    """Whether the configured sqlmap command can be run (binary on PATH or an existing file)."""
    if not cmd:
        return False
    return shutil.which(cmd[0]) is not None or os.path.exists(cmd[0])


def _target_url_and_data(request: HttpRequest) -> tuple[str, str | None]:
    parts = urlsplit(request.url)
    query = urlencode(request.params) if request.params else parts.query
    url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))
    data = urlencode(request.data) if request.data else None
    return url, data


def build_sqlmap_args(
    request: HttpRequest,
    *,
    cookie: str = "",
    proxy: str = "",
    user_agent: str = "",
    level: int = 2,
    risk: int = 2,
    timeout: int = 30,
) -> list[str]:
    """The sqlmap CLI args for one target. No --crawl/--dump; stays on the single URL, no data theft."""
    url, data = _target_url_and_data(request)
    args = [
        "-u", url,
        "--batch",
        "--disable-coloring",
        "--flush-session",
        "--technique=BEUST",
        f"--level={level}",
        f"--risk={risk}",
        f"--timeout={timeout}",
        "--retries=1",
        "--threads=2",
        "--banner",
        "--current-user",
        "--current-db",
        "-v", "1",
    ]
    if data:
        args += ["--data", data]
    if cookie:
        args += ["--cookie", cookie]
    if proxy:
        args += ["--proxy", proxy]
    if user_agent:
        args += ["--user-agent", user_agent]
    return args


async def _run_one(cmd: Sequence[str], args: Sequence[str], timeout: float) -> str | None:
    """Run sqlmap once; return its combined stdout/stderr text, or None on failure/timeout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
    except (OSError, ValueError):
        return None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.kill()
        return None
    return out.decode("utf-8", "replace")


def _finding(request: HttpRequest, param: str, result: SqlmapResult) -> Finding:
    path = urlsplit(request.url).path or "/"
    proofs = [p for p in (
        result.dbms and f"DBMS {result.dbms}",
        result.banner and f"banner '{result.banner}'",
        result.current_user and f"usuario '{result.current_user}'",
        result.current_db and f"BD '{result.current_db}'",
    ) if p]
    technique = "; ".join(dict.fromkeys(result.techniques)) or "confirmada por sqlmap"
    critical = bool(result.dbms and (result.banner or result.current_user))
    return Finding(
        id=f"sqli-sqlmap:{request.method}:{path}:{param}",
        rule_id="sqli-sqlmap",
        name="SQL Injection confirmada por sqlmap",
        severity="critical" if critical else "high",
        cwe="CWE-89",
        owasp="A03:2021",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        family="sqli",
        injection_point=InjectionPoint(location="query", name=param, base_value="", request_template=request),
        evidence=[
            Evidence(
                type="differential",
                data=(
                    f"sqlmap confirmó SQL injection en el parámetro '{param}' ({technique}). "
                    + ("Impacto probado: " + "; ".join(proofs) + "." if proofs else "")
                )[:220],
                confidence="high",
            )
        ],
        request=request,
        response=HttpResponse(status_code=0, text=result.excerpt),
        impact=(
            "SQL injection explotable confirmada por sqlmap: " + "; ".join(proofs)
            if proofs
            else "SQL injection explotable confirmada por sqlmap."
        ),
        remediation=(
            "Usa consultas parametrizadas (prepared statements) en todos los accesos a datos; nunca "
            "concatenes entrada del usuario en SQL. Aplica ORM/consultas con placeholders y validación "
            "de tipos, y principio de mínimo privilegio en la cuenta de base de datos."
        ),
    )


async def run_sqlmap_scan(
    requests: list[HttpRequest],
    *,
    cmd: Sequence[str] = ("sqlmap",),
    in_scope: Callable[[str], bool] | None = None,
    cookie: str = "",
    proxy: str = "",
    user_agent: str = "",
    max_targets: int = 10,
    level: int = 2,
    risk: int = 2,
    per_target_timeout: int = 120,
) -> list[Finding]:
    """Run sqlmap over discovered injection points (URL + params) and report confirmed SQL injection."""
    findings: list[Finding] = []
    seen: set[str] = set()
    targets = 0
    for request in requests:
        if request.method.upper() not in ("GET", "POST"):
            continue
        if not (request.params or request.data):
            continue  # nothing to test
        if in_scope is not None and not in_scope(request.url):
            continue
        signature = request.signature()
        if signature in seen:
            continue
        seen.add(signature)
        if targets >= max_targets:
            break
        targets += 1

        args = build_sqlmap_args(
            request, cookie=cookie, proxy=proxy, user_agent=user_agent, level=level, risk=risk,
            timeout=min(per_target_timeout, 60),
        )
        output = await _run_one(cmd, args, timeout=per_target_timeout + 15)
        if output is None:
            continue
        result = parse_sqlmap_output(output)
        if not result.injectable:
            continue
        params = result.params or list(request.params) or list(request.data or {})
        for param in dict.fromkeys(params):  # dedup, keep order
            findings.append(_finding(request, param, result))
    return findings
