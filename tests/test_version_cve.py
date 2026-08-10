"""Known-vulnerable-version detection: the version-range matcher, component extraction
from headers/body, and the advisory lookup (including the not-affected boundary)."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.version_cve import (
    check_known_vulnerable_versions,
    extract_components,
    load_advisories,
    satisfies,
)

_REQ = HttpRequest(method="GET", url="http://target.test/")


def _resp(headers: dict | None = None, text: str = "") -> HttpResponse:
    return HttpResponse(status_code=200, headers=headers or {}, text=text)


# --- version range matcher --------------------------------------------------------------


def test_satisfies_operators() -> None:
    assert satisfies("2.4.49", "==2.4.49")
    assert satisfies("2.4.50", ">=2.4.49,<2.4.51")
    assert not satisfies("2.4.51", ">=2.4.49,<2.4.51")
    assert satisfies("3.3.1", "<3.5.0")
    assert not satisfies("3.5.1", "<3.5.0")


def test_satisfies_handles_openssl_letter_suffix() -> None:
    assert satisfies("1.0.1f", ">=1.0.1,<1.0.1g")
    assert not satisfies("1.0.1g", ">=1.0.1,<1.0.1g")


def test_advisory_db_loads() -> None:
    advisories = load_advisories()
    assert advisories and all({"product", "cve", "affected", "severity", "cwe"} <= a.keys() for a in advisories)


# --- component extraction ---------------------------------------------------------------


def test_extract_from_server_header() -> None:
    comps = extract_components(_resp(headers={"Server": "Apache/2.4.49 (Unix) OpenSSL/1.0.1f"}))
    by_product = {c.product: c.version for c in comps}
    assert by_product["apache"] == "2.4.49"
    assert by_product["openssl"] == "1.0.1f"


def test_extract_client_side_library_versions() -> None:
    body = '<script src="/static/jquery-3.4.1.min.js"></script><link href="bootstrap-4.1.3.min.css">'
    by_product = {c.product: c.version for c in extract_components(_resp(text=body))}
    assert by_product["jquery"] == "3.4.1"
    assert by_product["bootstrap"] == "4.1.3"


# --- end-to-end lookup ------------------------------------------------------------------


def test_flags_vulnerable_apache() -> None:
    findings = check_known_vulnerable_versions(_REQ, _resp(headers={"Server": "Apache/2.4.49 (Unix)"}))
    cves = {f.id.rsplit(":", 1)[-1] for f in findings}
    assert "CVE-2021-41773" in cves and "CVE-2021-42013" in cves
    assert all(f.rule_id == "known-vulnerable-version" and f.family == "vulnerable_component" for f in findings)
    assert all(f.evidence[0].confidence == "medium" for f in findings)  # version-banner based


def test_patched_apache_is_not_flagged() -> None:
    assert check_known_vulnerable_versions(_REQ, _resp(headers={"Server": "Apache/2.4.58 (Unix)"})) == []


def test_flags_vulnerable_jquery_but_not_patched() -> None:
    vuln = check_known_vulnerable_versions(_REQ, _resp(text='<script src="/js/jquery-3.3.1.min.js"></script>'))
    assert any("CVE-2020-11022" in f.id for f in vuln)
    safe = check_known_vulnerable_versions(_REQ, _resp(text='<script src="/js/jquery-3.5.1.min.js"></script>'))
    assert safe == []
