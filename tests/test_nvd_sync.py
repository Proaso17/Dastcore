"""NVD → advisory translation (pure, no network) and the merge logic. Also asserts that
the `affected` spec the sync emits is understood by the runtime version matcher."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from dastcore.detectors.version_cve import satisfies
from dastcore.vulndb.nvd import advisories_from_cve, merge_advisories

# Load the standalone sync script (scripts/ isn't a package) to test its pure helpers.
_spec = importlib.util.spec_from_file_location(
    "sync_nvd", Path(__file__).resolve().parent.parent / "scripts" / "sync_nvd.py"
)
sync_nvd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sync_nvd)


def _cve(cpe_match: dict, *, cve_id: str = "CVE-2021-41773", cwe: str = "CWE-22") -> dict:
    return {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": "Apache HTTP Server path traversal and RCE."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": cwe}]}],
        "configurations": [{"nodes": [{"cpeMatch": [cpe_match]}]}],
    }


def test_pinned_version_becomes_equality_constraint() -> None:
    cve = _cve({"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"})
    advisories = advisories_from_cve(cve)
    assert len(advisories) == 1
    adv = advisories[0]
    assert adv["product"] == "apache" and adv["affected"] == "==2.4.49"
    assert adv["severity"] == "high" and adv["cwe"] == "CWE-22" and adv["cvss"] == "7.5"
    assert adv["source"] == "nvd"


def test_version_range_becomes_bounds() -> None:
    cve = _cve(
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.4.49",
            "versionEndExcluding": "2.4.51",
        }
    )
    adv = advisories_from_cve(cve)[0]
    assert adv["affected"] == ">=2.4.49,<2.4.51" and adv["fixed"] == "2.4.51"


def test_emitted_spec_is_usable_by_the_runtime_matcher() -> None:
    # the whole point: what the sync writes must be understood by version_cve.satisfies
    cve = _cve(
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.4.49",
            "versionEndExcluding": "2.4.51",
        }
    )
    spec = advisories_from_cve(cve)[0]["affected"]
    assert satisfies("2.4.50", spec) and not satisfies("2.4.51", spec)


def test_unmapped_product_is_skipped() -> None:
    cve = _cve({"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*"})
    assert advisories_from_cve(cve) == []


def test_non_vulnerable_match_is_skipped() -> None:
    cve = _cve({"vulnerable": False, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"})
    assert advisories_from_cve(cve) == []


def test_cvss_v2_fallback() -> None:
    cve = _cve({"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"})
    del cve["metrics"]["cvssMetricV31"]
    cve["metrics"]["cvssMetricV2"] = [{"baseSeverity": "MEDIUM", "cvssData": {"baseScore": 5.0}}]
    assert advisories_from_cve(cve)[0]["severity"] == "medium"


def test_merge_dedupes_and_keeps_existing() -> None:
    existing = [{"product": "apache", "cve": "CVE-1", "affected": "==1.0", "severity": "high"}]
    incoming = [
        {"product": "apache", "cve": "CVE-1", "affected": "==1.0", "severity": "low", "source": "nvd"},  # dup
        {"product": "nginx", "cve": "CVE-2", "affected": "<1.21.0", "severity": "high", "source": "nvd"},  # new
    ]
    merged = merge_advisories(existing, incoming)
    assert len(merged) == 2
    apache = next(a for a in merged if a["product"] == "apache")
    assert apache["severity"] == "high" and "source" not in apache  # existing (curated) won


def test_filter_by_severity_keeps_the_diff_small() -> None:
    advisories = [
        {"cve": "A", "severity": "low"},
        {"cve": "B", "severity": "high"},
        {"cve": "C", "severity": "critical"},
        {"cve": "D", "severity": "medium"},
    ]
    kept = {a["cve"] for a in sync_nvd.filter_by_severity(advisories, "high")}
    assert kept == {"B", "C"}


def test_recency_params_are_bounded_to_120_days() -> None:
    params = sync_nvd._recency_params(365)
    assert "lastModStartDate" in params and "lastModEndDate" in params
    assert sync_nvd._recency_params(0) == {}
