"""Pure NVD → advisory translation (no network here — see scripts/sync_nvd.py for the fetch).

The NVD API 2.0 returns CVEs with CPE match configurations that encode affected version
ranges. This module turns one CVE object into zero or more advisory entries in dastcore's
own schema (the same shape as vulndb/advisories.yaml), so the sync script can fetch and
this can be unit-tested against fixtures.
"""

from __future__ import annotations

from typing import Any

# NVD CPE `vendor:product` -> dastcore product key (what the fingerprinter emits).
DEFAULT_PRODUCT_MAP: dict[str, str] = {
    "apache:http_server": "apache",
    "nginx:nginx": "nginx",
    "f5:nginx": "nginx",
    "openssl:openssl": "openssl",
    "php:php": "php",
    "jquery:jquery": "jquery",
    "openjsf:jquery": "jquery",
    "getbootstrap:bootstrap": "bootstrap",
    "bootstrap:bootstrap": "bootstrap",
    "wordpress:wordpress": "wordpress",
}


def _cpe_parts(criteria: str) -> tuple[str, str, str] | None:
    """Return (vendor, product, version) from a `cpe:2.3:a:vendor:product:version:…` string."""
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return None
    return parts[3], parts[4], parts[5]


def _match_to_spec(match: dict[str, Any]) -> str | None:
    """Turn a cpeMatch's version bounds into dastcore's comma-separated constraint spec."""
    clauses: list[str] = []
    if v := match.get("versionStartIncluding"):
        clauses.append(f">={v}")
    if v := match.get("versionStartExcluding"):
        clauses.append(f">{v}")
    if v := match.get("versionEndIncluding"):
        clauses.append(f"<={v}")
    if v := match.get("versionEndExcluding"):
        clauses.append(f"<{v}")
    if clauses:
        return ",".join(clauses)
    parsed = _cpe_parts(match.get("criteria", ""))
    if parsed and parsed[2] not in ("*", "-", ""):
        return f"=={parsed[2]}"  # a single pinned vulnerable version
    return None


def _severity_and_cvss(cve: dict[str, Any]) -> tuple[str, str]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            return str(data.get("baseSeverity", "medium")).lower(), str(data.get("baseScore", ""))
    v2 = metrics.get("cvssMetricV2")
    if v2:
        return str(v2[0].get("baseSeverity", "medium")).lower(), str(v2[0].get("cvssData", {}).get("baseScore", ""))
    return "medium", ""


def _first_cwe(cve: dict[str, Any]) -> str:
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-") and value[4:].isdigit():
                return value
    return "CWE-1035"  # "Using Components with Known Vulnerabilities" umbrella


def advisories_from_cve(cve: dict[str, Any], product_map: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Translate one NVD CVE object into dastcore advisory entries (deduped by product+range)."""
    product_map = product_map or DEFAULT_PRODUCT_MAP
    cve_id = cve.get("id", "")
    title = next(
        (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        cve_id,
    )
    severity, cvss = _severity_and_cvss(cve)
    cwe = _first_cwe(cve)

    entries: dict[tuple[str, str], dict[str, Any]] = {}
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parsed = _cpe_parts(match.get("criteria", ""))
                if parsed is None:
                    continue
                vendor, product, _ = parsed
                mapped = product_map.get(f"{vendor}:{product}") or product_map.get(product)
                if not mapped:
                    continue
                spec = _match_to_spec(match)
                if spec is None:
                    continue
                entries.setdefault(
                    (mapped, spec),
                    {
                        "product": mapped,
                        "cve": cve_id,
                        "title": title[:120].strip(),
                        "affected": spec,
                        "fixed": match.get("versionEndExcluding") or "the latest release",
                        "severity": severity,
                        "cwe": cwe,
                        "cvss": cvss,
                        "source": "nvd",
                    },
                )
    return list(entries.values())


def _advisory_key(advisory: dict[str, Any]) -> tuple[str, str, str]:
    return (advisory.get("product", ""), advisory.get("cve", ""), advisory.get("affected", ""))


def merge_advisories(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge synced advisories into the current set, keeping curated entries and de-duping
    by (product, cve, affected). Existing entries win on conflict (never clobber a hand-tuned
    advisory)."""
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for advisory in existing:
        merged[_advisory_key(advisory)] = advisory
    added = 0
    for advisory in incoming:
        key = _advisory_key(advisory)
        if key not in merged:
            merged[key] = advisory
            added += 1
    ordered = sorted(merged.values(), key=lambda a: (a.get("product", ""), a.get("cve", ""), a.get("affected", "")))
    return ordered
