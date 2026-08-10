"""Refresh dastcore/vulndb/advisories.yaml from the NVD API 2.0.

Network-facing and run by hand (or in a scheduled maintenance job), NOT at scan time:
the scanner only ever reads the bundled YAML, so scans stay offline and deterministic.
The CVE→advisory translation lives in dastcore/vulndb/nvd.py and is unit-tested; this
script is just the fetch + merge around it.

Usage:
  python scripts/sync_nvd.py --dry-run                # show what would change (default)
  python scripts/sync_nvd.py --write                  # merge into advisories.yaml
  NVD_API_KEY=... python scripts/sync_nvd.py --write   # higher rate limit with a key

An NVD API key (free) raises the rate limit; without one the script self-throttles.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dastcore.vulndb.nvd import DEFAULT_PRODUCT_MAP, advisories_from_cve, merge_advisories  # noqa: E402

_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_ADVISORIES = Path(__file__).resolve().parent.parent / "dastcore" / "vulndb" / "advisories.yaml"


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def filter_by_severity(advisories: list[dict], min_severity: str) -> list[dict]:
    """Keep advisories at or above `min_severity` (pure; keeps a weekly PR small)."""
    floor = _SEVERITY_ORDER.get(min_severity, 0)
    return [a for a in advisories if _SEVERITY_ORDER.get(str(a.get("severity", "")).lower(), 0) >= floor]


def _recency_params(since_days: int) -> dict[str, str]:
    """NVD requires both bounds and a window <= 120 days; return lastMod{Start,End}Date."""
    if since_days <= 0:
        return {}
    end = dt.datetime.now(dt.UTC)
    start = end - dt.timedelta(days=min(since_days, 120))
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    return {"lastModStartDate": start.strftime(fmt), "lastModEndDate": end.strftime(fmt)}


def _fetch(cpe: str, api_key: str | None, start: int, per_page: int, extra: dict[str, str]) -> dict:
    params = {"virtualMatchString": cpe, "resultsPerPage": per_page, "startIndex": start, **extra}
    request = urllib.request.Request(
        f"{_API}?{urllib.parse.urlencode(params)}", headers={"User-Agent": "dastcore-nvd-sync"}
    )
    if api_key:
        request.add_header("apiKey", api_key)
    for attempt in range(5):  # NVD returns 403/503 under load; back off and retry
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429, 503) and attempt < 4:
                time.sleep(10 * (attempt + 1))
                continue
            raise
    raise RuntimeError("NVD API kept failing after retries")


def _cpe_targets() -> list[str]:
    return sorted({key for key in DEFAULT_PRODUCT_MAP if ":" in key})


def sync(*, api_key: str | None, per_page: int, max_per_product: int, since_days: int = 0) -> list[dict]:
    delay = 0.7 if api_key else 6.5  # NVD: ~50 req/30s with a key, ~5 without
    recency = _recency_params(since_days)
    collected: list[dict] = []
    for target in _cpe_targets():
        cpe = f"cpe:2.3:a:{target}"
        start, total = 0, None
        while True:
            data = _fetch(cpe, api_key, start, per_page, recency)
            total = data.get("totalResults", 0) if total is None else total
            for item in data.get("vulnerabilities", []):
                collected.extend(advisories_from_cve(item.get("cve", {})))
            fetched = start + data.get("resultsPerPage", 0)
            print(f"  {target}: {min(fetched, total)}/{total}", file=sys.stderr)
            if fetched >= total or (max_per_product and fetched >= max_per_product):
                break
            start = fetched
            time.sleep(delay)
    return collected


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync advisories.yaml from the NVD API 2.0.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true", default=True, help="show changes without writing (default)")
    group.add_argument("--write", dest="dry_run", action="store_false", help="merge results into advisories.yaml")
    parser.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"), help="NVD API key (or $NVD_API_KEY)")
    parser.add_argument("--per-page", type=int, default=2000, help="NVD resultsPerPage (max 2000)")
    parser.add_argument("--max-per-product", type=int, default=0, help="cap CVEs fetched per product (0 = all)")
    parser.add_argument("--since-days", type=int, default=0, help="only CVEs modified in the last N days (<=120)")
    parser.add_argument(
        "--min-severity",
        choices=list(_SEVERITY_ORDER),
        default="info",
        help="drop advisories below this severity (keeps the diff small)",
    )
    args = parser.parse_args()

    existing = (yaml.safe_load(_ADVISORIES.read_text(encoding="utf-8")) or {}).get("advisories", [])
    incoming = filter_by_severity(
        sync(
            api_key=args.api_key,
            per_page=args.per_page,
            max_per_product=args.max_per_product,
            since_days=args.since_days,
        ),
        args.min_severity,
    )
    merged = merge_advisories(existing, incoming)
    added = len(merged) - len(existing)

    print(f"\nexisting: {len(existing)}  fetched: {len(incoming)}  merged total: {len(merged)}  (+{added} new)")
    if args.dry_run:
        print("dry run — nothing written. Re-run with --write to update advisories.yaml.")
        return 0

    header = _ADVISORIES.read_text(encoding="utf-8").split("advisories:", 1)[0].rstrip() + "\n\n"
    body = yaml.safe_dump({"advisories": merged}, sort_keys=False, allow_unicode=True, width=100)
    _ADVISORIES.write_text(header + body, encoding="utf-8")
    print(f"wrote {len(merged)} advisories to {_ADVISORIES}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
