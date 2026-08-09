"""Dogfooding gate: run the real `dastcore` CLI against the bundled vulnerable demo
target and fail if it stops finding what it should.

A security scanner's worst regression is silently detecting *less*. Unit tests import
the engine internals; this instead drives the shipped CLI end to end (crawl → active
+ passive scan → SARIF → exit code), so packaging, output and exit-code regressions are
caught too. Wired into CI as its own job.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from dastcore.demo.app import start_demo_target

# The demo target plants these high-severity, deterministic web vulns.
REQUIRED_RULES = {"sqli-injection", "xss-reflected"}
FAIL_ON = "high"
EXIT_FINDINGS_OVER_THRESHOLD = 2  # dastcore's exit code when --fail-on trips


def main() -> int:
    server, base_url = start_demo_target()
    sarif_path = Path(tempfile.mkdtemp(prefix="dastcore-selfscan-")) / "self_scan.sarif"
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "dastcore",
                "scan",
                base_url,
                "--i-have-authorization",
                "--quiet",
                "--fail-on",
                FAIL_ON,
                "--format",
                "sarif",
                "--output",
                str(sarif_path),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
    finally:
        server.shutdown()

    if proc.stdout.strip():
        print(proc.stdout[-2000:])
    if proc.stderr.strip():
        print(proc.stderr[-2000:], file=sys.stderr)

    # The planted high-severity vulns must be found, which trips --fail-on high (exit 2).
    # Exit 0 = found nothing over the bar (detection regressed); exit 1 = the CLI errored.
    if proc.returncode != EXIT_FINDINGS_OVER_THRESHOLD:
        print(
            f"SELF-SCAN FAILED: expected exit {EXIT_FINDINGS_OVER_THRESHOLD} "
            f"(planted high-severity vulns detected), got {proc.returncode}."
        )
        return 1

    if not sarif_path.exists():
        print("SELF-SCAN FAILED: the CLI did not write the SARIF report.")
        return 1

    doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    rule_ids = {result["ruleId"] for result in doc["runs"][0]["results"]}
    missing = REQUIRED_RULES - rule_ids
    if missing:
        print(f"SELF-SCAN FAILED: expected findings missing: {sorted(missing)}; got {sorted(rule_ids)}.")
        return 1

    print(f"SELF-SCAN OK: {len(rule_ids)} rule(s) fired, including {sorted(REQUIRED_RULES)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
