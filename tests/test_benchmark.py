"""Accuracy benchmark: measure precision / recall / F1 against a labeled target.

Runs a real crawl + scan over a set of vulnerable endpoints AND realistic decoys
(safe endpoints that look injectable), then scores active findings against the
ground-truth labels. This is the honest, "not the exam it already knows" metric:
the decoys are the false-positive traps. Run `pytest -s tests/test_benchmark.py`
to print the full scorecard.
"""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit

from dastcore.config import RateLimitConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.discovery.crawler_http import HttpCrawler
from dastcore.engine.oast import LocalOastServer
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner
from tests.targets.benchmark.app import EXPECTED

# Families that come from *active* injection testing (what the benchmark scores).
# Passive/info findings (headers, fingerprint) are deterministic, not FP-prone, and
# out of scope for a precision benchmark.
_ACTIVE_FAMILIES = {
    "sqli",
    "xss",
    "cmdi",
    "xpath",
    "ldap",
    "lfi",
    "open_redirect",
    "secret",
    "nosqli",
    "ssti",
    "xxe",
    "ssrf",
    "crlf",
    "host_header",
    "rce",
    "cors",
    "csv_injection",
    "xml_injection",
}


async def test_accuracy_benchmark(benchmark_url: str) -> None:
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    rate = RateLimitConfig(requests_per_second=100, max_concurrency=20)
    oast = LocalOastServer()
    await oast.start()
    try:
        async with HttpClient(scope, rate_limit=rate) as client:
            discovered = await HttpCrawler(client).crawl(f"{benchmark_url}/")
            findings = await Scanner(client, load_rules(), oast=oast, oob_poll_attempts=6).scan(discovered)
    finally:
        await oast.stop()

    detected: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        if finding.family in _ACTIVE_FAMILIES:
            detected[urlsplit(finding.request.url).path].add(finding.family)

    tp = fn = 0
    false_positives: list[tuple[str, list[str]]] = []
    false_negatives: list[str] = []
    for path, expected in EXPECTED.items():
        families = detected.get(path, set())
        if expected is not None:
            if expected in families:
                tp += 1
            else:
                fn += 1
                false_negatives.append(f"{path} (expected {expected})")
        elif families:
            false_positives.append((path, sorted(families)))

    fp = len(false_positives)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    positives = sum(1 for v in EXPECTED.values() if v is not None)
    decoys = len(EXPECTED) - positives

    print("\n" + "=" * 56)
    print(f"  dastcore accuracy benchmark  ({positives} vulns, {decoys} decoys)")
    print("=" * 56)
    print(f"  TP={tp}  FP={fp}  FN={fn}")
    print(f"  precision={precision:.3f}  recall={recall:.3f}  F1={f1:.3f}")
    if false_positives:
        print("  FALSE POSITIVES:")
        for path, fams in false_positives:
            print(f"    - {path}: {', '.join(fams)}")
    if false_negatives:
        print("  FALSE NEGATIVES:")
        for miss in false_negatives:
            print(f"    - {miss}")
    print("=" * 56)

    # Regression gate: no false positives, and near-perfect recall.
    assert false_positives == [], f"false positives on decoys: {false_positives}"
    assert recall >= 0.9, f"recall {recall:.2f} too low; missed: {false_negatives}"


async def test_intensity_keeps_zero_false_positives(benchmark_url: str) -> None:
    """The adaptive-planner intensity boost must not cost precision. Run the same benchmark with EVERY
    active family marked a priority (so every rule's intensive_payloads fire and WAF evasion is on), and
    require the decoys to stay clean. This is the honest guard for the feature's core promise: more
    payloads, never more false positives — because every one is still confirmed by the rule's oracle."""
    scope = ScopeConfig(allow_domains=["127.0.0.1"])
    rate = RateLimitConfig(requests_per_second=100, max_concurrency=20)
    oast = LocalOastServer()
    await oast.start()
    try:
        async with HttpClient(scope, rate_limit=rate) as client:
            discovered = await HttpCrawler(client).crawl(f"{benchmark_url}/")
            scanner = Scanner(
                client, load_rules(), oast=oast, oob_poll_attempts=6,
                priority_families=tuple(sorted(_ACTIVE_FAMILIES)),  # intensity ON for all families
            )
            findings = await scanner.scan(discovered)
    finally:
        await oast.stop()

    detected: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        if finding.family in _ACTIVE_FAMILIES:
            detected[urlsplit(finding.request.url).path].add(finding.family)

    false_positives = [
        (path, sorted(detected[path])) for path, expected in EXPECTED.items()
        if expected is None and detected.get(path)
    ]
    tp = sum(1 for path, expected in EXPECTED.items() if expected is not None and expected in detected.get(path, set()))
    positives = sum(1 for v in EXPECTED.values() if v is not None)
    recall = tp / positives if positives else 1.0

    assert false_positives == [], f"intensity introduced false positives on decoys: {false_positives}"
    assert recall >= 0.9, f"intensity dropped recall to {recall:.2f}"  # intensity must never lose coverage
