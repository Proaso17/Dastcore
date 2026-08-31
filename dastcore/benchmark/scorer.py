"""Precision / recall / F1 scoring for the accuracy benchmark.

Scores a set of *active* findings against the labeled target's ground truth (``EXPECTED``: path -> the
one vulnerable family, or ``None`` for a decoy that must stay clean). Decoys are the false-positive
traps, so this is the honest metric — precision measures "does it stay quiet on safe-but-injectable-
looking endpoints", recall measures "does it catch the planted bugs". Passive/info findings are
excluded: they are deterministic and not false-positive-prone, so they do not belong in a precision
benchmark.

The same scorer scores an *external* tool's findings (``score_external``), so a user can drop a ZAP /
Nuclei export beside dastcore's own run and compare on identical ground truth.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from dastcore.core.models import Finding

# Families produced by *active* injection testing — the ones a precision benchmark scores.
ACTIVE_FAMILIES: frozenset[str] = frozenset({
    "sqli", "xss", "cmdi", "xpath", "ldap", "lfi", "open_redirect", "secret", "nosqli", "ssti",
    "xxe", "ssrf", "crlf", "host_header", "rce", "cors", "csv_injection", "xml_injection",
})


@dataclass
class BenchmarkResult:
    """A scored run: the confusion counts, the derived metrics, and the exact mistakes."""

    label: str
    tp: int
    fp: int
    fn: int
    positives: int
    decoys: int
    false_positives: list[tuple[str, list[str]]] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {
            "label": self.label, "tp": self.tp, "fp": self.fp, "fn": self.fn,
            "positives": self.positives, "decoys": self.decoys,
            "precision": round(self.precision, 3), "recall": round(self.recall, 3), "f1": round(self.f1, 3),
            "false_positives": [{"path": p, "families": f} for p, f in self.false_positives],
            "false_negatives": self.false_negatives,
        }

    def scorecard(self) -> str:
        lines = [
            "=" * 56,
            f"  dastcore accuracy benchmark — {self.label}  ({self.positives} vulns, {self.decoys} decoys)",
            "=" * 56,
            f"  TP={self.tp}  FP={self.fp}  FN={self.fn}",
            f"  precision={self.precision:.3f}  recall={self.recall:.3f}  F1={self.f1:.3f}",
        ]
        if self.false_positives:
            lines.append("  FALSE POSITIVES:")
            lines += [f"    - {p}: {', '.join(fams)}" for p, fams in self.false_positives]
        if self.false_negatives:
            lines.append("  FALSE NEGATIVES:")
            lines += [f"    - {miss}" for miss in self.false_negatives]
        lines.append("=" * 56)
        return "\n".join(lines)


def markdown_table(results: list[BenchmarkResult]) -> str:
    """A shareable Markdown scorecard (one row per tool) — for a README or a comparison."""
    head = "| Tool | Vulns | Decoys | TP | FP | FN | Precision | Recall | F1 |\n"
    head += "|---|---:|---:|---:|---:|---:|---:|---:|---:|\n"
    rows = "".join(
        f"| {r.label} | {r.positives} | {r.decoys} | {r.tp} | {r.fp} | {r.fn} | "
        f"{r.precision:.3f} | {r.recall:.3f} | {r.f1:.3f} |\n"
        for r in results
    )
    return head + rows


def detected_from_findings(findings: list[Finding]) -> dict[str, set[str]]:
    """path -> set of active families detected there (passive/info findings ignored)."""
    detected: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        if finding.family in ACTIVE_FAMILIES:
            detected[urlsplit(finding.request.url).path].add(finding.family)
    return detected


def score(detected: dict[str, set[str]], expected: dict[str, str | None], *, label: str = "dastcore") -> BenchmarkResult:
    """Score detected families-per-path against the ground truth."""
    tp = fn = 0
    false_positives: list[tuple[str, list[str]]] = []
    false_negatives: list[str] = []
    for path, want in expected.items():
        families = detected.get(path, set())
        if want is not None:
            if want in families:
                tp += 1
            else:
                fn += 1
                false_negatives.append(f"{path} (expected {want})")
        elif families:
            false_positives.append((path, sorted(families)))
    positives = sum(1 for v in expected.values() if v is not None)
    return BenchmarkResult(
        label=label, tp=tp, fp=len(false_positives), fn=fn,
        positives=positives, decoys=len(expected) - positives,
        false_positives=false_positives, false_negatives=false_negatives,
    )


def _detected_from_external(data: list) -> dict[str, set[str]]:
    """Accept either a dastcore ``Finding[]`` JSON or a simple ``[{"path","family"}]`` list."""
    if data and isinstance(data[0], dict) and "request" in data[0]:
        return detected_from_findings([Finding.model_validate(item) for item in data])
    detected: dict[str, set[str]] = defaultdict(set)
    for item in data:
        path, family = item.get("path"), item.get("family")
        if path and family:
            detected[path].add(family)
    return detected


def score_external(path: str, expected: dict[str, str | None], *, label: str = "") -> BenchmarkResult:
    """Score another tool's findings file against the same ground truth (for a fair comparison)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return score(_detected_from_external(data), expected, label=label or Path(path).stem)
