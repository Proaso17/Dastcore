"""Generate docs/demo.svg — a terminal-style SVG snapshot of a `dastcore demo` run.

Runs the bundled demo scan, renders the findings table + summary panel to a
recording rich Console, and exports it to SVG (an honest 'screenshot', no faking).

    python docs/gen_demo_svg.py
"""

from __future__ import annotations

import asyncio
import collections
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dastcore.cli import _run_demo_scan
from dastcore.demo.app import start_demo_target

_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def main() -> None:
    server, base_url = start_demo_target()
    try:
        findings = asyncio.run(_run_demo_scan(base_url))
    finally:
        server.shutdown()

    console = Console(record=True, width=96)
    console.print("[bold]$ dastcore demo[/bold]\n")

    table = Table(title=f"{len(findings)} hallazgos — web + IA (objetivo vulnerable incluido)")
    table.add_column("Severidad")
    table.add_column("Categoría")
    table.add_column("Hallazgo")
    for finding in sorted(findings, key=lambda f: f.severity, reverse=True)[:14]:
        style = _SEVERITY_STYLE.get(finding.severity, "")
        table.add_row(f"[{style}]{finding.severity}[/{style}]", finding.owasp.split(" ")[0], finding.name)
    console.print(table)

    counts = collections.Counter(f.severity for f in findings)
    parts = [
        f"[{_SEVERITY_STYLE[s]}]{s}: {counts.get(s, 0)}[/{_SEVERITY_STYLE[s]}]"
        for s in ("high", "medium", "low")
        if counts.get(s)
    ]
    console.print(
        Panel("  ".join(parts) + f"\n\nTotal: [bold]{len(findings)}[/bold]", title="Resumen", border_style="cyan")
    )

    out = Path(__file__).resolve().parent / "demo.svg"
    console.save_svg(str(out), title="dastcore demo")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
