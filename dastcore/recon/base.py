"""Common recon adapter interface.

An adapter wraps one external tool (or OSINT source). It separates a **pure parser** (``parse`` —
tested against recorded fixtures, no network) from **execution** (``_invoke`` — runs the tool). The
public ``collect`` ties them together and degrades gracefully: replay a recorded output when provided,
run the real tool when it's installed, or return nothing (with the caller free to warn) when it isn't.

Adding a source = one ``Adapter`` subclass + a fixture; the orchestrator never changes.
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod

from dastcore.recon.models import Asset, ReconOptions


class Adapter(ABC):
    name: str = ""
    stage: str = "subdomain"  # "subdomain" (per-seed enumeration) | "probe" (over discovered hosts)
    passive: bool = True  # False = touches the target (skipped in passive profile / no-scan programs)
    binary: str | None = None  # the CLI tool to look for; None = pure HTTP/OSINT, always available

    def available(self) -> bool:
        return self.binary is None or shutil.which(self.binary) is not None

    @abstractmethod
    def parse(self, raw: str) -> list[Asset]:
        """Parse one tool invocation's raw output into assets. Pure — no I/O."""

    async def _invoke(self, targets: list[str], opts: ReconOptions) -> list[Asset]:
        """Run the real tool over ``targets`` and parse it. Overridden per adapter."""
        return []

    async def collect(self, targets: list[str], opts: ReconOptions) -> list[Asset]:
        if self.name in opts.replay:  # test / recorded mode — never touches the network
            return self.parse(opts.replay[self.name])
        if not targets or not self.available():
            return []  # graceful degrade: tool missing -> skip, don't crash the pipeline
        try:
            return await self._invoke(targets, opts)
        except (TimeoutError, OSError, ValueError):
            return []
