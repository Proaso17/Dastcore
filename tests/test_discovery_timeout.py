"""The discovery stages that run inline (subdomain sweep, historical mining) are bounded by a wall-clock
cap, so a pathological target — a wildcard/ISP-hijack domain that answers every name, a stalled archive —
degrades to partial coverage instead of hanging the whole scan for hours. _bounded_discovery is that cap."""

from __future__ import annotations

import asyncio

import pytest

from dastcore.cli import _bounded_discovery
from dastcore.core.http_client import BudgetExceededError


async def test_returns_result_when_it_finishes_in_time() -> None:
    async def quick() -> list[int]:
        return [1, 2, 3]

    assert await _bounded_discovery(quick(), timeout=5.0, label="x", default=[]) == [1, 2, 3]


async def test_times_out_and_returns_default() -> None:
    async def hangs() -> list[int]:
        await asyncio.sleep(10)  # a stalled stage that never returns
        return [99]

    result = await _bounded_discovery(hangs(), timeout=0.05, label="subdominios", default=["fallback"])
    assert result == ["fallback"]  # abandoned at the cap, scan continues with the default


async def test_error_degrades_to_default() -> None:
    async def boom() -> list[int]:
        raise RuntimeError("source down")

    assert await _bounded_discovery(boom(), timeout=5.0, label="histórico", default=[]) == []


async def test_budget_exceeded_still_propagates() -> None:
    # The budget soft-stop must bubble up (it ends the scan cleanly) rather than being swallowed as a
    # failed discovery stage.
    async def over_budget() -> list[int]:
        raise BudgetExceededError("time budget spent")

    with pytest.raises(BudgetExceededError):
        await _bounded_discovery(over_budget(), timeout=5.0, label="subdominios", default=[])
