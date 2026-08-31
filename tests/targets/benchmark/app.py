"""Re-export the accuracy-benchmark target from the shipped package (kept here for the test fixtures)."""

from dastcore.benchmark.app import EXPECTED, create_app

__all__ = ["EXPECTED", "create_app"]
