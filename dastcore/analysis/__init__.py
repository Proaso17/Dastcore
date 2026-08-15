"""Post-confirmation analysis: enrich already-confirmed findings with proof of impact.

This package never *detects* — it runs only over findings an oracle already confirmed,
so it cannot create false positives. If an extraction fails, the finding stands unchanged.
"""

from dastcore.analysis.impact import prove_findings_impact

__all__ = ["prove_findings_impact"]
