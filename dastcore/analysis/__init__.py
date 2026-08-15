"""Post-confirmation analysis: enrich already-confirmed findings with proof of impact.

This package never *detects* — it runs only over findings an oracle already confirmed,
so it cannot create false positives. If an extraction fails, the finding stands unchanged.
"""

from dastcore.analysis.chains import AttackChain, ChainLeg, correlate_chains
from dastcore.analysis.impact import prove_findings_impact

__all__ = ["AttackChain", "ChainLeg", "correlate_chains", "prove_findings_impact"]
