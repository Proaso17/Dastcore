"""External recon / attack-surface discovery.

Turns a bug-bounty scope (with wildcards) into a set of live, in-scope assets, wrapping ecosystem
tools in replay-testable adapters. Every asset passes ``ScopeChecker`` before it is stored.
"""

from dastcore.recon.adapters import default_adapters
from dastcore.recon.models import Asset, ReconOptions
from dastcore.recon.runner import run_recon
from dastcore.recon.store import AssetStore

__all__ = ["Asset", "AssetStore", "ReconOptions", "default_adapters", "run_recon"]
