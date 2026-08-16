"""Bug-bounty layer: the authorized *program* a hunt operates under.

A ``Program`` captures the scope (wildcards / exact domains / CIDR + out-of-scope), the rate/behaviour
limits the program imposes, and the recon seeds. It maps cleanly onto the existing ``ScopeConfig`` /
``ScanConfig`` so the rest of dastcore (scanner, scope enforcement, gate) is reused unchanged.
"""

from dastcore.bugbounty.loader import load_program
from dastcore.bugbounty.program import Program, ProgramLimits, ProgramScope

__all__ = ["Program", "ProgramLimits", "ProgramScope", "load_program"]
