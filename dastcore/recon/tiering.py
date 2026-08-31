"""Attack-surface tiering: rank discovered assets so the hunt spends effort where it pays off.

The bug-bounty heuristic is that a small slice of the surface holds most of the value: admin / internal
/ staging / dev / API hosts (Tier 1) reward far more scrutiny than the polished main app (Tier 3). This
classifies each ``Asset`` into a tier from its hostname labels and detected tech, so the campaign scans
Tier 1 first and the reports/UI surface it. Purely a *priority* signal — nothing is excluded by tier.
"""

from __future__ import annotations

import re

from dastcore.recon.models import Asset

# Tier 1: high-value hostname labels (matched as whole dot/hyphen-separated labels, so "development"
# does not match "dev"). Admin panels, internal/non-prod envs, and API/auth surface.
_TIER1_LABELS: frozenset[str] = frozenset({
    "admin", "internal", "intranet", "corp", "staging", "stage", "preprod", "pre-prod", "uat", "qa",
    "test", "testing", "dev", "develop", "sandbox", "beta", "demo", "api", "apis", "gateway", "gql",
    "graphql", "auth", "sso", "login", "oauth", "idp", "vpn", "portal", "backend", "back-office",
    "backoffice", "jenkins", "gitlab", "jira", "confluence", "grafana", "kibana", "phpmyadmin",
})
# Tier 2: legacy/old stacks (from detected tech) — more likely to hold unpatched classic bugs.
_TIER2_TECH = re.compile(
    r"\b(php|wordpress|wp|drupal|joomla|coldfusion|struts|jboss|weblogic|tomcat|apache/2\.2|iis/[67]|"
    r"asp\.net|cgi|perl|flash|jquery/1\.|angularjs)\b",
    re.IGNORECASE,
)

TIER_LABELS: dict[int, str] = {
    1: "Tier 1 · admin/API/interno (máxima prioridad)",
    2: "Tier 2 · stacks antiguos",
    3: "Tier 3 · app principal",
}


def _host_labels(host: str) -> set[str]:
    return {label for label in re.split(r"[.\-]", host.lower()) if label}


def classify_tier(asset: Asset) -> int:
    """1 (scan first) … 3 (scan last). Hostname decides Tier 1; legacy tech decides Tier 2."""
    if _host_labels(asset.host) & _TIER1_LABELS:
        return 1
    tech_blob = " ".join(asset.tech)
    if _TIER2_TECH.search(tech_blob):
        return 2
    return 3


def assign_tiers(assets: list[Asset]) -> list[Asset]:
    """Set ``asset.tier`` on each asset in place and return the list (for chaining)."""
    for asset in assets:
        asset.tier = classify_tier(asset)
    return assets


def by_tier(assets: list[Asset]) -> list[Asset]:
    """Assets ordered highest-priority first (Tier 1 → 3), stable within a tier."""
    assign_tiers(assets)
    return sorted(assets, key=lambda a: a.tier)


def tier_counts(assets: list[Asset]) -> dict[int, int]:
    counts = {1: 0, 2: 0, 3: 0}
    for asset in assets:
        counts[classify_tier(asset)] += 1
    return counts
