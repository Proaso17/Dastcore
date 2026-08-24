"""ASN intelligence — all offline via an injected RIPEstat JSON fetcher (no network)."""

from __future__ import annotations

from dastcore.discovery.asn import (
    AsnIntel,
    _norm_asn,
    announced_prefixes,
    as_holder,
    asn_intel_findings,
    gather_asn_intel,
    network_info,
)

_RESPONSES = {
    "network-info/data.json?resource=8.8.8.8": {"data": {"asns": ["15169"], "prefix": "8.8.8.0/24"}},
    "as-overview/data.json?resource=AS15169": {"data": {"holder": "GOOGLE, US"}},
    "announced-prefixes/data.json?resource=AS15169": {
        "data": {"prefixes": [{"prefix": "8.8.8.0/24"}, {"prefix": "8.8.4.0/24"}]}
    },
}


def _fetcher(table: dict[str, dict]):
    async def fetch(url: str) -> dict | None:
        for suffix, payload in table.items():
            if url.endswith(suffix):
                return payload
        return None

    return fetch


def test_norm_asn_accepts_variants() -> None:
    assert _norm_asn("15169") == "AS15169"
    assert _norm_asn("as15169") == "AS15169"
    assert _norm_asn("AS15169") == "AS15169"
    assert _norm_asn("notanasn") == ""


async def test_network_info_parses_asns_and_prefix() -> None:
    info = await network_info("8.8.8.8", fetcher=_fetcher(_RESPONSES))
    assert info is not None and info.asns == ["AS15169"] and info.prefix == "8.8.8.0/24"


async def test_as_holder_and_prefixes() -> None:
    fetch = _fetcher(_RESPONSES)
    assert await as_holder("15169", fetcher=fetch) == "GOOGLE, US"
    assert await announced_prefixes("AS15169", fetcher=fetch) == ["8.8.8.0/24", "8.8.4.0/24"]


async def test_gather_asn_intel_dedupes_prefixes_and_maps_holders() -> None:
    intel = await gather_asn_intel(["8.8.8.8", "8.8.8.8", ""], fetcher=_fetcher(_RESPONSES))
    assert intel.asns == ["AS15169"]
    assert intel.holders == {"AS15169": "GOOGLE, US"}
    assert intel.prefixes == ["8.8.8.0/24", "8.8.4.0/24"]


async def test_gather_asn_intel_fail_open_on_missing_data() -> None:
    async def empty(_url: str) -> dict | None:
        return None

    intel = await gather_asn_intel(["203.0.113.1"], fetcher=empty)
    assert intel.asns == [] and intel.prefixes == []


def test_asn_intel_findings_are_info_and_empty_without_asns() -> None:
    assert asn_intel_findings(AsnIntel(), "https://acme.com") == []
    intel = AsnIntel(asns=["AS15169"], holders={"AS15169": "GOOGLE"}, prefixes=["8.8.8.0/24"])
    findings = asn_intel_findings(intel, "https://acme.com")
    assert len(findings) == 1 and findings[0].severity == "info" and findings[0].rule_id == "asn-footprint"
    assert "AS15169" in findings[0].evidence[0].data
