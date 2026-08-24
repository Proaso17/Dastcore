"""DNS record enrichment + PTR sweep — fully offline via injected resolvers (no network, no dnspython)."""

from __future__ import annotations

from dastcore.discovery.dns_records import (
    RecordSet,
    _iter_scope_ips,
    cname_map,
    gather_dns_records,
    gather_records,
    ptr_sweep,
)


def _resolver(table: dict[tuple[str, str], list[str]]):
    async def resolve(host: str, rrtype: str) -> list[str]:
        return table.get((host, rrtype), [])

    return resolve


async def test_gather_records_maps_types_to_fields() -> None:
    resolver = _resolver(
        {
            ("api.acme.com", "A"): ["203.0.113.5"],
            ("api.acme.com", "CNAME"): ["acme.github.io"],
            ("api.acme.com", "MX"): ["mail.acme.com"],
            ("api.acme.com", "TXT"): ["v=spf1 include:_spf.google.com ~all"],
        }
    )
    rs = await gather_records("API.acme.com.", resolver=resolver)
    assert rs.host == "api.acme.com"  # normalised
    assert rs.a == ["203.0.113.5"] and rs.cname == ["acme.github.io"]
    assert rs.mx == ["mail.acme.com"] and rs.txt[0].startswith("v=spf1")
    assert rs.resolves is True


async def test_records_without_address_or_cname_do_not_resolve() -> None:
    rs = await gather_records("ghost.acme.com", resolver=_resolver({("ghost.acme.com", "NS"): ["ns1.acme.com"]}))
    assert rs.ns == ["ns1.acme.com"] and rs.resolves is False


async def test_gather_dns_records_dedupes_and_keys_by_host() -> None:
    resolver = _resolver({("a.acme.com", "A"): ["1.1.1.1"]})
    records = await gather_dns_records(["a.acme.com", "A.acme.com.", ""], resolver=resolver)
    assert set(records) == {"a.acme.com"}


def test_cname_map_extracts_first_cname_only() -> None:
    records = {
        "a.acme.com": RecordSet(host="a.acme.com", cname=["a.github.io"]),
        "b.acme.com": RecordSet(host="b.acme.com", a=["1.2.3.4"]),  # no cname
    }
    assert cname_map(records) == {"a.acme.com": "a.github.io"}


def test_iter_scope_ips_skips_network_broadcast_and_caps() -> None:
    ips = _iter_scope_ips(["192.0.2.0/29"], max_hosts=100)
    assert "192.0.2.0" not in ips and "192.0.2.7" not in ips  # network + broadcast excluded
    assert ips[0] == "192.0.2.1" and len(ips) == 6
    assert _iter_scope_ips(["192.0.2.0/24"], max_hosts=3) == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]


async def test_ptr_sweep_gates_ip_and_hostname_by_scope() -> None:
    # 192.0.2.1 is in scope and reverse-resolves to an in-scope host; 192.0.2.2 resolves out of scope.
    ptr = {"192.0.2.1": ["host1.acme.com"], "192.0.2.2": ["evil.example.org"]}

    async def resolver(ip: str) -> list[str]:
        return ptr.get(ip, [])

    def in_scope(value: str) -> bool:
        return value.endswith("acme.com") or value.startswith("192.0.2.")

    hosts = await ptr_sweep(["192.0.2.0/29"], in_scope, resolver=resolver, max_hosts=10)
    assert hosts == {"host1.acme.com"}  # out-of-scope PTR target dropped


async def test_ptr_sweep_empty_when_no_ip_in_scope() -> None:
    async def resolver(_ip: str) -> list[str]:
        raise AssertionError("resolver must not be called when no IP is in scope")

    assert await ptr_sweep(["10.0.0.0/30"], lambda _v: False, resolver=resolver) == set()
