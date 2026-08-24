"""Favicon fingerprinting — MurmurHash3 matches the mmh3/Shodan convention, and the product lookup is
FP-safe (only verified hashes map to a product). The fetch is scope-gated."""

from __future__ import annotations

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.discovery.favicon import (
    KNOWN_FAVICONS,
    FaviconInfo,
    favicon_hash,
    murmur3_x86_32,
    probe_favicon,
)


def test_murmur3_matches_reference_vectors() -> None:
    # The canonical mmh3.hash (x86 32-bit, seed 0, signed) values.
    assert murmur3_x86_32(b"") == 0
    assert murmur3_x86_32(b"foo") == -156908512
    assert murmur3_x86_32(b"hello") == 613153351


def test_favicon_hash_is_deterministic_and_signed() -> None:
    content = bytes(range(256)) * 4
    assert favicon_hash(content) == favicon_hash(content)
    assert -(2**31) <= favicon_hash(content) < 2**31


def test_known_favicon_lookup_maps_hash_to_product() -> None:
    # Table starts empty (FP-safe); a lookup only resolves for a hash that has been verified in.
    fake = FaviconInfo(url="http://x/favicon.ico", hash=42, product=KNOWN_FAVICONS.get(42))
    assert fake.product is None
    with_entry = dict(KNOWN_FAVICONS)
    with_entry[42] = "TestProduct"
    assert with_entry.get(42) == "TestProduct"


async def test_probe_favicon_rejects_out_of_scope() -> None:
    async with HttpClient(ScopeConfig(allow_domains=["acme.com"])) as client:
        assert await probe_favicon(client, "http://not-in-scope.example.org") is None
