"""Favicon fingerprinting — identify a host's stack from its ``/favicon.ico``.

A favicon is a stable, distinctive fingerprint: the same product ships the same icon across every
deployment, so its hash identifies the software (Shodan's ``http.favicon.hash`` works exactly this way)
and correlates hosts that share a stack even when headers and bodies are stripped or obfuscated. A
Jenkins/GitLab/Grafana favicon tells you the stack — and therefore which paths ``tech_paths`` should
probe — regardless of what the homepage says.

The hash is the Shodan convention: MurmurHash3 (x86, 32-bit, signed) over the standard-base64 encoding
of the icon bytes. MurmurHash3 is implemented here in pure Python, so this adds **no dependency**. The
hash function and the known-product table are pure and fully unit-testable from raw bytes; the fetch is
scope-gated and injectable.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from dastcore.core.http_client import HttpClient

_UINT32 = 0xFFFFFFFF


def murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, returned **signed** (matches Python ``mmh3.hash``/Shodan)."""
    length = len(data)
    nblocks = length // 4
    h1 = seed & _UINT32
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for block in range(nblocks):
        i = block * 4
        k1 = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & _UINT32
        k1 = ((k1 << 15) | (k1 >> 17)) & _UINT32
        k1 = (k1 * c2) & _UINT32
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & _UINT32
        h1 = (h1 * 5 + 0xE6546B64) & _UINT32

    tail_index = nblocks * 4
    k1 = 0
    tail_size = length & 3
    if tail_size == 3:
        k1 ^= data[tail_index + 2] << 16
    if tail_size >= 2:
        k1 ^= data[tail_index + 1] << 8
    if tail_size >= 1:
        k1 ^= data[tail_index]
        k1 = (k1 * c1) & _UINT32
        k1 = ((k1 << 15) | (k1 >> 17)) & _UINT32
        k1 = (k1 * c2) & _UINT32
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & _UINT32
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & _UINT32
    h1 ^= h1 >> 16

    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(content: bytes) -> int:
    """The Shodan-style favicon hash: MurmurHash3 over the icon's standard-base64 (MIME, ``\\n`` every 76)."""
    encoded = base64.encodebytes(content)  # RFC 2045: wraps at 76 chars with a trailing newline
    return murmur3_x86_32(encoded)


# hash -> product it identifies. Intentionally starts empty: an entry is only added once its hash has
# been *verified* against the real product favicon, because a wrong hash would misidentify a stack (a
# false positive). Until then, the hash itself is still useful — identical hashes correlate hosts that
# share a favicon (same product/deployment), which needs no ground-truth table.
KNOWN_FAVICONS: dict[int, str] = {}


@dataclass(frozen=True)
class FaviconInfo:
    """A host's favicon: where it lives, its Shodan-style hash, and the product it identifies (if known)."""

    url: str
    hash: int
    product: str | None = None


async def probe_favicon(client: HttpClient, root: str) -> FaviconInfo | None:
    """Fetch ``root``'s ``/favicon.ico`` (scope-gated) and return its hash + identified product, or None.

    The fetch uses a raw ``httpx`` GET because the favicon is binary and the shared client only exposes
    decoded text; scope is enforced explicitly first, so this can never leave the authorised host.
    """
    parts = urlsplit(root)
    if not parts.scheme or not parts.netloc:
        return None
    favicon_url = urljoin(f"{parts.scheme}://{parts.netloc}/", "favicon.ico")
    if not client.is_in_scope(favicon_url):
        return None

    import httpx

    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as http:  # noqa: S501
            resp = await http.get(favicon_url)
    except (httpx.HTTPError, OSError):
        return None
    if resp.status_code != 200 or not resp.content:
        return None

    digest = favicon_hash(resp.content)
    return FaviconInfo(url=favicon_url, hash=digest, product=KNOWN_FAVICONS.get(digest))
