"""Phase 6: OAST and blind-vulnerability confirmation.

Covers the self-hosted collaborator, the end-to-end blind-SSRF flow with its
zero-false-positive guarantee, and — offline — the Interactsh client's RSA+AES
decryption (the one part of that client worth verifying without a live server).
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest
from dastcore.engine.oast import (
    InteractshClient,
    LocalOastServer,
    OastHandle,
    decrypt_interaction,
    substitute_oast,
)
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner

_SCOPE = ScopeConfig(allow_domains=["127.0.0.1"])


# --- substitution ----------------------------------------------------------------------


def test_substitute_oast_replaces_both_placeholders() -> None:
    handle = OastHandle(token="abc", url="http://c.test/abc", domain="c.test")
    assert substitute_oast("{{oast_url}}", handle) == "http://c.test/abc"
    assert substitute_oast("x http://{{oast_domain}}/y", handle) == "x http://c.test/y"


# --- self-hosted collaborator ----------------------------------------------------------


async def test_local_oast_records_and_polls_interactions() -> None:
    server = LocalOastServer()
    await server.start()
    try:
        handle = server.new_handle()
        assert server.is_available()
        # No callback yet.
        assert await server.poll() == []
        # Simulate the target reaching out to the callback URL.
        httpx.get(handle.url, timeout=5)
        interactions = await server.poll()
        assert any(i.token == handle.token for i in interactions)
    finally:
        await server.stop()


# --- end-to-end blind SSRF -------------------------------------------------------------


async def test_blind_ssrf_confirmed_via_oob(vuln_app_url: str) -> None:
    server = LocalOastServer()
    await server.start()
    try:
        request = HttpRequest(method="GET", url=f"{vuln_app_url}/fetch", params={"url": "http://placeholder/"})
        rules = load_rules()
        async with HttpClient(_SCOPE) as client:
            findings = await Scanner(client, rules, oast=server, oob_poll_attempts=6).scan([request])
    finally:
        await server.stop()

    ssrf = [f for f in findings if f.rule_id == "ssrf-oob"]
    assert ssrf, [f.rule_id for f in findings]
    assert ssrf[0].severity == "high"
    assert ssrf[0].evidence[0].type == "oob"
    assert ssrf[0].injection_point.name == "url"
    # The callback metadata classifies it as a server-side HTTP fetch (blind SSRF).
    assert "HTTP" in ssrf[0].evidence[0].data and "server-side fetch" in ssrf[0].evidence[0].data


async def test_no_oob_finding_without_a_real_callback(vuln_app_url: str) -> None:
    """Zero false positives: /greet reflects the payload but never calls it out-of-band."""
    server = LocalOastServer()
    await server.start()
    try:
        request = HttpRequest(method="GET", url=f"{vuln_app_url}/greet", params={"name": "seed"})
        rules = load_rules()
        async with HttpClient(_SCOPE) as client:
            findings = await Scanner(client, rules, oast=server, oob_poll_attempts=2).scan([request])
    finally:
        await server.stop()

    assert not any(f.rule_id == "ssrf-oob" for f in findings)


async def test_oob_rules_do_nothing_without_a_provider(vuln_app_url: str) -> None:
    """Without an OAST provider the blind rules are inert — no probing, no findings."""
    request = HttpRequest(method="GET", url=f"{vuln_app_url}/fetch", params={"url": "http://placeholder/"})
    rules = load_rules()
    async with HttpClient(_SCOPE) as client:
        findings = await Scanner(client, rules).scan([request])
    assert not any(f.rule_id in {"ssrf-oob", "cmdi-oob", "ssti-oob", "xxe-oob", "crlf-oob"} for f in findings)


# --- Interactsh decryption (offline) ---------------------------------------------------


def test_interactsh_decrypt_roundtrip() -> None:
    """Mimic the Interactsh server's encryption and verify the client decrypts it.

    Server side: RSA-OAEP(SHA-256) encrypts a random AES key with the client's public
    key; each interaction is AES-CFB encrypted with IV prepended. This validates the
    hard part of the client without any network.
    """
    pytest.importorskip("cryptography")
    import os

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.modes import CFB

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    aes_key = os.urandom(32)
    aes_key_b64 = base64.b64encode(
        public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    ).decode()

    interaction = {"protocol": "http", "full-id": "corr1234deadbeef", "remote-address": "203.0.113.9"}
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(aes_key), CFB(iv)).encryptor()
    ciphertext = encryptor.update(json.dumps(interaction).encode()) + encryptor.finalize()
    data_b64 = base64.b64encode(iv + ciphertext).decode()

    decrypted = decrypt_interaction(private_key, aes_key_b64, data_b64)
    assert decrypted["full-id"] == "corr1234deadbeef"
    assert decrypted["protocol"] == "http"


def test_interactsh_client_handle_shape() -> None:
    client = InteractshClient(server="oast.example")
    handle = client.new_handle()
    assert handle.domain.endswith(".oast.example")
    assert handle.url == f"https://{handle.domain}"
    assert len(handle.token) == 33  # 20-char correlation id + 13-char unique suffix
    assert not client.is_available()  # never registered (no network)
