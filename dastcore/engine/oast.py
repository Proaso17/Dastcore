"""Out-of-band Application Security Testing (OAST).

Blind vulnerabilities (blind SSRF, blind RCE/command injection, XXE, some SSTI
and CRLF) produce no in-band signal: the response looks identical whether or
not the payload worked. OAST closes that gap. Each payload embeds a unique
callback address; if the *target* later reaches out to that address, the
interaction proves the payload executed. Because confirmation requires a real
network callback correlated to a specific payload, an OAST-confirmed finding
has effectively zero false positives.

Two providers implement the same interface:

* ``LocalOastServer`` — a self-hosted HTTP collaborator you run yourself
  (default for localhost/CI). Correlation is by a unique token in the callback
  path.
* ``InteractshClient`` — a client for a public/self-hosted Interactsh server.
  Correlation is by a unique subdomain label; interactions are fetched over an
  RSA+AES-encrypted poll channel.
"""
from __future__ import annotations

import abc
import base64
import json
import secrets
import socket
import threading

import httpx
from pydantic import BaseModel


class OastInteraction(BaseModel):
    """A single callback the target made to the collaborator."""

    token: str
    protocol: str = "http"
    remote_addr: str | None = None
    raw: str = ""


class OastHandle(BaseModel):
    """A freshly minted, unique callback address for one payload."""

    token: str
    url: str
    domain: str


def substitute_oast(template: str, handle: OastHandle) -> str:
    """Replace OAST placeholders in a payload template with a concrete handle."""
    return template.replace("{{oast_url}}", handle.url).replace("{{oast_domain}}", handle.domain)


class OastProvider(abc.ABC):
    """Common interface the scanner uses; implementations differ in transport/correlation."""

    @abc.abstractmethod
    async def start(self) -> None: ...

    @abc.abstractmethod
    async def stop(self) -> None: ...

    @abc.abstractmethod
    def is_available(self) -> bool: ...

    @abc.abstractmethod
    def new_handle(self) -> OastHandle: ...

    @abc.abstractmethod
    async def poll(self) -> list[OastInteraction]: ...


# --------------------------------------------------------------------------------------
# Self-hosted local collaborator
# --------------------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class LocalOastServer(OastProvider):
    """A minimal self-hosted HTTP collaborator.

    Any HTTP request to ``http://<host>:<port>/<token>`` is recorded; correlation
    is by the unique ``token`` in the path. Suitable for scanning localhost/CI
    targets, or when you host it on an address the target can reach.
    """

    def __init__(self, host: str = "127.0.0.1", port: int | None = None) -> None:
        self._host = host
        self._port = port or _free_port()
        self._interactions: list[OastInteraction] = []
        self._lock = threading.Lock()
        self._server = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self._host}:{self._port}"

    def _wsgi_app(self, environ, start_response):
        path = environ.get("PATH_INFO", "/")
        method = environ.get("REQUEST_METHOD", "GET")
        token = path.strip("/").split("/", 1)[0]
        remote = environ.get("REMOTE_ADDR")
        with self._lock:
            self._interactions.append(
                OastInteraction(token=token, protocol="http", remote_addr=remote, raw=f"{method} {path}")
            )
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]

    async def start(self) -> None:
        from werkzeug.serving import make_server

        self._server = make_server(self._host, self._port, self._wsgi_app, threaded=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def is_available(self) -> bool:
        return self._server is not None

    def new_handle(self) -> OastHandle:
        token = secrets.token_hex(8)
        return OastHandle(token=token, url=f"{self.base_url}/{token}", domain=f"{self._host}:{self._port}")

    async def poll(self) -> list[OastInteraction]:
        with self._lock:
            return list(self._interactions)


# --------------------------------------------------------------------------------------
# Interactsh client
# --------------------------------------------------------------------------------------

_INTERACTSH_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def _random_label(length: int) -> str:
    return "".join(secrets.choice(_INTERACTSH_ALPHABET) for _ in range(length))


def decrypt_interaction(private_key, aes_key_b64: str, data_b64: str) -> dict:
    """Decrypt one Interactsh interaction payload.

    The server encrypts a random AES key with our RSA public key (OAEP/SHA-256),
    and encrypts each interaction with AES-CFB using that key (IV is the first 16
    bytes of the message). This mirrors the Interactsh server exactly, and is the
    part worth testing offline.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    # Interactsh uses AES-CFB; CFB moved from `primitives` to `decrepit` in newer
    # cryptography releases, so resolve it from whichever location is available.
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:  # pragma: no cover - depends on cryptography version
        from cryptography.hazmat.primitives.ciphers.modes import CFB

    aes_key = private_key.decrypt(
        base64.b64decode(aes_key_b64),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    raw = base64.b64decode(data_b64)
    iv, ciphertext = raw[:16], raw[16:]
    decryptor = Cipher(algorithms.AES(aes_key), CFB(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return json.loads(plaintext.decode("utf-8", errors="replace"))


class InteractshClient(OastProvider):
    """Client for an Interactsh collaborator server (public or self-hosted)."""

    def __init__(self, server: str = "oast.fun", token: str | None = None, timeout: float = 10.0) -> None:
        self._server = server.rstrip("/")
        self._auth_token = token
        self._timeout = timeout
        self._correlation_id = _random_label(20)
        self._secret = secrets.token_hex(16)
        self._private_key = None
        self._registered = False
        self._client: httpx.AsyncClient | None = None

    def _headers(self) -> dict[str, str]:
        return {"Authorization": self._auth_token} if self._auth_token else {}

    async def start(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_b64 = base64.b64encode(public_pem).decode("ascii")

        self._client = httpx.AsyncClient(timeout=self._timeout)
        resp = await self._client.post(
            f"https://{self._server}/register",
            json={"public-key": pub_b64, "secret-key": self._secret, "correlation-id": self._correlation_id},
            headers=self._headers(),
        )
        self._registered = resp.status_code == 200

    async def stop(self) -> None:
        if self._client is not None:
            try:
                await self._client.post(
                    f"https://{self._server}/deregister",
                    json={"secret-key": self._secret, "correlation-id": self._correlation_id},
                    headers=self._headers(),
                )
            except httpx.HTTPError:
                pass
            await self._client.aclose()

    def is_available(self) -> bool:
        return self._registered

    def new_handle(self) -> OastHandle:
        # 33-char label: correlation id (20) + unique per-payload suffix (13).
        label = self._correlation_id + _random_label(13)
        domain = f"{label}.{self._server}"
        return OastHandle(token=label, url=f"https://{domain}", domain=domain)

    async def poll(self) -> list[OastInteraction]:
        if not self._registered or self._client is None:
            return []
        resp = await self._client.get(
            f"https://{self._server}/poll",
            params={"id": self._correlation_id, "secret": self._secret},
            headers=self._headers(),
        )
        if resp.status_code != 200:
            return []
        body = resp.json()
        data = body.get("data") or []
        aes_key = body.get("aes_key")
        interactions: list[OastInteraction] = []
        if not aes_key:
            return interactions
        for item in data:
            try:
                decoded = decrypt_interaction(self._private_key, aes_key, item)
            except Exception:
                continue
            full_id = decoded.get("full-id") or decoded.get("unique-id") or ""
            interactions.append(
                OastInteraction(
                    token=full_id,
                    protocol=decoded.get("protocol", "dns"),
                    remote_addr=decoded.get("remote-address"),
                    raw=json.dumps(decoded)[:500],
                )
            )
        return interactions
