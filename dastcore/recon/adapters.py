"""Recon adapters (MVP set). Each is a thin wrapper over one tool/source with a pure parser.

- ``crtsh``     — subdomains from the crt.sh certificate-transparency log (HTTP, no binary).
- ``subfinder`` — passive subdomain enumeration (projectdiscovery).
- ``naabu``     — port discovery over the discovered hosts (projectdiscovery; active probe stage).
- ``httpx``     — live-host probing: which hosts answer, with status/title/tech (projectdiscovery).

More (dnsx, nmap, katana, gau, nuclei…) drop in as further ``Adapter`` subclasses + fixtures.
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlsplit

from dastcore.recon.base import Adapter
from dastcore.recon.models import Asset, ReconOptions


def _clean_host(value: str) -> str:
    return value.strip().lower().lstrip("*.").rstrip(".")


class CrtShAdapter(Adapter):
    name = "crtsh"
    stage = "subdomain"
    passive = True
    binary = None  # pure HTTP against a third-party CT log (not the target)

    def parse(self, raw: str) -> list[Asset]:
        try:
            rows = json.loads(raw)
        except ValueError:
            return []
        hosts: set[str] = set()
        for row in rows if isinstance(rows, list) else []:
            for name in str(row.get("name_value", "")).splitlines():
                host = _clean_host(name)
                if host and "@" not in host and " " not in host:
                    hosts.add(host)
        return [Asset(host=host, source=self.name) for host in sorted(hosts)]

    async def _invoke(self, targets: list[str], opts: ReconOptions) -> list[Asset]:
        import httpx

        assets: list[Asset] = []
        async with httpx.AsyncClient(timeout=opts.timeout, follow_redirects=True) as client:
            for seed in targets:
                try:
                    resp = await client.get("https://crt.sh/", params={"q": f"%.{seed}", "output": "json"})
                    assets += self.parse(resp.text)
                except httpx.HTTPError:
                    continue
        return assets


class SubfinderAdapter(Adapter):
    name = "subfinder"
    stage = "subdomain"
    passive = True
    binary = "subfinder"

    def parse(self, raw: str) -> list[Asset]:
        hosts = {_clean_host(line) for line in raw.splitlines() if line.strip()}
        return [Asset(host=host, source=self.name) for host in sorted(hosts) if host]

    async def _invoke(self, targets: list[str], opts: ReconOptions) -> list[Asset]:
        assets: list[Asset] = []
        for seed in targets:
            proc = await asyncio.create_subprocess_exec(
                "subfinder",
                "-silent",
                "-d",
                seed,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=opts.timeout)
            assets += self.parse(out.decode("utf-8", "replace"))
        return assets


def _first_ip(obj: dict) -> str | None:
    if obj.get("ip"):
        return str(obj["ip"])
    a = obj.get("a")
    return str(a[0]) if isinstance(a, list) and a else None


class HttpxAdapter(Adapter):
    name = "httpx"
    stage = "probe"
    passive = False  # sends requests to the target hosts
    binary = "httpx"

    def parse(self, raw: str) -> list[Asset]:
        assets: list[Asset] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            url = obj.get("url") or obj.get("input")
            host = obj.get("host") or (urlsplit(url).hostname if url else None) or obj.get("input")
            if not host:
                continue
            port = obj.get("port")
            assets.append(
                Asset(
                    host=_clean_host(str(host)),
                    url=url,
                    port=int(port) if port else None,
                    ip=_first_ip(obj),
                    status_code=obj.get("status_code") or obj.get("status-code"),
                    title=obj.get("title"),
                    tech=[str(t) for t in (obj.get("tech") or obj.get("technologies") or [])],
                    source=self.name,
                )
            )
        return assets

    async def _invoke(self, targets: list[str], opts: ReconOptions) -> list[Asset]:
        proc = await asyncio.create_subprocess_exec(
            "httpx",
            "-json",
            "-silent",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(input="\n".join(targets).encode()), timeout=opts.timeout)
        return self.parse(out.decode("utf-8", "replace"))


class NaabuAdapter(Adapter):
    """Port discovery (projectdiscovery ``naabu``): which TCP ports each in-scope host has open.

    Parses both naabu's plain ``host:port`` lines and its ``-json`` output. Each open port becomes an
    ``Asset`` carrying the host + port (no URL yet — an httpx probe decides which speak HTTP), so the
    orchestrator's scope gate applies to every one before it is stored.
    """

    name = "naabu"
    stage = "probe"
    passive = False  # sends TCP probes to the target hosts
    binary = "naabu"

    def parse(self, raw: str) -> list[Asset]:
        assets: list[Asset] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            host: str | None = None
            port: int | None = None
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    host = obj.get("host") or obj.get("ip")
                    port = int(obj["port"]) if obj.get("port") is not None else None
                except (ValueError, KeyError, TypeError):
                    continue
            elif ":" in line:
                host_part, _, port_part = line.rpartition(":")
                host = host_part
                port = int(port_part) if port_part.isdigit() else None
            if not host or port is None:
                continue
            assets.append(Asset(host=_clean_host(str(host)), port=port, source=self.name))
        return assets

    async def _invoke(self, targets: list[str], opts: ReconOptions) -> list[Asset]:
        proc = await asyncio.create_subprocess_exec(
            "naabu",
            "-json",
            "-silent",
            "-host",
            ",".join(targets),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=opts.timeout)
        return self.parse(out.decode("utf-8", "replace"))


def default_adapters() -> list[Adapter]:
    return [CrtShAdapter(), SubfinderAdapter(), NaabuAdapter(), HttpxAdapter()]
