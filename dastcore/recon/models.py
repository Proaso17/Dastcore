"""Normalized recon data model. Every adapter, whatever tool it wraps, emits ``Asset``s."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Asset(BaseModel):
    """One discovered piece of attack surface, normalized across every recon source."""

    host: str  # canonical hostname (a subdomain, or an IP literal)
    ip: str | None = None
    port: int | None = None
    url: str | None = None  # set once a live-host probe reaches it
    source: str = ""  # which adapter found it (crtsh, subfinder, httpx…)
    tech: list[str] = Field(default_factory=list)
    status_code: int | None = None
    title: str | None = None

    def dedupe_key(self) -> str:
        """Stable identity for the asset store: a live URL if we have one, else the host(:port)."""
        if self.url:
            return self.url
        return f"{self.host}:{self.port}" if self.port else self.host


class ReconOptions(BaseModel):
    """Knobs for a recon run. ``replay`` feeds each adapter recorded output so tests never hit the net."""

    profile: Literal["passive", "standard", "deep"] = "standard"
    timeout: float = 120.0
    replay: dict[str, str] = Field(default_factory=dict)  # adapter name -> recorded raw output
