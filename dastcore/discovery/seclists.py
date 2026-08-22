"""Managed SecLists wordlists — big, community-grade dictionaries available to everyone with no manual
path juggling. SecLists in full is ~1 GB, so we don't bundle it; instead we download the handful of
high-value lists on demand into ``~/.dastcore/seclists`` and expose them as **named presets**
(``seclists-content``, ``seclists-subdomains``…). A preset resolves to its installed file; the loaders
fall back to the built-in list when a preset isn't downloaded yet.
"""

from __future__ import annotations

import os
from pathlib import Path

_RAW_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"

# preset name -> (category, path within the SecLists repo).
_PRESETS: dict[str, tuple[str, str]] = {
    "seclists-content": ("content", "Discovery/Web-Content/directory-list-2.3-medium.txt"),
    "seclists-content-big": ("content", "Discovery/Web-Content/directory-list-2.3-big.txt"),
    "seclists-content-raft": ("content", "Discovery/Web-Content/raft-large-directories.txt"),
    "seclists-subdomains": ("subdomains", "Discovery/DNS/subdomains-top1million-20000.txt"),
    "seclists-subdomains-big": ("subdomains", "Discovery/DNS/subdomains-top1million-110000.txt"),
    "seclists-params": ("params", "Discovery/Web-Content/burp-parameter-names.txt"),
}

# Human labels for the UI (category -> [(preset, label)]).
PRESET_LABELS: dict[str, list[tuple[str, str]]] = {
    "content": [
        ("seclists-content", "SecLists · directory-list medium (~220k)"),
        ("seclists-content-raft", "SecLists · raft-large directories"),
        ("seclists-content-big", "SecLists · directory-list big (~1.2M)"),
    ],
    "subdomains": [
        ("seclists-subdomains", "SecLists · subdomains top-20k"),
        ("seclists-subdomains-big", "SecLists · subdomains top-110k"),
    ],
    "params": [("seclists-params", "SecLists · burp parameter names")],
}


def seclists_dir() -> Path:
    """Where downloaded SecLists files live (``$DASTCORE_SECLISTS`` or ``~/.dastcore/seclists``)."""
    override = os.environ.get("DASTCORE_SECLISTS", "").strip()
    return Path(override) if override else Path.home() / ".dastcore" / "seclists"


def is_preset(name: str) -> bool:
    """Whether ``name`` is a known SecLists preset (not a raw file path)."""
    return name in _PRESETS


def preset_path(name: str) -> Path | None:
    """The on-disk path a preset name maps to, or None if ``name`` isn't a known preset."""
    entry = _PRESETS.get(name)
    return seclists_dir() / entry[1] if entry else None


def resolve_wordlist(category: str, value: str | Path | None) -> str | None:
    """A wordlist selection → a file path (or None for the built-in).

    ``value`` may be empty (built-in), a preset name (resolved to its SecLists file), or a raw file path.
    A preset for the wrong category, or one not downloaded yet, resolves to None (fall back to built-in).
    """
    if not value:
        return None
    text = str(value)
    entry = _PRESETS.get(text)
    if entry is not None:
        cat, _rel = entry
        path = preset_path(text)
        return str(path) if (cat == category and path is not None and path.exists()) else None
    return text  # a raw path the caller supplied


def installed_presets(category: str) -> list[tuple[str, str]]:
    """The (preset, label) options for ``category`` whose files are already downloaded."""
    return [(name, label) for name, label in PRESET_LABELS.get(category, []) if _is_downloaded(name)]


def _is_downloaded(name: str) -> bool:
    path = preset_path(name)
    return path is not None and path.exists()


def status() -> list[dict[str, object]]:
    """Per-preset install status (name, category, downloaded, size) for the UI / CLI."""
    rows: list[dict[str, object]] = []
    for name, (category, _rel) in _PRESETS.items():
        path = preset_path(name)
        downloaded = path is not None and path.exists()
        rows.append(
            {
                "name": name,
                "category": category,
                "downloaded": downloaded,
                "size": path.stat().st_size if downloaded and path else 0,
            }
        )
    return rows


def is_installed() -> bool:
    """True if at least one SecLists preset has been downloaded."""
    return any(_is_downloaded(name) for name in _PRESETS)


async def download_presets(names: list[str] | None = None, on_progress=None) -> list[str]:
    """Download the given presets (all by default) into ``seclists_dir``. Returns the presets now present.

    Idempotent: an already-downloaded file is kept. A failed/partial download is cleaned up and skipped.
    """
    import httpx

    target = list(_PRESETS) if names is None else [n for n in names if n in _PRESETS]
    base = seclists_dir()
    done: list[str] = []
    async with httpx.AsyncClient(timeout=180.0, follow_redirects=True) as client:
        for name in target:
            _category, rel = _PRESETS[name]
            dest = base / rel
            if dest.exists():
                done.append(name)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                async with client.stream("GET", _RAW_BASE + rel) as resp:
                    resp.raise_for_status()
                    with dest.open("wb") as handle:
                        async for chunk in resp.aiter_bytes():
                            handle.write(chunk)
                done.append(name)
                if on_progress is not None:
                    on_progress(name)
            except Exception:  # noqa: BLE001 — best-effort; drop a partial file and move on
                if dest.exists():
                    dest.unlink(missing_ok=True)
    return done
