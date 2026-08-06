"""Build the bundled `dastcore` sidecar and name it for Tauri.

Runs PyInstaller against dastcore.spec to produce a one-file executable, then
copies it to ``src-tauri/binaries/dastcore-<host-triple>[.exe]`` — the name
Tauri's ``externalBin`` mechanism expects for the current host.

Prerequisites in the build environment:
  pip install ".[web]" pyinstaller     # dastcore importable + PyInstaller
  rustc on PATH                         # to read the host target triple

Usage:  python desktop/sidecar/build_sidecar.py   (or: npm run sidecar)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent  # desktop/sidecar
DESKTOP = HERE.parent  # desktop
BIN_DIR = DESKTOP / "src-tauri" / "binaries"


def host_triple() -> str:
    """The Rust host target triple, e.g. x86_64-pc-windows-msvc."""
    try:
        out = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit("rustc not found — install the Rust toolchain (https://rustup.rs)") from exc
    for line in out.splitlines():
        if line.startswith("host:"):
            return line.split(":", 1)[1].strip()
    raise SystemExit("could not determine the host triple from `rustc -vV`")


def main() -> None:
    triple = host_triple()
    ext = ".exe" if os.name == "nt" else ""

    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "dastcore.spec",
            "--noconfirm",
            "--distpath",
            str(HERE / "dist"),
            "--workpath",
            str(HERE / "build"),
        ],
        cwd=HERE,
        check=True,
    )

    built = HERE / "dist" / f"dastcore{ext}"
    if not built.exists():
        raise SystemExit(f"expected PyInstaller output not found: {built}")

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    dest = BIN_DIR / f"dastcore-{triple}{ext}"
    shutil.copy2(built, dest)
    print(f"sidecar built: {dest}")


if __name__ == "__main__":
    main()
