"""PyInstaller entry point for the bundled `dastcore` sidecar.

A thin wrapper so PyInstaller has a concrete script to analyze; it just invokes
the same Typer app the `dastcore` console script does.
"""

from dastcore.cli import app

if __name__ == "__main__":
    app()
