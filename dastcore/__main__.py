"""Enable `python -m dastcore` as an alias for the `dastcore` console script."""

from dastcore.cli import app

if __name__ == "__main__":
    app()
