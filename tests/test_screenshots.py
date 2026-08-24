"""Screenshot filename sanitisation (the capture itself needs a real browser and is covered by the
headless engine's fail-open behaviour)."""

from __future__ import annotations

from dastcore.cli import _screenshot_filename


def test_screenshot_filename_is_filesystem_safe() -> None:
    assert _screenshot_filename("https://admin.acme.com/") == "admin.acme.com.png"
    assert _screenshot_filename("https://acme.com:8443/path") == "acme.com_8443.png"
    assert _screenshot_filename("http://10.0.0.1/") == "10.0.0.1.png"
    assert _screenshot_filename("not a url").endswith(".png")
