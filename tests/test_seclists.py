"""Managed SecLists presets: resolution to installed files, built-in fallback when not downloaded,
and the loaders honouring a preset name. Offline — no download is performed."""

from __future__ import annotations

from dastcore.discovery import seclists
from dastcore.discovery.content import load_content_wordlist

_MEDIUM = "Discovery/Web-Content/directory-list-2.3-medium.txt"


def test_is_preset() -> None:
    assert seclists.is_preset("seclists-content")
    assert not seclists.is_preset("/etc/passwd")
    assert not seclists.is_preset("")


def test_resolve_passthrough_and_builtin() -> None:
    assert seclists.resolve_wordlist("content", "") is None  # built-in
    assert seclists.resolve_wordlist("content", "/my/list.txt") == "/my/list.txt"  # raw path


def test_resolve_preset_requires_the_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DASTCORE_SECLISTS", str(tmp_path))
    # not downloaded -> None so the loader falls back to the built-in list
    assert seclists.resolve_wordlist("content", "seclists-content") is None

    target = tmp_path / _MEDIUM
    target.parent.mkdir(parents=True)
    target.write_text("admin\nlogin\napi\n", encoding="utf-8")
    assert seclists.resolve_wordlist("content", "seclists-content") == str(target)
    assert seclists.resolve_wordlist("subdomains", "seclists-content") is None  # wrong category
    assert ("seclists-content", "SecLists · directory-list medium (~220k)") in seclists.installed_presets("content")


def test_loader_uses_a_downloaded_preset(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DASTCORE_SECLISTS", str(tmp_path))
    target = tmp_path / _MEDIUM
    target.parent.mkdir(parents=True)
    target.write_text("customword1\ncustomword2\n", encoding="utf-8")
    words = load_content_wordlist("aggressive", "seclists-content")
    assert words == ["customword1", "customword2"]


def test_loader_falls_back_to_builtin_for_a_missing_preset(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DASTCORE_SECLISTS", str(tmp_path))  # empty -> preset not present
    words = load_content_wordlist("light", "seclists-content")
    assert "admin" in words  # the built-in content list, not empty
