"""Managed SecLists presets: resolution to installed files, built-in fallback when not downloaded,
and the loaders honouring a preset name. Offline — no download is performed."""

from __future__ import annotations

from dastcore.discovery import seclists
from dastcore.discovery.content import load_content_wordlist

_MEDIUM = "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"


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


async def test_add_custom_wordlist_from_text_and_use_it(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DASTCORE_SECLISTS", str(tmp_path))
    path = await seclists.add_custom_wordlist("content", "Mi Lista!", text="foo\nbar\n")
    assert path.is_file() and path.name == "mi-lista.txt"
    # It shows up as an option and resolves to its own path (passthrough), and the loader reads it.
    assert (str(path), "Propio · mi-lista") in seclists.custom_wordlists("content")
    assert (str(path), "Propio · mi-lista") in seclists.wordlist_options("content")
    assert seclists.resolve_wordlist("content", str(path)) == str(path)
    assert load_content_wordlist("aggressive", str(path)) == ["foo", "bar"]


async def test_add_custom_wordlist_rejects_bad_inputs(tmp_path, monkeypatch) -> None:
    import pytest

    monkeypatch.setenv("DASTCORE_SECLISTS", str(tmp_path))
    with pytest.raises(ValueError):
        await seclists.add_custom_wordlist("nope", "x", text="a")  # bad category
    with pytest.raises(ValueError):
        await seclists.add_custom_wordlist("content", "!!!", text="a")  # slug empties out
    with pytest.raises(ValueError):
        await seclists.add_custom_wordlist("content", "x")  # neither url nor text


def test_is_managed_wordlist(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DASTCORE_SECLISTS", str(tmp_path))
    assert seclists.is_managed_wordlist("seclists-content")  # a preset
    assert not seclists.is_managed_wordlist("")  # built-in
    assert not seclists.is_managed_wordlist(str(tmp_path / "etc" / "passwd"))  # arbitrary path
    managed = tmp_path / "custom" / "content" / "list.txt"
    managed.parent.mkdir(parents=True)
    managed.write_text("a\n", encoding="utf-8")
    assert seclists.is_managed_wordlist(str(managed))  # a file under the custom dir
