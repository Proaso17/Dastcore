"""Baseline profiling + volatile-region normalization (and the timing jitter guard)."""

from __future__ import annotations

from dastcore.core.models import HttpResponse
from dastcore.validation.baseline import BaselineProfile, build_baseline, normalize_body
from dastcore.validation.oracles import check_time_based


def _resp(text: str = "", elapsed_ms: float = 5.0) -> HttpResponse:
    return HttpResponse(status_code=200, text=text, elapsed_ms=elapsed_ms, url="http://x/")


def test_normalize_masks_common_volatiles() -> None:
    out = normalize_body(
        "id 550e8400-e29b-41d4-a716-446655440000 hex deadbeefdeadbeefcafe ts 2026-08-07T10:11:12Z n 1723030272"
    )
    assert "{UUID}" in out and "{HEX}" in out and "{TS}" in out and "{NUM}" in out
    # the volatile literals are gone
    assert "550e8400" not in out and "deadbeefdeadbeef" not in out


def test_normalize_masks_csrf_token_value_but_keeps_structure() -> None:
    html = '<input type="hidden" name="csrf_token" value="Xy91acbz7Q">'
    out = normalize_body(html)
    assert 'name="csrf_token"' in out  # structure kept
    assert "Xy91acbz7Q" not in out and "{TOKEN}" in out  # value masked


def test_normalize_is_stable_for_non_volatile_content() -> None:
    text = "<h1>Bienvenido</h1><p>Panel de control</p>"
    assert normalize_body(text) == text


def test_build_baseline_computes_median_and_jitter() -> None:
    profile = build_baseline([_resp(elapsed_ms=10), _resp(elapsed_ms=14), _resp(elapsed_ms=12)])
    assert profile.expected_ms == 12  # median
    assert profile.jitter_ms == 4  # max - min
    assert profile.primary.elapsed_ms == 10


def test_baseline_stability_and_extra_masks() -> None:
    # Two samples that differ only by an app-specific volatile token -> stable + masked.
    a = _resp(text="<p>hola</p><span>req=abc123def</span>")
    b = _resp(text="<p>hola</p><span>req=zzz999yyy</span>")
    profile = build_baseline([a, b])
    assert profile.extra_masks  # discovered the differing token
    assert profile.stable  # equal once the volatile part is masked


def test_baseline_detects_structural_instability() -> None:
    a = _resp(text="<p>hola</p>")
    b = _resp(text="<p>hola</p><div>anuncio aleatorio distinto cada vez</div>")
    profile = build_baseline([a, b])
    # These differ structurally, not just by a token; not fully maskable -> unstable.
    assert profile.stable is False


def test_time_based_ignores_delay_within_jitter() -> None:
    # A 900ms delay over a noisy target (jitter 400ms -> 3x = 1200ms floor) must NOT fire.
    mutated = _resp(elapsed_ms=1000)
    assert check_time_based(mutated, threshold_ms=800, baseline_ms=100, jitter_ms=400) is None


def test_time_based_fires_when_delay_clears_jitter_and_threshold() -> None:
    mutated = _resp(elapsed_ms=5100)
    ev = check_time_based(mutated, threshold_ms=4500, baseline_ms=100, jitter_ms=50)
    assert ev is not None and ev.type == "time_based"


def test_profile_normalize_uses_discovered_masks() -> None:
    profile = BaselineProfile(responses=[_resp()], expected_ms=5, jitter_ms=0, extra_masks=("SESSION-XYZ",))
    assert "SESSION-XYZ" not in profile.normalize("token=SESSION-XYZ end")
