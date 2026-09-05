"""response_match must only fire on a signal the payload *introduced*: a marker already present in the
unmutated baseline is part of the page, not proof the injection landed. This killed the ldap/xpath false
positives on bWAPP, whose bug-picker lists "LDAP Injection"/"XPATH Injection" on every page."""

from __future__ import annotations

from dastcore.core.models import HttpResponse
from dastcore.validation.oracles import check_response_match


def _resp(text: str) -> HttpResponse:
    return HttpResponse(status_code=200, headers={}, text=text, url="http://x/y")


def test_marker_already_in_baseline_is_suppressed() -> None:
    base = _resp("<option>LDAP Injection</option><option>XPATH Injection</option>")
    mutated = _resp("<option>LDAP Injection</option> results...")  # same 'LDAP' from the menu, not an error
    assert check_response_match(mutated, [r"LDAP(?:Error|Exception)?"], "body", base_response=base) is None


def test_marker_introduced_by_payload_still_fires() -> None:
    base = _resp("<option>LDAP Injection</option> normal page")  # menu label only
    mutated = _resp("javax.naming.directory error: LDAPException: bad search filter")  # a real error appears
    ev = check_response_match(mutated, [r"LDAP(?:Error|Exception)\b"], "body", base_response=base)
    assert ev is not None and "LDAPException" in ev.data


def test_without_baseline_behaviour_is_unchanged() -> None:
    mutated = _resp("You have an error in your SQL syntax")
    assert check_response_match(mutated, [r"SQL syntax"], "body") is not None  # no base_response -> as before


def test_echoed_payload_is_still_skipped() -> None:
    # The pre-existing reflection guard: a match that is only the echoed payload isn't a server signal.
    mutated = _resp("your input was: SQL syntax")
    assert check_response_match(mutated, [r"SQL syntax"], "body", payload="SQL syntax") is None


def test_baseline_diffing_is_bounded_on_large_bodies() -> None:
    # Regression (bWAPP): difflib over full large bodies with autojunk off froze the whole scan.
    # Baseline diffing must be bounded now — a ~1MB mostly-repetitive HTML body profiles near-instantly.
    import time

    from dastcore.core.models import HttpResponse
    from dastcore.validation.baseline import build_baseline, similarity_ratio

    def r(text: str) -> HttpResponse:
        return HttpResponse(status_code=200, headers={}, text=text, elapsed_ms=1.0, url="http://x/")

    big_a = "<div class='row'>item</div>\n" * 40000 + "sid-AAAAAA"  # ~1.1 MB
    big_b = "<div class='row'>item</div>\n" * 40000 + "sid-BBBBBB"
    t0 = time.perf_counter()
    build_baseline([r(big_a), r(big_b)])
    similarity_ratio(big_a, big_b)
    elapsed = time.perf_counter() - t0
    assert elapsed < 3.0, f"baseline diffing took {elapsed:.1f}s — not bounded (would hang the scan)"
