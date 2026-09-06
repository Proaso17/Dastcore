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
    # Baseline diffing must be bounded now — it only ever looks at the first _MAX_DIFF_LEN chars.
    import time

    from dastcore.core.models import HttpResponse
    from dastcore.validation.baseline import _MAX_DIFF_LEN, build_baseline, similarity_ratio

    def r(text: str) -> HttpResponse:
        return HttpResponse(status_code=200, headers={}, text=text, elapsed_ms=1.0, url="http://x/")

    # Deterministic proof the cap is in effect: two ~1MB bodies that are byte-identical through the
    # first _MAX_DIFF_LEN chars and differ ONLY afterwards must compare as identical — the differing
    # suffix is past the cap, so it is never diffed. (Uncapped, difflib would see the difference and
    # grind over the whole ~1MB, returning a ratio < 1.0 after seconds/minutes of O(n*m) work.)
    shared = "<div class='row'>item</div>\n" * 40000  # ~1.1 MB, well past the cap
    assert len(shared) > _MAX_DIFF_LEN
    big_a = shared + "UNIQUE-AAAAAA" * 500
    big_b = shared + "UNIQUE-BBBBBB" * 500
    t0 = time.perf_counter()
    build_baseline([r(big_a), r(big_b)])
    ratio = similarity_ratio(big_a, big_b)
    elapsed = time.perf_counter() - t0
    assert ratio == 1.0, "diffing looked past _MAX_DIFF_LEN — the cap is not bounding the input"
    # Secondary hang guard, generous so it never flakes on a loaded CI box: a truly unbounded O(n*m)
    # difflib over these ~1MB repetitive bodies takes many seconds to minutes, so any small bound
    # separates "capped" from "hung". The deterministic ratio check above is the real assertion.
    assert elapsed < 15.0, f"baseline diffing took {elapsed:.1f}s — not bounded (would hang the scan)"
