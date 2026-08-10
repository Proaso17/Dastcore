from __future__ import annotations

from dastcore.core.models import HttpResponse
from dastcore.validation.oracles import (
    OracleCheck,
    OracleSpec,
    check_differential,
    check_open_redirect,
    check_reflected,
    check_response_match,
    check_time_based,
    evaluate_oracle,
)

_PROBE = "https://dastcore-redirect-probe.invalid/"


def _response(**overrides) -> HttpResponse:
    defaults = {"status_code": 200, "headers": {}, "text": "", "elapsed_ms": 5.0, "url": "http://x/"}
    defaults.update(overrides)
    return HttpResponse(**defaults)


def test_check_response_match_finds_pattern_in_body() -> None:
    response = _response(text="oops: SQLite3::error near: bad token")
    evidence = check_response_match(response, ["SQLite3::error"], part="body")
    assert evidence is not None
    assert evidence.type == "response_match"
    assert evidence.confidence == "high"


def test_check_response_match_returns_none_when_no_pattern_matches() -> None:
    response = _response(text="all good here")
    assert check_response_match(response, ["SQLite3::error", "Traceback"], part="body") is None


def test_check_response_match_ignores_echoed_payload() -> None:
    # An API 422 that echoes our payload — the pattern matched the reflection, not a
    # server signal, so it must NOT fire.
    response = _response(text='{"detail":"invalid input","input":"x $where y"}')
    assert check_response_match(response, ["\\$where"], part="body", payload="a $where b") is None
    # But a genuine server error (not contained in the payload) still fires.
    server_err = _response(text="MongoError: unknown top level operator near 'x'")
    assert check_response_match(server_err, ["MongoError"], part="body", payload="{$ne:1}") is not None
    # In headers, an echoed payload IS the signal (open redirect via Location), so it fires.
    redir = _response(headers={"Location": "https://evil.example/"})
    assert check_response_match(redir, ["evil\\.example"], part="headers", payload="https://evil.example/") is not None


def test_open_redirect_fires_when_probe_is_the_target_host() -> None:
    resp = _response(status_code=302, headers={"Location": _PROBE})
    ev = check_open_redirect(resp, _PROBE)
    assert ev is not None and ev.confidence == "high"


def test_open_redirect_ignores_probe_reflected_in_same_origin_query_param() -> None:
    # The classic false positive: the probe appears in Location, but as a "next=" param of
    # a same-origin path — the browser stays on this host, so it is NOT an open redirect.
    resp = _response(status_code=302, headers={"Location": f"/login?next={_PROBE}"})
    assert check_open_redirect(resp, _PROBE) is None


def test_open_redirect_ignores_probe_as_a_subdomain_lookalike() -> None:
    # A different host that merely contains the probe string must not match (exact host).
    resp = _response(status_code=302, headers={"Location": "https://dastcore-redirect-probe.invalid.evil.com/"})
    assert check_open_redirect(resp, _PROBE) is None


def test_open_redirect_handles_protocol_relative_and_backslash_bypass() -> None:
    assert check_open_redirect(_response(headers={"Location": "//dastcore-redirect-probe.invalid/"}), _PROBE)
    assert check_open_redirect(_response(headers={"Location": "https:/\\dastcore-redirect-probe.invalid/"}), _PROBE)


def test_open_redirect_reads_the_refresh_header_target() -> None:
    resp = _response(headers={"Refresh": f"0; url={_PROBE}"})
    assert check_open_redirect(resp, _PROBE) is not None


def test_open_redirect_none_without_a_redirect_header() -> None:
    assert check_open_redirect(_response(text=_PROBE), _PROBE) is None  # in body, not a redirect


def test_check_response_match_searches_headers_when_requested() -> None:
    response = _response(headers={"Location": "https://evil.example/"})
    evidence = check_response_match(response, ["evil\\.example"], part="headers")
    assert evidence is not None


def test_check_reflected_detects_exact_payload() -> None:
    response = _response(text="<h1>Hello <script>alert(1)</script></h1>")
    evidence = check_reflected(response, "<script>alert(1)</script>")
    assert evidence is not None
    assert evidence.type == "reflected"


def test_check_reflected_none_when_payload_absent_or_empty() -> None:
    response = _response(text="<h1>Hello world</h1>")
    assert check_reflected(response, "<script>alert(1)</script>") is None
    assert check_reflected(response, "") is None


def test_check_differential_flags_new_server_error() -> None:
    base = _response(status_code=200)
    mutated = _response(status_code=500)
    evidence = check_differential(base, mutated)
    assert evidence is not None
    assert "200" in evidence.data and "500" in evidence.data


def test_check_differential_ignores_when_base_already_errored() -> None:
    base = _response(status_code=500)
    mutated = _response(status_code=500)
    assert check_differential(base, mutated) is None


def test_check_time_based_flags_slow_response_above_threshold() -> None:
    mutated = _response(elapsed_ms=3000.0)
    evidence = check_time_based(mutated, threshold_ms=2500.0, baseline_ms=10.0)
    assert evidence is not None
    assert evidence.type == "time_based"


def test_check_time_based_ignores_fast_response() -> None:
    mutated = _response(elapsed_ms=50.0)
    assert check_time_based(mutated, threshold_ms=2500.0, baseline_ms=10.0) is None


def test_evaluate_oracle_any_of_short_circuits_on_first_match() -> None:
    oracle = OracleSpec(
        type="any_of",
        checks=[
            OracleCheck(type="response_match", part="body", patterns=["MATCH_ME"]),
            OracleCheck(type="reflected"),
        ],
    )
    base = _response(text="clean")
    mutated = _response(text="contains MATCH_ME here")
    evidence = evaluate_oracle(oracle, base_response=base, mutated_response=mutated, payload="whatever")
    assert len(evidence) == 1


def test_evaluate_oracle_any_of_returns_empty_when_nothing_matches() -> None:
    oracle = OracleSpec(type="any_of", checks=[OracleCheck(type="response_match", part="body", patterns=["NOPE"])])
    base = _response(text="clean")
    mutated = _response(text="still clean")
    assert evaluate_oracle(oracle, base_response=base, mutated_response=mutated, payload="x") == []


def test_evaluate_oracle_all_of_requires_every_check() -> None:
    oracle = OracleSpec(
        type="all_of",
        checks=[
            OracleCheck(type="response_match", part="body", patterns=["MATCH_ME"]),
            OracleCheck(type="reflected"),
        ],
    )
    base = _response(text="clean")
    # matches response_match but payload isn't reflected -> all_of must fail entirely
    mutated = _response(text="contains MATCH_ME here")
    assert evaluate_oracle(oracle, base_response=base, mutated_response=mutated, payload="my-payload") == []

    # matches both -> all_of succeeds with both pieces of evidence
    mutated_both = _response(text="contains MATCH_ME and my-payload")
    evidence = evaluate_oracle(oracle, base_response=base, mutated_response=mutated_both, payload="my-payload")
    assert len(evidence) == 2
