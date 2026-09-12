"""Audit-queue prioritisation: the highest-value requests are scanned first so a time/request budget is
spent on the juiciest targets. Higher score = more (rare) attack surface + more inherent interest."""

from __future__ import annotations

from types import SimpleNamespace

from dastcore.core.models import HttpRequest
from dastcore.engine.prioritize import prioritize_requests, prioritize_rules, score_requests


def test_juicy_requests_sort_before_boilerplate() -> None:
    reqs = [
        HttpRequest(method="GET", url="http://t/style.css"),                                    # no params
        HttpRequest(method="GET", url="http://t/list?page=1", params={"page": "1"}),            # common param
        HttpRequest(method="POST", url="http://t/login", json_body={"user": "a", "password": "b"}),  # juicy
        HttpRequest(method="GET", url="http://t/go?redirect=x&id=5", params={"redirect": "x", "id": "5"}),
    ]
    ordered = [r.url for r in prioritize_requests(reqs)]
    assert ordered[0].endswith("/login")          # state-changing + injectable names first
    assert ordered[-1].endswith("/style.css")     # zero attack surface last
    assert ordered.index("http://t/go?redirect=x&id=5") < ordered.index("http://t/list?page=1")


def test_rare_parameters_outrank_common_ones() -> None:
    # 'page' appears on many requests (boilerplate); 'ssrf_url' is unique (expands attack surface).
    common = [HttpRequest(method="GET", url=f"http://t/p{i}?page=1", params={"page": "1"}) for i in range(5)]
    unique = HttpRequest(method="GET", url="http://t/fetch?ssrf_url=x", params={"ssrf_url": "x"})
    reqs = [*common, unique]
    assert prioritize_requests(reqs)[0] is unique


def test_prioritisation_is_stable_on_ties() -> None:
    # Two identical-shape requests keep their original discovery order.
    a = HttpRequest(method="GET", url="http://t/a?x=1", params={"x": "1"})
    b = HttpRequest(method="GET", url="http://t/b?x=1", params={"x": "1"})
    ordered = prioritize_requests([a, b])
    assert ordered[0] is a and ordered[1] is b


def test_scores_align_with_order() -> None:
    reqs = [
        HttpRequest(method="GET", url="http://t/x"),
        HttpRequest(method="POST", url="http://t/y", data={"cmd": "ls"}),
    ]
    scores = score_requests(reqs)
    assert scores[1] > scores[0]  # the POST with an injectable 'cmd' param scores higher


# --- adaptive planner steer: boost the target's priority families -----------------------------------


def test_priority_family_pulls_its_request_forward() -> None:
    # 'view' hints at file inclusion but isn't in the generic interesting-name set, and 'menu' matches
    # neither — so without a plan they tie on surface+interest and keep their order. Tell the planner the
    # target is PHP (lfi a priority) and the file-inclusion-shaped request must audit first.
    lfi = HttpRequest(method="GET", url="http://t/a?view=x", params={"view": "x"})
    other = HttpRequest(method="GET", url="http://t/b?menu=x", params={"menu": "x"})
    assert prioritize_requests([other, lfi])[0] is other  # no plan → stable, original order
    assert prioritize_requests([other, lfi], ("lfi",))[0] is lfi  # plan → lfi request jumps ahead


def test_family_boost_is_ranked_top_family_wins() -> None:
    # A redirect-shaped request and a sqli-shaped request, each with a unique param (tied on surface).
    redirect = HttpRequest(method="GET", url="http://t/go?redirect=x", params={"redirect": "x"})
    sqli = HttpRequest(method="GET", url="http://t/p?category=x", params={"category": "x"})
    # Planner ranks open_redirect above sqli → the redirect request sorts first.
    ordered = prioritize_requests([sqli, redirect], ("open_redirect", "sqli"))
    assert ordered[0] is redirect
    # Flip the priority and the order flips too — the steer, not the shape, decides.
    assert prioritize_requests([sqli, redirect], ("sqli", "open_redirect"))[0] is sqli


def test_empty_priority_families_leaves_scores_unchanged() -> None:
    reqs = [
        HttpRequest(method="GET", url="http://t/a?file=x", params={"file": "x"}),
        HttpRequest(method="POST", url="http://t/y", data={"cmd": "ls"}),
    ]
    assert score_requests(reqs) == score_requests(reqs, ())  # no plan → identical scoring


def test_prioritize_rules_puts_priority_families_first() -> None:
    rules = [
        SimpleNamespace(id="xss", family="xss"),
        SimpleNamespace(id="sqli", family="sqli"),
        SimpleNamespace(id="lfi", family="lfi"),
        SimpleNamespace(id="crlf", family="crlf"),
    ]
    ordered = [r.id for r in prioritize_rules(rules, ("lfi", "sqli"))]
    assert ordered[:2] == ["lfi", "sqli"]            # priority families first, in plan order
    assert ordered[2:] == ["xss", "crlf"]            # the rest keep their original relative order


def test_prioritize_rules_is_stable_within_a_family() -> None:
    # Three sqli rules (sqli.yaml, sqli_boolean.yaml, sqli_oob.yaml style) must keep their original order.
    rules = [
        SimpleNamespace(id="sqli-error", family="sqli"),
        SimpleNamespace(id="xss", family="xss"),
        SimpleNamespace(id="sqli-bool", family="sqli"),
        SimpleNamespace(id="sqli-oob", family="sqli"),
    ]
    ordered = [r.id for r in prioritize_rules(rules, ("sqli",))]
    assert ordered == ["sqli-error", "sqli-bool", "sqli-oob", "xss"]


def test_prioritize_rules_no_plan_is_identity() -> None:
    rules = [SimpleNamespace(id="a", family="xss"), SimpleNamespace(id="b", family="sqli")]
    assert prioritize_rules(rules, ()) == rules


def test_scanner_orders_its_rules_by_priority_families() -> None:
    # The wiring: a Scanner built with the planner's priority families attacks them first per request.
    from dastcore.engine.rule_engine import Rule
    from dastcore.engine.scanner import Scanner
    from dastcore.validation.oracles import OracleCheck, OracleSpec

    def _rule(rid: str, family: str) -> Rule:
        return Rule(
            id=rid, name=rid, family=family, severity="high", cwe="CWE-0", owasp="T-0",
            inject_into=["query"], payloads=["x"],
            oracle=OracleSpec(type="any_of", checks=[OracleCheck(type="response_match", part="body", patterns=["z"])]),
            remediation="n/a",
        )

    rules = [_rule("xss", "xss"), _rule("sqli", "sqli"), _rule("lfi", "lfi")]
    scanner = Scanner(object(), rules, priority_families=("lfi", "sqli"))
    assert [r.family for r in scanner._rules][:2] == ["lfi", "sqli"]  # noqa: SLF001 — asserting the steer


def test_scanner_reprioritize_swaps_the_steer_mid_plan() -> None:
    # Adaptive re-planning: the brain revises priorities before the active scan; reprioritize() re-orders
    # the rules and updates the intensity set from the ORIGINAL rule order (not the already-sorted one).
    from dastcore.engine.rule_engine import Rule
    from dastcore.engine.scanner import Scanner
    from dastcore.validation.oracles import OracleCheck, OracleSpec

    def _rule(fam: str) -> Rule:
        return Rule(
            id=fam, name=fam, family=fam, severity="high", cwe="CWE-0", owasp="T-0",
            inject_into=["query"], payloads=["x"],
            oracle=OracleSpec(type="any_of", checks=[OracleCheck(type="response_match", part="body", patterns=["z"])]),
            remediation="n/a",
        )

    scanner = Scanner(object(), [_rule("xss"), _rule("sqli"), _rule("lfi")], priority_families=("xss",))
    assert [r.family for r in scanner._rules][0] == "xss"  # noqa: SLF001
    scanner.reprioritize(("lfi", "sqli"))  # recon revealed file/id params → revise
    assert [r.family for r in scanner._rules][:2] == ["lfi", "sqli"]  # noqa: SLF001 — re-ordered from base
    assert scanner._priority_families == ("lfi", "sqli") and scanner._is_priority("lfi")  # noqa: SLF001
