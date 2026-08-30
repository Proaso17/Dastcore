from __future__ import annotations

from dastcore.core.models import HttpRequest, InjectionPoint
from dastcore.engine.rule_engine import DEFAULT_RULES_DIR, Rule, applicable_payloads, build_mutated_request, load_rules
from dastcore.validation.oracles import OracleCheck, OracleSpec


def test_load_rules_loads_all_shipped_rule_files() -> None:
    rules = load_rules()
    ids = {rule.id for rule in rules}
    in_band = {"sqli-injection", "xss-reflected", "open-redirect", "path-traversal-lfi", "ssti-inband", "nosqli-error"}
    oob = {"ssrf-oob", "cmdi-oob", "ssti-oob", "xxe-oob", "crlf-oob", "log4shell-jndi"}
    header = {"host-header-injection", "log4shell-jndi"}
    assert in_band <= ids
    assert oob <= ids
    assert all("header" in {r.id: r for r in rules}[rid].inject_into for rid in header)


def test_build_mutated_request_header() -> None:
    request = HttpRequest(method="GET", url="http://x/reset", headers={"User-Agent": "orig"})
    point = InjectionPoint(location="header", name="Host", base_value="x", request_template=request)
    mutated = build_mutated_request(point, "evil.test")
    assert mutated.headers == {"User-Agent": "orig", "Host": "evil.test"}
    assert request.headers == {"User-Agent": "orig"}  # original untouched


def test_oob_rules_are_flagged_and_in_band_rules_are_not() -> None:
    rules = {rule.id: rule for rule in load_rules()}
    assert rules["ssrf-oob"].is_oob is True
    assert rules["cmdi-oob"].is_oob is True
    assert rules["sqli-injection"].is_oob is False
    assert rules["xss-reflected"].is_oob is False


def test_shipped_rules_directory_matches_default() -> None:
    assert DEFAULT_RULES_DIR.is_dir()
    assert (DEFAULT_RULES_DIR / "sqli.yaml").exists()


def test_sqli_rule_has_expected_shape() -> None:
    rules = {rule.id: rule for rule in load_rules()}
    sqli = rules["sqli-injection"]
    assert sqli.severity == "high"
    assert sqli.cwe == "CWE-89"
    assert "query" in sqli.inject_into
    assert sqli.confirm_reproducible is True
    assert sqli.remediation


def test_sqli_rule_detects_orm_hql_errors_without_false_positives() -> None:
    # ORM/HQL injection (Hibernate/NHibernate/JPA) surfaces as query-layer exception class names.
    from dastcore.core.models import HttpResponse
    from dastcore.validation.oracles import check_response_match

    rules = {rule.id: rule for rule in load_rules()}
    patterns = [p for check in rules["sqli-injection"].oracle.checks
                if check.type == "response_match" for p in check.patterns]

    def body(text: str) -> HttpResponse:
        return HttpResponse(status_code=500, headers={}, text=text, elapsed_ms=5.0, url="http://x/")

    for hql in (
        "org.hibernate.QueryException: unexpected token near '''",
        "org.hibernate.hql.internal.ast.QuerySyntaxException: unexpected end of subtree",
        "NHibernate.Hql.Ast.ANTLR.QuerySyntaxException",
        "jakarta.persistence.PersistenceException: could not parse query",
    ):
        assert check_response_match(body(hql), patterns, part="body") is not None, hql
    for benign in ("Welcome back!", "Unexpected token < in JSON at position 0", "persistence layer unavailable"):
        assert check_response_match(body(benign), patterns, part="body") is None, benign


def test_applicable_payloads_includes_declared_and_rendered_time_based() -> None:
    rule = Rule(
        id="r",
        name="R",
        family="f",
        severity="high",
        cwe="CWE-0",
        owasp="X",
        inject_into=["query"],
        payloads=["a", "b"],
        oracle=OracleSpec(
            type="any_of",
            checks=[OracleCheck(type="time_based", payload="SLEEP({{delay}})", delay=5, threshold_ms=1000)],
        ),
        remediation="fix it",
    )
    payloads = [p.value for p in applicable_payloads(rule)]
    assert payloads == ["a", "b", "SLEEP(5)"]
    assert all(p.family == "f" and p.oob is False for p in applicable_payloads(rule))


def test_applicable_payloads_dedups_rendered_payload_already_declared() -> None:
    rule = Rule(
        id="r",
        name="R",
        family="f",
        severity="high",
        cwe="CWE-0",
        owasp="X",
        inject_into=["query"],
        payloads=["SLEEP(5)"],
        oracle=OracleSpec(
            type="any_of",
            checks=[OracleCheck(type="time_based", payload="SLEEP({{delay}})", delay=5, threshold_ms=1000)],
        ),
        remediation="fix it",
    )
    payloads = [p.value for p in applicable_payloads(rule)]
    assert payloads == ["SLEEP(5)"]


def test_build_mutated_request_query() -> None:
    request = HttpRequest(method="GET", url="http://x/search", params={"q": "demo"})
    point = InjectionPoint(location="query", name="q", base_value="demo", request_template=request)
    mutated = build_mutated_request(point, "'")
    assert mutated.params == {"q": "'"}
    assert request.params == {"q": "demo"}  # original untouched


def test_build_mutated_request_body() -> None:
    request = HttpRequest(method="POST", url="http://x/login", data={"username": "bob", "password": "x"})
    point = InjectionPoint(location="body", name="username", base_value="bob", request_template=request)
    mutated = build_mutated_request(point, "' OR '1'='1")
    assert mutated.data == {"username": "' OR '1'='1", "password": "x"}
    assert request.data == {"username": "bob", "password": "x"}


def test_build_mutated_request_json() -> None:
    request = HttpRequest(method="POST", url="http://x/api", json_body={"id": "1", "name": "x"})
    point = InjectionPoint(location="json", name="id", base_value="1", request_template=request)
    mutated = build_mutated_request(point, "1 OR 1=1")
    assert mutated.json_body == {"id": "1 OR 1=1", "name": "x"}
    assert request.json_body == {"id": "1", "name": "x"}


def test_build_mutated_request_only_touches_targeted_param() -> None:
    request = HttpRequest(method="GET", url="http://x/search", params={"q": "demo", "page": "1"})
    point = InjectionPoint(location="query", name="q", base_value="demo", request_template=request)
    mutated = build_mutated_request(point, "'")
    assert mutated.params["page"] == "1"
