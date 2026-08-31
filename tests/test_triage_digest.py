"""Triage copilot: deterministic cross-host clustering, ranking, and false-positive bucketing.
Downstream of the oracle — it never changes a finding, only reorganises the list."""

from __future__ import annotations

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint
from dastcore.triage.digest import build_digest


def _finding(host: str, *, rule: str = "sqli-injection", family: str = "sqli", severity: str = "high",
             conf: str = "high", name: str = "SQL Injection", param: str = "q") -> Finding:
    req = HttpRequest(method="GET", url=f"http://{host}/search", params={param: "1"})
    point = InjectionPoint(location="query", name=param, base_value="1", request_template=req)
    return Finding(
        id=f"{rule}:{host}:{param}", rule_id=rule, name=name, severity=severity, cwe="CWE-89", owasp="",
        family=family, injection_point=point,
        evidence=[Evidence(type="differential", data="pair differed", confidence=conf)],
        request=req, response=HttpResponse(status_code=500), remediation="x",
    )


def test_same_class_and_point_collapses_across_hosts() -> None:
    findings = [_finding("a.test"), _finding("b.test"), _finding("c.test")]
    digest = build_digest(findings)
    assert len(digest.clusters) == 1
    cluster = digest.priority[0]
    assert cluster.count == 3 and cluster.host_count == 3
    assert cluster.hosts == ["a.test", "b.test", "c.test"]  # sorted, distinct
    assert digest.total_findings == 3 and digest.distinct_hosts == 3


def test_different_rule_or_param_are_separate_clusters() -> None:
    findings = [
        _finding("a.test"),
        _finding("a.test", rule="reflected-xss", family="xss", name="XSS", param="name"),
        _finding("a.test", param="id"),  # same rule, different param -> its own cluster
    ]
    digest = build_digest(findings)
    assert len(digest.clusters) == 3


def test_low_confidence_findings_go_to_the_review_bucket() -> None:
    findings = [
        _finding("a.test"),  # high-confidence sqli -> priority
        _finding("b.test", rule="reflected-xss", family="xss", conf="low", name="weak", param="s"),  # -> review
    ]
    digest = build_digest(findings)
    assert len(digest.priority) == 1 and len(digest.review) == 1
    assert digest.review[0].fp_risk is True and digest.priority[0].fp_risk is False


def test_priority_bucket_is_ranked_most_urgent_first() -> None:
    findings = [
        _finding("a.test", rule="ssrf-cloud-metadata", family="ssrf", severity="critical",
                 name="SSRF metadata", param="url"),
        _finding("b.test"),  # high sqli
    ]
    digest = build_digest(findings)
    assert [c.name for c in digest.priority] == ["SSRF metadata", "SQL Injection"]  # critical first
    assert digest.priority[0].band in ("P1", "P2")


def test_suppressed_findings_are_excluded() -> None:
    f = _finding("a.test")
    f.suppressed = True
    digest = build_digest([f, _finding("b.test")])
    assert digest.total_findings == 1 and digest.clusters[0].host_count == 1


def test_to_dict_is_json_shaped() -> None:
    digest = build_digest([
        _finding("a.test"),
        _finding("b.test", rule="reflected-xss", family="xss", conf="low", param="s"),
    ])
    d = digest.to_dict()
    assert set(d) >= {"total_findings", "distinct_hosts", "cluster_count", "severity_counts", "priority", "review"}
    assert d["cluster_count"] == 2 and d["priority"][0]["host_count"] == 1
