"""CAPEC attack-pattern knowledge layer for the planner brain: prerequisites → applicable patterns →
likelihood-weighted, CAPEC-cited family votes. Deterministic, evidence-driven, and never perturbs the
stack-prior rankings (the design rule that keeps zero-FP + the existing planner behaviour intact)."""

from __future__ import annotations

import re

from dastcore.analysis.capec import (
    _CAPEC_FAMILY_CAP,
    _CATALOG,
    KNOWN_FAMILIES,
    applicable_patterns,
    capec_family_votes,
)
from dastcore.analysis.planner import (
    TargetProfile,
    plan_areas,
    plan_hosts,
    plan_scan,
    render_plan,
)

_CAPEC_ID = re.compile(r"^CAPEC-\d+$")
_CWE_ID = re.compile(r"^CWE-\d+$")


def test_catalogue_integrity() -> None:
    """Every entry is well-formed and aligned with the scanner: real-shaped CAPEC id, known family, valid
    likelihood/severity, CWE-shaped weaknesses, unique ids."""
    seen: set[str] = set()
    for ap in _CATALOG:
        assert _CAPEC_ID.match(ap.capec_id), ap.capec_id
        assert ap.capec_id not in seen, f"duplicate {ap.capec_id}"
        seen.add(ap.capec_id)
        assert ap.family in KNOWN_FAMILIES, f"{ap.capec_id} drives unknown family {ap.family}"
        assert ap.likelihood in ("high", "medium", "low")
        assert ap.severity in ("very high", "high", "medium", "low")
        assert ap.cwes and all(_CWE_ID.match(c) for c in ap.cwes)
        assert ap.why.strip()


def test_families_used_are_exactly_the_declared_set() -> None:
    assert {ap.family for ap in _CATALOG} == KNOWN_FAMILIES  # no drift between catalogue and its guard set


def test_bare_stack_prior_yields_no_capec_patterns() -> None:
    """The design rule: CAPEC fires on OBSERVED prerequisites, never a language prior alone — so it can't
    perturb the stack-prior rankings the planner already computes."""
    php = TargetProfile(languages=frozenset({"php"}))
    assert applicable_patterns(php) == []
    assert capec_family_votes(php) == []


def test_sql_injection_applies_on_observed_query_surface() -> None:
    ids = {ap.capec_id for ap in applicable_patterns(TargetProfile(param_names=frozenset({"search"})))}
    assert "CAPEC-66" in ids  # a query param → SQL Injection applies
    assert "CAPEC-66" in {ap.capec_id for ap in applicable_patterns(TargetProfile(api_kind="rest"))}


def test_path_traversal_and_ssrf_and_idor_prerequisites() -> None:
    trav = {ap.capec_id for ap in applicable_patterns(TargetProfile(param_names=frozenset({"file"})))}
    assert "CAPEC-126" in trav  # file/path param → Path Traversal
    ssrf = {ap.capec_id for ap in applicable_patterns(TargetProfile(param_names=frozenset({"callback_url"})))}
    assert "CAPEC-664" in ssrf  # url/callback param → SSRF
    ssrf_next = {ap.capec_id for ap in applicable_patterns(TargetProfile(frameworks=frozenset({"nextjs"})))}
    assert "CAPEC-664" in ssrf_next  # Next.js image optimizer → SSRF applies even without a url param
    idor = {ap.capec_id for ap in applicable_patterns(TargetProfile(backend="supabase"))}
    assert "CAPEC-77" in idor  # per-object backend → IDOR/BOLA applies


def test_login_panel_unlocks_the_auth_patterns() -> None:
    ids = {ap.capec_id for ap in applicable_patterns(TargetProfile(has_login=True))}
    assert {"CAPEC-49", "CAPEC-115", "CAPEC-593", "CAPEC-62"} <= ids  # brute force, auth bypass, session, CSRF


def test_votes_are_capped_and_cite_the_capec_ids() -> None:
    # A target that triggers several access-control patterns (CAPEC-1/77/87…) must not let authz run away.
    profile = TargetProfile(
        api_kind="rest", backend="supabase", has_login=True,
        paths=frozenset({"/admin/users", "/orders/1"}), param_names=frozenset({"id", "account"}),
    )
    votes = {fam: (w, reason) for fam, w, reason in capec_family_votes(profile)}
    assert "authz" in votes
    weight, reason = votes["authz"]
    assert weight <= _CAPEC_FAMILY_CAP  # capped so a family with many patterns can't swamp the score
    assert "CAPEC-" in reason  # the reasoning cites the attack patterns


def test_plan_scan_integrates_capec_without_disturbing_stack_priors() -> None:
    # Bare PHP: unchanged (no CAPEC) — the exact score/order the planner tests pin down.
    bare = plan_scan(TargetProfile(languages=frozenset({"php"})))
    assert bare.attack_patterns == [] and bare.family_scores.get("sqli") == 4.0
    # Evidence-rich: CAPEC patterns attach and the reasoning cites them.
    rich = plan_scan(TargetProfile(api_kind="rest", has_login=True, param_names=frozenset({"id", "file"})))
    assert rich.attack_patterns  # the applicable attack catalogue is exposed
    assert any("CAPEC-" in line for line in rich.reasoning)  # the visible thinking cites CAPEC
    text = render_plan(TargetProfile(api_kind="rest", has_login=True, param_names=frozenset({"id"})), rich)
    assert "CAPEC" in text  # the plan renders the applicable attack patterns + how to work them


def test_capec_reinforces_an_observed_family_ranking() -> None:
    # An observed url param should rank SSRF; CAPEC-664 reinforces it (present in scores + reasoning).
    plan = plan_scan(TargetProfile(param_names=frozenset({"redirect_url"})))
    assert "ssrf" in plan.family_scores
    assert any("CAPEC-664" in line for line in plan.reasoning)


def test_areas_cite_their_applicable_capec_patterns() -> None:
    profile = TargetProfile(
        has_login=True, api_kind="rest", param_names=frozenset({"id"}),
        paths=frozenset({"/admin/users", "/orders/1"}),
    )
    areas = {a.name: a for a in plan_areas(profile)}
    auth = next(a for n, a in areas.items() if "Autenticación" in n)
    assert any("CAPEC-49" in c or "CAPEC-593" in c for c in auth.capec)  # brute force / session on the auth zone
    assert any("CAPEC-1" in c or "CAPEC-66" in c for c in areas["API"].capec)  # ACL / SQLi on the API zone


def test_host_plans_cite_capec_per_role() -> None:
    from dastcore.analysis.capec import applicable_patterns

    profile = TargetProfile(
        has_login=True, api_kind="rest", param_names=frozenset({"id"}), backend="supabase",
        hosts=("admin.acme.com", "api.acme.com"),
    )
    patterns = tuple(applicable_patterns(profile))
    by_host = {hp.host: hp for hp in plan_hosts(profile.hosts, ("sqli",), patterns)}
    assert any("CAPEC-" in c for c in by_host["admin.acme.com"].capec)  # admin (authz/weak-creds) cites patterns
    assert any("CAPEC-77" in c or "CAPEC-1" in c for c in by_host["api.acme.com"].capec)  # api authz patterns


def test_render_shows_capec_per_zone() -> None:
    profile = TargetProfile(has_login=True, api_kind="rest", hosts=("admin.acme.com", "api.acme.com"))
    text = render_plan(profile, plan_scan(profile))
    assert "CAPEC:" in text  # the per-area / per-host CAPEC citations are rendered


def test_plan_hosts_without_patterns_has_no_capec() -> None:
    # Back-compat: called without the patterns arg (as the existing planner tests do), hosts carry no CAPEC.
    plans = plan_hosts(("admin.acme.com", "www.acme.com"), ("sqli",))
    assert all(hp.capec == () for hp in plans)
