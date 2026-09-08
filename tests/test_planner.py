"""The adaptive scan planner (decision brain): recon signals in a TargetProfile → a prioritised strategy.
Deterministic expert heuristics, so every mapping is pinned down here."""

from __future__ import annotations

from dastcore.analysis.planner import TargetProfile, plan_scan, render_plan


def _families(profile: TargetProfile) -> tuple[str, ...]:
    return plan_scan(profile).priority_families


def test_php_stack_prioritises_injection_and_file_inclusion() -> None:
    fams = _families(TargetProfile(languages=frozenset({"php"})))
    assert fams[:3] == ("sqli", "lfi", "code-injection")


def test_java_stack_prioritises_deserialization_and_log4shell() -> None:
    fams = _families(TargetProfile(languages=frozenset({"java"})))
    assert fams[0] == "deserialization" and "rce" in fams


def test_node_stack_prioritises_nosql_and_prototype_pollution() -> None:
    fams = _families(TargetProfile(languages=frozenset({"node"})))
    assert "nosqli" in fams and "proto_pollution" in fams


def test_wordpress_gets_a_cms_playbook() -> None:
    plan = plan_scan(TargetProfile(cms="wordpress", languages=frozenset({"php"})))
    assert any(i.focus == "WordPress" for i in plan.items)
    assert "wp-json" in render_plan(TargetProfile(cms="wordpress"), plan).lower() or \
        any("wp-json" in i.why for i in plan.items)


def test_spa_turns_on_headless_and_targets_dom_xss() -> None:
    plan = plan_scan(TargetProfile(is_spa=True))
    assert plan.use_headless is True and "xss" in plan.priority_families


def test_rest_api_prioritises_authorization() -> None:
    assert "authz" in _families(TargetProfile(api_kind="rest"))


def test_graphql_gets_graphql_moves() -> None:
    assert "graphql" in _families(TargetProfile(api_kind="graphql"))


def test_login_panel_pushes_authenticated_scanning() -> None:
    plan = plan_scan(TargetProfile(has_login=True))
    assert plan.push_auth is True
    assert {"weak-creds", "jwt", "session"} <= set(plan.priority_families)


def test_supabase_backend_planned() -> None:
    assert any(i.focus == "Supabase" for i in plan_scan(TargetProfile(backend="supabase")).items)


def test_waf_adds_evasion_note() -> None:
    assert any("evasi" in n.lower() for n in plan_scan(TargetProfile(waf=True)).notes)


def test_juicy_subdomains_are_ordered_first() -> None:
    hosts = ("www.t.com", "blog.t.com", "api.t.com", "admin.t.com", "staging.t.com")
    focus = plan_scan(TargetProfile(hosts=hosts)).focus_hosts
    assert focus[:3] == ("api.t.com", "admin.t.com", "staging.t.com")  # juicy first, original order kept
    assert set(focus) == set(hosts)  # nothing dropped


def test_empty_profile_falls_back_to_generic_coverage() -> None:
    plan = plan_scan(TargetProfile())
    assert plan.items and plan.items[0].focus == "Genérico"
    assert "sqli" in plan.priority_families


def test_render_plan_is_readable_and_names_the_moves() -> None:
    profile = TargetProfile(tech=frozenset({"WordPress", "PHP"}), cms="wordpress",
                            languages=frozenset({"php"}), has_login=True)
    text = render_plan(profile, plan_scan(profile))
    assert "WordPress" in text and "Plan" in text and "login" in text.lower()
