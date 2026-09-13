"""The adaptive scan planner (decision brain): recon signals in a TargetProfile → a prioritised strategy.
Deterministic expert heuristics, so every mapping is pinned down here."""

from __future__ import annotations

from dastcore.analysis.planner import (
    TargetProfile,
    plan_areas,
    plan_hosts,
    plan_recon,
    plan_scan,
    render_plan,
)


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


# --- richer analysis + confidence scoring (the improved brain) --------------------------------------


def test_observed_params_outrank_the_language_prior() -> None:
    # Pure PHP prioritises SQLi; but if recon actually saw file-inclusion-shaped params, evidence wins.
    base = _families(TargetProfile(languages=frozenset({"php"})))
    assert base[0] == "sqli"
    fams = _families(TargetProfile(languages=frozenset({"php"}), param_names=frozenset({"file", "path"})))
    assert fams.index("lfi") < fams.index("sqli")  # observed file/path params push LFI above the SQLi prior


def test_framework_playbook_adds_its_families_and_note() -> None:
    plan = plan_scan(TargetProfile(frameworks=frozenset({"spring"})))
    assert "rce" in plan.priority_families and "ssrf" in plan.priority_families
    assert any("Spring" in n or "Log4Shell" in n for n in plan.notes)


def test_auth_kind_jwt_prioritises_jwt_attacks() -> None:
    plan = plan_scan(TargetProfile(auth_kind="jwt"))
    assert "jwt" in plan.priority_families
    assert any("JWT" in n for n in plan.notes)


def test_hardened_posture_steers_to_authz_lax_to_injection() -> None:
    hardened = plan_scan(TargetProfile(security_posture="hardened"))
    assert "authz" in hardened.priority_families and any("endurecida" in n for n in hardened.notes)
    lax = plan_scan(TargetProfile(security_posture="lax"))
    assert "sqli" in lax.priority_families and any("laxa" in n for n in lax.notes)


def test_file_upload_signal_is_planned() -> None:
    plan = plan_scan(TargetProfile(has_file_upload=True))
    assert "upload" in plan.priority_families and any(i.focus == "Subida de ficheros" for i in plan.items)


def test_plan_exposes_scores_and_a_reasoning_trace() -> None:
    plan = plan_scan(TargetProfile(languages=frozenset({"php"})))
    assert plan.family_scores.get("sqli") == 4.0                      # the transparent confidence score
    assert plan.reasoning and plan.reasoning[0].startswith("sqli")    # the visible "thinking" cites evidence
    assert "stack php" in plan.reasoning[0]


def test_waf_vendor_and_secrets_surface_as_notes() -> None:
    plan = plan_scan(TargetProfile(waf=True, waf_vendor="cloudflare", exposed_secrets=True))
    assert any("cloudflare" in n.lower() for n in plan.notes)
    assert any("Secretos" in n for n in plan.notes)


# --- per-host / per-area planning (the brain tailors strategy to each host's role) ------------------


def test_plan_hosts_classifies_roles_and_blends_global_families() -> None:
    hosts = ("admin.acme.com", "api.acme.com", "staging.acme.com", "www.acme.com", "git.acme.com")
    by_host = {hp.host: hp for hp in plan_hosts(hosts, global_families=("sqli",))}
    assert by_host["admin.acme.com"].role == "admin" and "authz" in by_host["admin.acme.com"].families
    assert by_host["api.acme.com"].role == "api" and "mass_assignment" in by_host["api.acme.com"].families
    assert by_host["staging.acme.com"].role == "staging"
    assert by_host["git.acme.com"].role == "devops" and "weak-creds" in by_host["git.acme.com"].families
    assert by_host["www.acme.com"].role == "web"
    assert "sqli" in by_host["www.acme.com"].families  # the target's global priorities are blended in


def test_plan_scan_attaches_per_host_plans_for_a_multi_role_surface() -> None:
    plan = plan_scan(TargetProfile(hosts=("admin.acme.com", "www.acme.com")))
    roles = {hp.host: hp.role for hp in plan.host_plans}
    assert roles.get("admin.acme.com") == "admin" and roles.get("www.acme.com") == "web"


def test_single_plain_host_gets_no_split_but_a_juicy_one_does() -> None:
    assert plan_scan(TargetProfile(hosts=("www.acme.com",))).host_plans == []   # nothing to split
    juicy = plan_scan(TargetProfile(hosts=("admin.acme.com",)))
    assert juicy.host_plans and juicy.host_plans[0].role == "admin"             # a lone admin host still planned


def test_render_shows_the_per_host_plan() -> None:
    profile = TargetProfile(hosts=("admin.acme.com", "api.acme.com"))
    text = render_plan(profile, plan_scan(profile))
    assert "Plan por host" in text and "[admin]" in text and "[api]" in text


# --- reconnaissance planning (the brain decides HOW to recon, not just how to attack) ---------------


def test_recon_spa_uses_headless_and_mines_js() -> None:
    recon = plan_recon(TargetProfile(is_spa=True))
    assert recon.use_headless and recon.extract_js_endpoints


def test_recon_api_hunts_schema_and_mines_params() -> None:
    recon = plan_recon(TargetProfile(api_kind="rest"))
    assert recon.discover_api_schemas and recon.mine_params
    assert any("openapi" in p or "swagger" in p for p in recon.probe_paths)


def test_recon_graphql_probes_graphql_endpoints() -> None:
    recon = plan_recon(TargetProfile(api_kind="graphql"))
    assert recon.discover_api_schemas and "/graphql" in recon.probe_paths


def test_recon_framework_and_cms_probe_high_signal_paths() -> None:
    assert "/actuator" in plan_recon(TargetProfile(frameworks=frozenset({"spring"}))).probe_paths
    assert "/.env" in plan_recon(TargetProfile(frameworks=frozenset({"laravel"}))).probe_paths
    assert "/wp-json/wp/v2/users" in plan_recon(TargetProfile(cms="wordpress")).probe_paths


def test_recon_depth_scales_with_surface() -> None:
    big = plan_recon(TargetProfile(hosts=tuple(f"h{i}.acme.com" for i in range(6)), endpoint_count=80))
    small = plan_recon(TargetProfile(hosts=("only.acme.com",), endpoint_count=3))
    assert big.depth == "aggressive" and small.depth == "light"


def test_plan_scan_attaches_recon_and_render_shows_it() -> None:
    profile = TargetProfile(is_spa=True, frameworks=frozenset({"spring"}), api_kind="rest")
    plan = plan_scan(profile)
    assert plan.recon.use_headless and plan.recon.discover_api_schemas and plan.recon.probe_paths
    text = render_plan(profile, plan)
    assert "Reconocimiento" in text and "rutas de alto valor" in text


# --- functional-area mapping (recon like a pentester: zones, then focus each) -----------------------


def test_plan_areas_maps_the_functional_zones() -> None:
    profile = TargetProfile(
        has_login=True, api_kind="rest", has_file_upload=True,
        paths=frozenset({"/admin/users", "/search", "/checkout", "/orders/1"}),
        param_names=frozenset({"id"}),
    )
    names = [a.name for a in plan_areas(profile)]
    assert any("Autenticación" in n for n in names)
    assert "API" in names
    assert any("Administración" in n for n in names)
    assert any("Subida" in n for n in names)
    assert any("Búsqueda" in n for n in names)
    assert any("Comercio" in n for n in names)
    assert any("IDOR" in n for n in names)  # params id / /orders → object area


def test_plan_areas_auth_includes_oauth_when_seen() -> None:
    area = next(a for a in plan_areas(TargetProfile(auth_kind="oauth")) if "Autenticación" in a.name)
    assert "oauth" in area.families


def test_plan_areas_fallback_is_marketing() -> None:
    areas = plan_areas(TargetProfile(paths=frozenset({"/about", "/contact"})))
    assert len(areas) == 1 and areas[0].families == ("xss", "open_redirect")


def test_observed_paths_steer_the_attack_families() -> None:
    # No params/flags — only observed paths. /admin → authz, /upload → upload must still rank.
    plan = plan_scan(TargetProfile(paths=frozenset({"/admin/settings", "/upload/avatar"})))
    assert "authz" in plan.priority_families and "upload" in plan.priority_families
    assert plan.family_scores["authz"] > 0 and plan.family_scores["upload"] > 0


def test_areas_feed_recon_paths_and_render() -> None:
    profile = TargetProfile(has_login=True, api_kind="rest", cms="wordpress")
    plan = plan_scan(profile)
    assert plan.areas                                  # the app was mapped into zones
    assert "/login" in plan.recon.probe_paths          # the auth area's paths merged into recon
    text = render_plan(profile, plan)
    assert "Áreas" in text and "Autenticación" in text
