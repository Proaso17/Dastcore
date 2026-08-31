"""Mode A program import: parse pasted program-policy text into a reviewable Program + notes."""

from __future__ import annotations

from dastcore.bugbounty.importer import parse_program_policy

_POLICY = """\
Program: hackerone.com/bancoplata — Gold Standard Safe Harbor applies.
In scope
*.bancoplata.mx        Wildcard   Critical   Eligible
api.bancoplata.mx      Domain     Eligible
Banco Plata Android    com.bancoplata.app   Android   Eligible
Banco Plata iOS        Apple App Store      iOS
10.8.0.0/16            CIDR
Out of scope
blog.bancoplata.mx
marketing.thirdparty.com
Rules: please limit testing to 3 requests per second. Identify your traffic with the header
X-HackerOne: migon. Automated scanners are not allowed against login endpoints.
"""


def test_parse_extracts_scope_split_by_section() -> None:
    r = parse_program_policy(_POLICY, platform="hackerone")
    p = r.program
    assert p.scope.wildcards == ["*.bancoplata.mx"]
    assert p.scope.domains == ["api.bancoplata.mx"]  # the apex covered by the wildcard is dropped as redundant
    assert p.scope.cidrs == ["10.8.0.0/16"]
    assert set(p.scope.out_of_scope) == {"blog.bancoplata.mx", "marketing.thirdparty.com"}


def test_parse_derives_handle_and_drops_platform_host() -> None:
    p = parse_program_policy(_POLICY, platform="hackerone").program
    assert p.handle == "bancoplata"  # derived from the hackerone.com/<handle> URL
    assert "hackerone.com" not in p.scope.allow_patterns()  # the platform's own host is never a target


def test_parse_reads_rate_limit_no_automation_and_attribution() -> None:
    p = parse_program_policy(_POLICY, platform="hackerone").program
    assert p.limits.requests_per_second == 3.0
    assert p.limits.no_automated_scanning is True  # "automated scanners are not allowed"
    assert p.required_headers == {"X-HackerOne": "migon"}  # trailing period stripped


def test_parse_filters_mobile_assets_and_notes_safe_harbor() -> None:
    r = parse_program_policy(_POLICY, platform="hackerone")
    assert any("android" in f.lower() or "com.bancoplata.app" in f for f in r.filtered)
    assert any("iOS" in f or "ios" in f.lower() for f in r.filtered)
    assert r.program.bug_bounty_mode is True  # real-platform import defaults to bug-bounty mode
    joined = " ".join(r.notes).lower()
    assert "safe harbor" in joined and "no-web" in joined


def test_finance_program_without_rate_limit_gets_conservative_default() -> None:
    r = parse_program_policy("*.bank-example.com in scope. Please avoid harm to our banking systems.",
                             platform="hackerone")
    assert r.program.limits.requests_per_second == 2.0 and r.program.limits.max_concurrency == 2
    assert any("conservador" in n for n in r.notes)


def test_empty_or_hostless_policy_is_flagged_not_crashing() -> None:
    r = parse_program_policy("Please be nice. No hosts here.", platform="hackerone")
    assert r.program.scope.allow_patterns() == []
    assert any("No se detectó ningún host" in n for n in r.notes)


def test_self_platform_does_not_force_bug_bounty_mode() -> None:
    r = parse_program_policy("example.com", platform="self")
    assert r.program.bug_bounty_mode is False and r.program.platform == "self"
