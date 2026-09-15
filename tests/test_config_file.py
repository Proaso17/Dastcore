"""Polish: unified YAML/JSON config file (`--config`) with CLI-flag override."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from dastcore.cli import app
from dastcore.config import ScanFile

runner = CliRunner()


def test_scan_file_model_accepts_full_config(vuln_app_url: str) -> None:
    sf = ScanFile.model_validate(
        {
            "target": vuln_app_url,
            "allow_domains": ["127.0.0.1"],
            "engine": "http",
            "rps": 50,
            "concurrency": 4,
            "fail_on": "none",
        }
    )
    assert sf.target == vuln_app_url
    assert sf.concurrency == 4


def test_scan_file_accepts_supabase_fields() -> None:
    sf = ScanFile.model_validate(
        {
            "target": "https://x.supabase.co/rest/v1/",
            "supabase_frontend": "https://app.example.com",
            "supabase_tables": ["profiles", "orders"],
        }
    )
    assert sf.supabase_frontend == "https://app.example.com"
    assert sf.supabase_tables == ["profiles", "orders"]


def test_supabase_profiling_block_runs_and_emits_coverage_finding(vuln_app_url: str, tmp_path) -> None:
    # Regression: profile() returns a SupabaseProfile (not a Finding list). The scan must handle that
    # and emit the info coverage finding — not crash with "'SupabaseProfile' object is not subscriptable".
    cfg = tmp_path / "scan.yaml"
    cfg.write_text(
        json.dumps(
            {
                "target": vuln_app_url,
                "engine": "http",
                "rps": 90,
                "fail_on": "none",
                "supabase_tables": ["zzz_probe"],  # forces the Supabase profiling block on a local target
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan", "--config", str(cfg), "--i-have-authorization", "--quiet", "-f", "json"])
    assert result.exit_code == 0, result.stdout
    data = json.loads(result.stdout)
    assert any("supabase" in json.dumps(f).lower() for f in data), "supabase coverage finding missing"


def test_scan_file_rejects_unknown_keys() -> None:
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ScanFile.model_validate({"targett": "http://x"})  # typo'd key


def test_config_file_drives_scan(vuln_app_url: str, tmp_path) -> None:
    cfg = tmp_path / "scan.yaml"
    cfg.write_text(
        json.dumps({"target": vuln_app_url, "engine": "http", "rps": 60, "fail_on": "none"}),
        encoding="utf-8",
    )
    # No target argument on the CLI — it comes from the file.
    result = runner.invoke(app, ["scan", "--config", str(cfg), "--i-have-authorization"])
    assert result.exit_code == 0, result.stdout
    assert "SQL Injection" in result.stdout


def test_cli_flag_overrides_config_file(vuln_app_url: str, tmp_path) -> None:
    cfg = tmp_path / "scan.yaml"
    cfg.write_text(json.dumps({"target": vuln_app_url, "engine": "both", "fail_on": "none"}), encoding="utf-8")
    # File says engine=both (would need a browser); explicit --engine http must win.
    result = runner.invoke(
        app, ["scan", "--config", str(cfg), "--i-have-authorization", "--engine", "http", "--rps", "60"]
    )
    assert result.exit_code == 0
    assert "Motor de descubrimiento: http" in result.stdout


def test_scan_file_expands_env_vars(monkeypatch) -> None:
    from dastcore.cli import _expand_env_refs

    monkeypatch.setenv("GETNYMA_PW", "s3cr3t!:with#chars")
    data = {
        "target": "https://x.example",
        "auth": {"type": "form", "form": {"login_url": "https://x/login", "credentials": {"password": "${GETNYMA_PW}"}}},
    }
    expanded = _expand_env_refs(data)
    # The secret is injected as a plain value; its ':'/'#' can't corrupt the parsed structure.
    assert expanded["auth"]["form"]["credentials"]["password"] == "s3cr3t!:with#chars"
    assert expanded["target"] == "https://x.example"  # non-ref strings pass through untouched


def test_scan_file_env_var_default_used_when_unset(monkeypatch) -> None:
    from dastcore.cli import _expand_env_refs

    monkeypatch.delenv("DAST_MISSING", raising=False)
    assert _expand_env_refs({"k": "${DAST_MISSING:-fallback}"}) == {"k": "fallback"}


def test_load_scan_file_drops_identity_with_unset_env_var(monkeypatch, tmp_path) -> None:
    from dastcore.cli import _load_scan_file

    monkeypatch.delenv("DAST_PW_A", raising=False)
    monkeypatch.setenv("DAST_PW_B", "secretB")
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        "target: https://x.test/\n"
        "allow_domains: [x.test]\n"
        "identities:\n"
        "  - name: a\n    role: user\n    auth: {type: bearer, bearer_token: '${DAST_PW_A}'}\n"
        "  - name: b\n    role: user\n    auth: {type: bearer, bearer_token: '${DAST_PW_B}'}\n",
        encoding="utf-8",
    )
    sf, warnings = _load_scan_file(str(cfg))
    assert [i.name for i in sf.identities] == ["b"]  # 'a' dropped, 'b' kept (no abort)
    assert any("'a'" in w and "DAST_PW_A" in w for w in warnings)


def test_load_scan_file_drops_discovery_auth_with_unset_env_var(monkeypatch, tmp_path) -> None:
    from dastcore.cli import _load_scan_file

    monkeypatch.delenv("DAST_TOK", raising=False)
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        "target: https://x.test/\nallow_domains: [x.test]\nauth: {type: bearer, bearer_token: '${DAST_TOK}'}\n",
        encoding="utf-8",
    )
    sf, warnings = _load_scan_file(str(cfg))  # loads instead of aborting
    assert any("descubrimiento" in w and "DAST_TOK" in w for w in warnings)
    assert sf.auth is None or sf.auth.type in ("none", None)  # discovery auth dropped, not applied blank


def test_load_scan_file_env_file_supplies_vars(monkeypatch, tmp_path) -> None:
    from dastcore.cli import _load_scan_file

    monkeypatch.delenv("DAST_EF", raising=False)  # not in the process env at all
    envf = tmp_path / "creds.env"
    envf.write_text('# secretos\nDAST_EF="secret-from-file"\n', encoding="utf-8")
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        "target: https://x.test/\nallow_domains: [x.test]\n"
        "identities:\n  - name: a\n    role: user\n    auth: {type: bearer, bearer_token: '${DAST_EF}'}\n",
        encoding="utf-8",
    )
    sf, warnings = _load_scan_file(str(cfg), str(envf))
    assert warnings == []
    assert [i.name for i in sf.identities] == ["a"]  # kept: --env-file supplied the var
    assert sf.identities[0].auth.bearer_token == "secret-from-file"


def test_read_env_file_and_precedence(monkeypatch, tmp_path) -> None:
    from dastcore.cli import _read_env_file, _resolve_env

    envf = tmp_path / "e.env"
    envf.write_text("A=fromfile\nB='quoted'\n# comment\nBAD LINE NO EQUALS\n", encoding="utf-8")
    assert _read_env_file(str(envf)) == {"A": "fromfile", "B": "quoted"}
    monkeypatch.setenv("A", "fromproc")
    merged = _resolve_env(str(envf))
    assert merged["A"] == "fromfile"  # env-file wins over the process env
    assert merged["B"] == "quoted"


def test_authz_coverage_gap_finding_is_a_low_advisory() -> None:
    from dastcore.cli import _authz_coverage_gap_finding
    from dastcore.owasp import is_advisory

    f = _authz_coverage_gap_finding("https://x.supabase.co/rest/v1/", 13, 1)
    assert f.rule_id == "authz-coverage-gap" and f.severity == "low"
    assert "BOLA" in f.evidence[0].data and "13" in f.evidence[0].data  # says what wasn't tested
    assert is_advisory(f)  # excluded from the OWASP rollup (it's meta, not a target vuln)


def test_windows_persisted_env_is_a_safe_dict() -> None:
    from dastcore.cli import _windows_persisted_env

    assert isinstance(_windows_persisted_env(), dict)  # {} off Windows, registry env on Windows; never raises


def test_load_scan_file_unset_var_in_non_auth_field_still_errors(monkeypatch, tmp_path) -> None:
    import pytest

    from dastcore.cli import _load_scan_file

    monkeypatch.delenv("DAST_MISSING", raising=False)
    cfg = tmp_path / "c.yaml"
    cfg.write_text("target: 'https://${DAST_MISSING}.test/'\nallow_domains: [x.test]\n", encoding="utf-8")
    with pytest.raises(ValueError):  # a typo in target must still be a hard error
        _load_scan_file(str(cfg))


def test_scan_file_unset_env_var_without_default_errors(monkeypatch) -> None:
    import pytest

    from dastcore.cli import _expand_env_refs

    monkeypatch.delenv("DAST_MISSING", raising=False)
    with pytest.raises(ValueError, match="DAST_MISSING"):  # a typo'd/unset var must fail loudly
        _expand_env_refs({"k": "${DAST_MISSING}"})


def test_missing_target_without_config_errors() -> None:
    result = runner.invoke(app, ["scan", "--i-have-authorization"])
    assert result.exit_code == 1
    assert "Falta el target" in result.stdout


def test_quiet_mode_emits_only_report(vuln_app_url: str) -> None:
    result = runner.invoke(
        app, ["scan", vuln_app_url, "--i-have-authorization", "--rps", "60", "--quiet", "--fail-on", "none"]
    )
    assert result.exit_code == 0
    assert "AVISO LEGAL" not in result.stdout  # banner suppressed
    assert "Resumen del escaneo" not in result.stdout  # summary suppressed
    # the JSON report is still emitted and parses
    data = json.loads(result.stdout)
    assert isinstance(data, list)
