"""End-to-end CLI tests against the bundled example repositories."""

from __future__ import annotations

import json

from tests.support import (
    ADVISORY_DB,
    CLEAN,
    VULNERABLE,
    contains_raw_secret,
    read_json,
    run_cli,
    write_tree,
)


def test_version_command(capsys):
    assert run_cli(["version"]) == 0
    assert capsys.readouterr().out.strip() == "pipelineguard 0.1.0"


def test_rules_list_all(capsys):
    assert run_cli(["rules", "list"]) == 0
    out = capsys.readouterr().out
    assert "PIPE-SEC-001" in out
    assert "PIPE-DEP-001" in out
    assert "PIPE-LIC-001" in out
    assert "PIPE-CFG-001" in out
    assert "rule(s)." in out


def test_rules_list_filters_by_scanner(capsys):
    assert run_cli(["rules", "list", "--scanner", "config"]) == 0
    out = capsys.readouterr().out
    assert "PIPE-CFG-001" in out
    assert "PIPE-SEC-001" not in out


def test_rules_list_filters_licenses(capsys):
    assert run_cli(["rules", "list", "--scanner", "licenses"]) == 0
    out = capsys.readouterr().out
    assert "PIPE-LIC-001" in out
    assert "PIPE-LIC-002" in out
    assert "PIPE-SEC-001" not in out


def test_rules_list_rejects_unknown_scanner(capsys):
    assert run_cli(["rules", "list", "--scanner", "bogus"]) == 2
    captured = capsys.readouterr()
    assert "unknown scanner filter" in captured.err


def test_policy_validate_accepts_valid_file(tmp_path, capsys):
    path = tmp_path / "pipelineguard.yaml"
    path.write_text("fail_on: medium\nallow:\n  - scanner: deps\n    reason: demo\n")
    assert run_cli(["policy", "validate", str(path)]) == 0
    assert "policy OK" in capsys.readouterr().out


def test_policy_validate_rejects_invalid_file(tmp_path, capsys):
    path = tmp_path / "pipelineguard.yaml"
    path.write_text("fail_on: severe\n")
    assert run_cli(["policy", "validate", str(path)]) == 2
    captured = capsys.readouterr()
    assert "policy error" in captured.err
    assert "unknown severity" in captured.err


def test_scan_vulnerable_repository_fails(capsys):
    exit_code = run_cli(
        [
            "scan",
            str(VULNERABLE),
            "--offline",
            "--advisory-db",
            str(ADVISORY_DB),
            "--quiet",
        ]
    )
    assert exit_code == 1
    assert capsys.readouterr().out.startswith("pipelineguard: FAIL")


def test_scan_clean_repository_passes(capsys):
    exit_code = run_cli(["scan", str(CLEAN), "--offline", "--quiet"])
    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "pipelineguard: PASS"


def test_scan_console_shows_stats(capsys):
    exit_code = run_cli(["scan", str(CLEAN), "--offline", "--stats", "--no-color"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Summary" in out
    assert "filesScanned=" in out
    assert "Gate: PASS" in out


def test_scan_rejects_missing_path(capsys):
    assert run_cli(["scan", "/definitely/not/here"]) == 2
    assert "path does not exist" in capsys.readouterr().err


def test_scan_rejects_unknown_format(capsys):
    assert run_cli(["scan", str(CLEAN), "--format", "xml"]) == 2
    assert "unknown format 'xml'" in capsys.readouterr().err


def test_scan_requires_output_dir_for_multiple_formats(capsys):
    assert run_cli(["scan", str(CLEAN), "--format", "json,sarif"]) == 2
    assert "--output-dir is required" in capsys.readouterr().err


def test_scan_rejects_missing_advisory_db():
    assert (
        run_cli(
            [
                "scan",
                str(CLEAN),
                "--offline",
                "--advisory-db",
                "/definitely/not/here.json",
            ]
        )
        == 2
    )


def test_scan_rejects_invalid_fail_on():
    assert run_cli(["scan", str(CLEAN), "--fail-on", "severe"]) == 2


def test_scan_rejects_invalid_policy(tmp_path, capsys):
    bad = tmp_path / "policy.yaml"
    bad.write_text("fail_on: nope\n")
    assert run_cli(["scan", str(CLEAN), "--policy", str(bad)]) == 2
    assert "policy error" in capsys.readouterr().err


def test_scan_writes_all_artifacts(tmp_path, capsys):
    output_dir = tmp_path / "artifacts"
    exit_code = run_cli(
        [
            "scan",
            str(VULNERABLE),
            "--offline",
            "--advisory-db",
            str(ADVISORY_DB),
            "--format",
            "all",
            "--output-dir",
            str(output_dir),
            "--no-color",
        ]
    )
    assert exit_code == 1
    for name in ("results.json", "results.sarif", "comment.md", "sbom.cdx.json"):
        assert (output_dir / name).is_file(), name

    results = read_json(output_dir / "results.json")
    assert results["gate"]["status"] == "fail"
    assert sum(results["counts"].values()) > 0

    sarif = read_json(output_dir / "results.sarif")
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]

    bom = read_json(output_dir / "sbom.cdx.json")
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["components"]

    comment = (output_dir / "comment.md").read_text(encoding="utf-8")
    assert comment.startswith("<!-- pipelineguard -->")
    assert "results.json" in comment

    for name in ("results.json", "results.sarif", "comment.md", "sbom.cdx.json"):
        text = (output_dir / name).read_text(encoding="utf-8")
        assert contains_raw_secret(text) == [], name

    assert "Gate: FAIL" in capsys.readouterr().out


def test_scan_json_stdout(tmp_path, capsys):
    exit_code = run_cli(
        [
            "scan",
            str(VULNERABLE),
            "--offline",
            "--advisory-db",
            str(ADVISORY_DB),
            "--format",
            "json",
        ]
    )
    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["gate"]["status"] == "fail"
    assert len(payload["scanners"]) == 5


def test_scan_console_and_json_without_output_dir(capsys):
    exit_code = run_cli(["scan", str(CLEAN), "--offline", "--format", "console,json"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert '"tool": {' in out
    assert "Gate: PASS" in out


def test_scan_clean_artifacts_pass(tmp_path):
    output_dir = tmp_path / "clean"
    exit_code = run_cli(
        [
            "scan",
            str(CLEAN),
            "--offline",
            "--format",
            "all",
            "--output-dir",
            str(output_dir),
            "--quiet",
        ]
    )
    assert exit_code == 0
    assert read_json(output_dir / "results.json")["gate"]["status"] == "pass"


def test_scan_write_and_reuse_baseline(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    first = run_cli(
        [
            "scan",
            str(VULNERABLE),
            "--offline",
            "--advisory-db",
            str(ADVISORY_DB),
            "--write-baseline",
            str(baseline),
            "--quiet",
        ]
    )
    assert first == 1
    assert baseline.is_file()
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    assert payload["fingerprints"]

    second = run_cli(
        [
            "scan",
            str(VULNERABLE),
            "--offline",
            "--advisory-db",
            str(ADVISORY_DB),
            "--baseline",
            str(baseline),
            "--quiet",
        ]
    )
    assert second == 0
    assert "pipelineguard: PASS" in capsys.readouterr().out


def test_sbom_command_stdout(capsys):
    assert run_cli(["sbom", str(CLEAN)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["specVersion"] == "1.5"
    assert payload["components"]


def test_sbom_command_writes_file(tmp_path, capsys):
    target = tmp_path / "nested" / "sbom.json"
    assert run_cli(["sbom", str(CLEAN), "--output", str(target)]) == 0
    assert "Wrote CycloneDX 1.5 SBOM" in capsys.readouterr().out
    assert read_json(target)["bomFormat"] == "CycloneDX"


def test_secrets_command_fails_on_vulnerable_repository(capsys):
    assert run_cli(["secrets", str(VULNERABLE), "--quiet"]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_secrets_command_passes_on_clean_repository(capsys):
    assert run_cli(["secrets", str(CLEAN), "--quiet"]) == 0
    assert capsys.readouterr().out.strip() == "pipelineguard: PASS"


def test_secrets_command_writes_sarif(tmp_path):
    output_dir = tmp_path / "secrets"
    assert (
        run_cli(
            [
                "secrets",
                str(VULNERABLE),
                "--format",
                "sarif",
                "--output-dir",
                str(output_dir),
                "--quiet",
            ]
        )
        == 1
    )
    assert read_json(output_dir / "results.sarif")["version"] == "2.1.0"


def test_deps_command_fails_with_advisory_db(capsys):
    assert (
        run_cli(
            [
                "deps",
                str(VULNERABLE),
                "--offline",
                "--advisory-db",
                str(ADVISORY_DB),
                "--quiet",
            ]
        )
        == 1
    )
    assert "FAIL" in capsys.readouterr().out


def test_deps_command_passes_offline_without_advisories(capsys):
    assert run_cli(["deps", str(CLEAN), "--offline", "--quiet"]) == 0
    out = capsys.readouterr().out
    assert out.strip().startswith("pipelineguard: PASS")


def test_repository_policy_file_is_used(tmp_path, capsys):
    repo = tmp_path / "repo"
    write_tree(repo, {".gitignore": ".env\n", "README.md": "# demo\n"})
    (repo / "pipelineguard.yaml").write_text("fail_on: none\n")
    assert run_cli(["scan", str(repo), "--offline", "--quiet"]) == 0
    assert "PASS" in capsys.readouterr().out


def test_scan_staged_mode_in_git_repository(tmp_path, capsys):
    from tests.support import commit_all, make_git_repo

    repo = tmp_path / "repo"
    write_tree(repo, {".gitignore": ".env\n", "app.txt": "clean\n"})
    make_git_repo(repo)
    commit_all(repo)
    write_tree(
        repo,
        {".env": "AWS_ACCESS_KEY_ID=AKIAQ7Z2M4N6P8R1T3V5\n"},
    )
    from tests.support import git

    git(repo, "add", "-f", ".env")
    assert (
        run_cli(
            [
                "secrets",
                str(repo),
                "--staged",
                "--format",
                "json",
                "--fail-on",
                "high",
            ]
        )
        == 1
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["stagedMode"] is True
    assert payload["counts"]["critical"] >= 1
