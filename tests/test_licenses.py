"""License scanner tests: denylist, unknown handling, policy and reporting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pipelineguard.models import ScanReport, Severity
from pipelineguard.policy import PolicyError, default_policy, evaluate, parse_policy
from pipelineguard.report import console, markdown, sarif
from pipelineguard.report import json as json_report
from pipelineguard.scanners.base import available_scanners
from tests.support import CLEAN, run_cli, scan_named, write_tree


def write_package_lock(root: Path, packages: dict[str, dict[str, Any]]) -> None:
    document: dict[str, Any] = {
        "name": "license-demo",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "license-demo",
                "version": "1.0.0",
                "dependencies": {
                    name: str(metadata.get("version", "1.0.0"))
                    for name, metadata in packages.items()
                },
            }
        },
    }
    for name, metadata in packages.items():
        document["packages"][f"node_modules/{name}"] = dict(metadata)
    write_tree(root, {"package-lock.json": json.dumps(document)})


def scan_licenses(root: Path, **options: Any):
    return scan_named("licenses", root, options={"licenses": options})


def test_denylisted_license_is_high_and_case_insensitive(tmp_path: Path):
    write_package_lock(
        tmp_path,
        {
            "gpl-lib": {"version": "1.0.0", "license": "gPl-3.0"},
            "agpl-lib": {"version": "2.0.0", "license": "AGPL-3.0"},
            "sspl-lib": {"version": "3.0.0", "license": "SSPL-1.0"},
            "mit-lib": {"version": "4.0.0", "license": "MIT"},
        },
    )

    result = scan_licenses(tmp_path)

    assert result.error is None
    assert len(result.findings) == 3
    assert {finding.rule_id for finding in result.findings} == {"PIPE-LIC-001"}
    assert all(finding.severity is Severity.HIGH for finding in result.findings)
    by_package = {finding.package: finding for finding in result.findings}
    assert set(by_package) == {"gpl-lib", "agpl-lib", "sspl-lib"}
    gpl = by_package["gpl-lib"]
    assert gpl.version == "1.0.0"
    assert gpl.metadata["license"] == "gPl-3.0"
    assert gpl.metadata["deniedLicense"] == "gPl-3.0"
    assert "gpl-lib 1.0.0" in gpl.message
    assert "gPl-3.0" in gpl.message
    assert "policy denies" in gpl.message
    assert gpl.metadata["remediation"]
    assert result.metadata["deniedLicenses"] == 3


def test_deprecated_spdx_suffixes_match_the_base_deny_entry(tmp_path: Path):
    write_package_lock(
        tmp_path,
        {
            "only-lib": {"version": "1.0.0", "license": "GPL-3.0-only"},
            "later-lib": {"version": "1.0.0", "license": "GPL-3.0-or-later"},
        },
    )

    result = scan_licenses(tmp_path)

    assert {finding.rule_id for finding in result.findings} == {"PIPE-LIC-001"}
    assert {finding.package for finding in result.findings} == {"only-lib", "later-lib"}


def test_custom_deny_list_replaces_defaults(tmp_path: Path):
    write_package_lock(
        tmp_path,
        {
            "gpl-lib": {"version": "1.0.0", "license": "GPL-3.0"},
            "mit-lib": {"version": "2.0.0", "license": "MIT"},
        },
    )

    result = scan_licenses(tmp_path, deny=["mit"])

    assert [finding.package for finding in result.findings] == ["mit-lib"]
    assert result.metadata["deny"] == ["mit"]


def test_unknown_license_is_allowed_by_default(tmp_path: Path):
    write_package_lock(tmp_path, {"mystery-lib": {"version": "1.0.0"}})

    result = scan_licenses(tmp_path)

    assert result.findings == []
    assert result.metadata["unknownLicenses"] == 1
    assert result.metadata["allowUnknown"] is True


def test_unknown_license_is_low_when_not_allowed(tmp_path: Path):
    write_package_lock(tmp_path, {"mystery-lib": {"version": "1.0.0"}})

    result = scan_licenses(tmp_path, allow_unknown=False)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "PIPE-LIC-002"
    assert finding.severity is Severity.LOW
    assert finding.package == "mystery-lib"
    assert finding.version == "1.0.0"
    assert "no usable license metadata" in finding.message
    assert finding.metadata["remediation"]
    assert result.metadata["unknownLicenses"] == 1


def test_permissive_licenses_produce_no_findings(tmp_path: Path):
    write_package_lock(
        tmp_path,
        {
            "mit-lib": {"version": "1.0.0", "license": "MIT"},
            "apache-lib": {"version": "1.0.0", "license": "Apache-2.0"},
            "bsd-lib": {"version": "1.0.0", "license": "BSD-3-Clause"},
            "isc-lib": {"version": "1.0.0", "license": "ISC"},
            "dual-lib": {"version": "1.0.0", "license": "MIT OR Apache-2.0"},
            "exception-lib": {"version": "1.0.0", "license": "Apache-2.0 WITH LLVM-exception"},
        },
    )

    result = scan_licenses(tmp_path, allow_unknown=False)

    assert result.findings == []
    assert result.metadata["unknownLicenses"] == 0


def test_poetry_lock_license_metadata_is_used(tmp_path: Path):
    write_tree(
        tmp_path,
        {
            "poetry.lock": (
                '[[package]]\nname = "copyleft-lib"\nversion = "1.0.0"\nlicense = "GPL-3.0"\n'
            )
        },
    )

    result = scan_licenses(tmp_path)

    assert [finding.package for finding in result.findings] == ["copyleft-lib"]
    assert result.findings[0].rule_id == "PIPE-LIC-001"


def test_findings_flow_through_json_and_sarif(tmp_path: Path):
    write_package_lock(tmp_path, {"gpl-lib": {"version": "1.0.0", "license": "GPL-3.0"}})
    report = ScanReport(target="repo")
    report.results = [scan_licenses(tmp_path)]
    gate = evaluate(report, default_policy())

    payload = json.loads(json_report.render(report))
    licenses = next(item for item in payload["scanners"] if item["scanner"] == "licenses")
    finding = licenses["findings"][0]
    assert finding["ruleId"] == "PIPE-LIC-001"
    assert finding["package"]["name"] == "gpl-lib"
    assert finding["package"]["version"] == "1.0.0"
    assert finding["metadata"]["license"] == "GPL-3.0"
    assert finding["fingerprint"]
    assert payload["gate"]["status"] == "fail"

    document = sarif.build(report)
    run = document["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["PIPE-LIC-001"]
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "PIPE-LIC-001"
    assert run["results"][0]["level"] == "error"
    assert gate.exit_code == 1

    assert "PIPE-LIC-001" in markdown.render(report)
    assert "PIPE-LIC-001" in console.render(report, color=False)


def test_policy_allow_suppresses_license_finding_by_fingerprint(tmp_path: Path):
    write_package_lock(tmp_path, {"gpl-lib": {"version": "1.0.0", "license": "GPL-3.0"}})
    result = scan_licenses(tmp_path)
    finding = result.findings[0]
    report = ScanReport(target="repo")
    report.results = [result]
    policy = parse_policy(
        {
            "allow": [
                {
                    "fingerprint": finding.fingerprint,
                    "reason": "legacy dependency scheduled for replacement",
                    "expires": "2099-12-31",
                }
            ]
        }
    )

    gate = evaluate(report, policy)

    assert finding.suppressed is True
    assert finding.suppressed_reason == "legacy dependency scheduled for replacement"
    assert gate.passed is True
    assert gate.suppressed == 1
    assert gate.counts["high"] == 0


def test_expired_allowance_does_not_suppress_license_finding(tmp_path: Path):
    write_package_lock(tmp_path, {"gpl-lib": {"version": "1.0.0", "license": "GPL-3.0"}})
    result = scan_licenses(tmp_path)
    finding = result.findings[0]
    report = ScanReport(target="repo")
    report.results = [result]
    policy = parse_policy(
        {
            "allow": [
                {
                    "fingerprint": finding.fingerprint,
                    "reason": "expired exception",
                    "expires": "2020-01-01",
                }
            ]
        }
    )

    gate = evaluate(report, policy)

    assert finding.suppressed is False
    assert gate.passed is False
    assert "expired on 2020-01-01" in gate.stale_allowances[0].reason


def test_license_policy_reaches_scanner_through_cli(tmp_path: Path, capsys):
    write_package_lock(tmp_path, {"mystery-lib": {"version": "1.0.0"}})
    (tmp_path / "pipelineguard.yaml").write_text(
        "fail_on: none\nlicenses:\n  allow_unknown: false\n",
        encoding="utf-8",
    )

    exit_code = run_cli(["scan", str(tmp_path), "--offline", "--format", "json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    licenses = next(item for item in payload["scanners"] if item["scanner"] == "licenses")
    assert [finding["ruleId"] for finding in licenses["findings"]] == ["PIPE-LIC-002"]


def test_default_config_does_not_fail_clean_repository():
    result = scan_named("licenses", CLEAN)
    report = ScanReport(target="examples/clean-repo")
    report.results = [result]

    gate = evaluate(report, default_policy())

    assert result.findings == []
    assert result.error is None
    assert gate.passed is True
    assert gate.exit_code == 0


def test_license_policy_defaults_and_custom_values():
    defaults = default_policy()
    assert defaults.licenses.deny == ["GPL-3.0", "AGPL-3.0", "SSPL-1.0"]
    assert defaults.licenses.allow_unknown is True

    custom = parse_policy({"licenses": {"deny": ["MIT", "GPL-3.0"], "allow_unknown": False}})
    assert custom.licenses.deny == ["MIT", "GPL-3.0"]
    assert custom.licenses.allow_unknown is False
    assert custom.to_dict()["licenses"] == {
        "deny": ["MIT", "GPL-3.0"],
        "allow_unknown": False,
    }


def test_license_policy_rejects_invalid_configuration():
    with pytest.raises(PolicyError) as excinfo:
        parse_policy(
            {
                "licenses": {
                    "deny": "GPL-3.0",
                    "allow_unknown": "yes",
                    "unexpected": True,
                }
            }
        )
    errors = " ".join(excinfo.value.errors)
    assert "licenses.deny must be a list" in errors
    assert "licenses.allow_unknown must be true or false" in errors
    assert "licenses has unknown keys" in errors


def test_licenses_scanner_is_registered_and_requirable():
    assert "licenses" in available_scanners()
    policy = parse_policy({"required_scanners": ["licenses"]})
    assert policy.required_scanners == ["licenses"]
