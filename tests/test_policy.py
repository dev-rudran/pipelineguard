"""Policy parsing, allowance, baseline and gate evaluation tests."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from pipelineguard.models import Finding, ScannerResult, ScanReport, Severity
from pipelineguard.policy import (
    Allowance,
    Policy,
    PolicyError,
    apply_allowances,
    compare_baseline,
    default_policy,
    evaluate,
    load_baseline,
    load_policy,
    parse_policy,
    write_baseline,
)
from tests.support import write_tree


def make_finding(
    rule_id: str = "PIPE-SEC-001",
    severity: Severity = Severity.HIGH,
    path: str = "app/settings.py",
    scanner: str = "secrets",
    context: str = "aws-key",
    message: str = "A credential is committed.",
) -> Finding:
    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        title="Test finding",
        severity=severity,
        message=message,
        path=path,
        line=4,
        context=context,
    )


def make_report(*findings: Finding, scanner: str = "secrets") -> ScanReport:
    result = ScannerResult(scanner=scanner)
    result.findings.extend(findings)
    report = ScanReport(target="repo")
    report.results = [result]
    return report


def test_default_policy_fails_on_high():
    policy = default_policy()
    assert policy.fail_on is Severity.HIGH
    assert policy.required_scanners == []
    assert policy.allowances == []
    assert policy.offline is False


def test_parse_minimal_policy():
    policy = parse_policy({})
    assert policy.fail_on is Severity.HIGH
    assert policy.source is None


@pytest.mark.parametrize("value", ["none", "off", "false", "NONE"])
def test_fail_on_can_be_disabled(value):
    policy = parse_policy({"fail_on": value})
    assert policy.fail_on is None


def test_fail_on_accepts_severity():
    assert parse_policy({"fail_on": "critical"}).fail_on is Severity.CRITICAL


def test_fail_on_rejects_unknown_severity():
    with pytest.raises(PolicyError, match="unknown severity"):
        parse_policy({"fail_on": "severe"})


def test_unknown_policy_key_is_rejected():
    with pytest.raises(PolicyError, match="unknown policy keys: surprise"):
        parse_policy({"surprise": True})


def test_required_scanners_are_validated():
    policy = parse_policy({"required_scanners": ["secrets", " DEPS "]})
    assert policy.required_scanners == ["secrets", "deps"]


def test_required_scanners_reject_unknown_names():
    with pytest.raises(PolicyError, match="unknown required scanner 'fuzz'"):
        parse_policy({"required_scanners": ["fuzz"]})


def test_required_scanners_must_be_a_list():
    with pytest.raises(PolicyError, match="required_scanners must be a list"):
        parse_policy({"required_scanners": "secrets"})


def test_max_findings_are_parsed():
    policy = parse_policy({"max_findings": {"high": 2, "critical": 0}})
    assert policy.max_findings == {Severity.HIGH: 2, Severity.CRITICAL: 0}


def test_max_findings_rejects_bad_entries():
    with pytest.raises(PolicyError) as excinfo:
        parse_policy({"max_findings": {"bogus": 1, "high": -1, "low": True}})
    errors = " ".join(excinfo.value.errors)
    assert "unknown severity" in errors
    assert "max_findings.high must be a non-negative integer" in errors
    assert "max_findings.low must be a non-negative integer" in errors


def test_allowance_is_parsed_with_expiry():
    policy = parse_policy(
        {
            "allow": [
                {
                    "scanner": "secrets",
                    "id": "PIPE-SEC-001",
                    "file": "tests/**",
                    "reason": "fixture credential",
                    "expires": "2099-12-31",
                }
            ]
        }
    )
    allowance = policy.allowances[0]
    assert allowance.scanner == "secrets"
    assert allowance.rule_id == "PIPE-SEC-001"
    assert allowance.file == "tests/**"
    assert allowance.reason == "fixture credential"
    assert allowance.expires == dt.date(2099, 12, 31)
    assert allowance.expired is False
    assert "scanner=secrets" in allowance.label
    assert "file=tests/**" in allowance.label


def test_allowance_supports_rule_and_path_aliases():
    policy = parse_policy({"allow": [{"rule": "PIPE-CFG-015", "path": ".env", "reason": "demo"}]})
    allowance = policy.allowances[0]
    assert allowance.rule_id == "PIPE-CFG-015"
    assert allowance.file == ".env"


def test_allowance_requires_selector_and_reason():
    with pytest.raises(PolicyError) as excinfo:
        parse_policy({"allow": [{"expires": "2099-01-01"}]})
    errors = " ".join(excinfo.value.errors)
    assert "needs at least one selector" in errors
    assert "needs a reason" in errors


def test_allowance_rejects_unknown_keys_and_bad_expiry():
    with pytest.raises(PolicyError) as excinfo:
        parse_policy(
            {
                "allow": [
                    {
                        "scanner": "secrets",
                        "reason": "test",
                        "unexpected": 1,
                        "expires": "31/12/2099",
                    }
                ]
            }
        )
    errors = " ".join(excinfo.value.errors)
    assert "unknown keys: unexpected" in errors
    assert "ISO date" in errors


def test_allowance_scanner_type_is_validated():
    with pytest.raises(PolicyError, match="scanner must be a string"):
        parse_policy({"allow": [{"scanner": 1, "reason": "test"}]})


def test_offline_and_exclude_paths_are_parsed():
    policy = parse_policy({"offline": True, "exclude_paths": ["vendor/**", "*.min.js"]})
    assert policy.offline is True
    assert policy.exclude_paths == ["vendor/**", "*.min.js"]


def test_offline_requires_boolean():
    with pytest.raises(PolicyError, match="offline must be true or false"):
        parse_policy({"offline": "yes"})


def test_policy_to_dict_roundtrip():
    policy = parse_policy(
        {
            "fail_on": "medium",
            "required_scanners": ["deps"],
            "max_findings": {"low": 3},
            "exclude_paths": ["docs/**"],
            "offline": True,
            "allow": [{"scanner": "deps", "reason": "accepted risk"}],
        },
        source="pipelineguard.yaml",
    )
    payload = policy.to_dict()
    assert payload["fail_on"] == "medium"
    assert payload["required_scanners"] == ["deps"]
    assert payload["max_findings"] == {"low": 3}
    assert payload["exclude_paths"] == ["docs/**"]
    assert payload["offline"] is True
    assert payload["source"] == "pipelineguard.yaml"
    assert payload["allow"][0]["reason"] == "accepted risk"


def test_load_policy_missing_optional_returns_default(tmp_path):
    policy = load_policy(tmp_path / "missing.yaml")
    assert policy.fail_on is Severity.HIGH


def test_load_policy_missing_required_raises(tmp_path):
    with pytest.raises(PolicyError, match="policy file not found"):
        load_policy(tmp_path / "missing.yaml", required=True)


def test_load_policy_reads_yaml(tmp_path):
    path = tmp_path / "pipelineguard.yaml"
    path.write_text("fail_on: critical\n", encoding="utf-8")
    policy = load_policy(path, required=True)
    assert policy.fail_on is Severity.CRITICAL
    assert policy.source == str(path)


def test_load_policy_rejects_invalid_yaml(tmp_path):
    path = tmp_path / "pipelineguard.yaml"
    path.write_text("fail_on: [unterminated\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid YAML"):
        load_policy(path)


def test_load_policy_rejects_non_mapping(tmp_path):
    path = tmp_path / "pipelineguard.yaml"
    path.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="must contain a mapping"):
        load_policy(path)


def test_allowance_matches_rule_and_glob():
    finding = make_finding(path="tests/test_api.py")
    allowance = Allowance(index=1, scanner="secrets", rule_id="PIPE-SEC-001", file="tests/**")
    assert allowance.matches(finding) is True
    assert allowance.matches(make_finding(rule_id="PIPE-SEC-002")) is False
    assert allowance.matches(make_finding(path="app/main.py")) is False
    assert allowance.matches(make_finding(scanner="deps")) is False


def test_apply_allowances_suppresses_matching_findings():
    first = make_finding()
    second = make_finding(rule_id="PIPE-SEC-018", context="generic")
    report = make_report(first, second)
    policy = parse_policy(
        {"allow": [{"id": "PIPE-SEC-001", "reason": "test fixture", "expires": "2099-01-01"}]}
    )
    stale = apply_allowances(report, policy)
    assert stale == []
    assert first.suppressed is True
    assert first.suppressed_reason == "test fixture"
    assert second.suppressed is False


def test_expired_allowance_is_stale_and_does_not_suppress():
    finding = make_finding()
    report = make_report(finding)
    policy = parse_policy(
        {"allow": [{"id": "PIPE-SEC-001", "reason": "old", "expires": "2020-01-01"}]}
    )
    stale = apply_allowances(report, policy)
    assert finding.suppressed is False
    assert len(stale) == 1
    assert "expired on 2020-01-01" in stale[0].reason


def test_unmatched_allowance_is_stale():
    report = make_report(make_finding())
    policy = parse_policy({"allow": [{"id": "PIPE-CFG-001", "reason": "unused"}]})
    stale = apply_allowances(report, policy)
    assert len(stale) == 1
    assert "does not match any current finding" in stale[0].reason


def test_gate_passes_below_threshold():
    report = make_report(make_finding(severity=Severity.MEDIUM))
    gate = evaluate(report, Policy(fail_on=Severity.HIGH))
    assert gate.passed is True
    assert gate.exit_code == 0
    assert gate.reasons == []


def test_gate_fails_at_threshold():
    report = make_report(make_finding(severity=Severity.HIGH))
    gate = evaluate(report, Policy(fail_on=Severity.HIGH))
    assert gate.passed is False
    assert gate.exit_code == 1
    assert "1 finding(s) at or above severity high" in gate.reasons[0]
    assert gate.threshold_violations == ["fail_on=high: 1 finding(s)"]


def test_gate_with_fail_on_none_passes():
    report = make_report(make_finding(severity=Severity.CRITICAL))
    gate = evaluate(report, Policy(fail_on=None))
    assert gate.passed is True
    assert gate.fail_on is None


def test_gate_honors_max_findings():
    report = make_report(
        make_finding(severity=Severity.LOW, context="a"),
        make_finding(severity=Severity.LOW, context="b"),
    )
    gate = evaluate(report, Policy(fail_on=None, max_findings={Severity.LOW: 1}))
    assert gate.passed is False
    assert gate.reasons == ["max_findings.low: 2 > 1"]


def test_gate_skips_excluded_paths():
    report = make_report(make_finding(path="vendor/min.js"))
    gate = evaluate(report, Policy(fail_on=Severity.LOW, exclude_paths=["vendor/**"]))
    assert gate.passed is True
    assert gate.counts["high"] == 0


def test_gate_reports_missing_required_scanner():
    report = make_report(make_finding())
    gate = evaluate(report, Policy(required_scanners=["deps"]))
    assert gate.passed is False
    assert gate.missing_scanners == ["deps"]
    assert "required scanner did not run: deps" in gate.reasons


def test_gate_fails_on_scanner_error():
    report = make_report()
    report.results[0].error = "crash in parser"
    gate = evaluate(report, Policy())
    assert gate.passed is False
    assert gate.scanner_errors == ["secrets"]
    assert "scanner 'secrets' failed: crash in parser" in gate.reasons


def test_gate_counts_suppressed_separately():
    suppressed = make_finding(context="suppressed")
    active = make_finding(rule_id="PIPE-SEC-018", severity=Severity.LOW, context="active")
    report = make_report(suppressed, active)
    policy = parse_policy({"allow": [{"id": "PIPE-SEC-001", "reason": "test"}]})
    suppressed.suppressed_by = "allow[1]"
    gate = evaluate(report, policy)
    assert gate.suppressed == 1
    assert gate.counts["low"] == 1
    assert gate.counts["high"] == 0


def test_gate_with_baseline_only_fails_new_findings():
    existing = make_finding(context="existing")
    new = make_finding(context="new")
    report = make_report(existing, new)
    baseline = compare_baseline(report, {existing.fingerprint: {"fingerprint": "x"}})
    gate = evaluate(report, Policy(fail_on=Severity.HIGH), baseline=baseline)
    assert gate.passed is False
    assert "new finding(s)" in gate.reasons[0]


def test_gate_with_baseline_passes_when_nothing_is_new():
    existing = make_finding()
    report = make_report(existing)
    baseline = compare_baseline(report, {existing.fingerprint: {"fingerprint": "x"}})
    gate = evaluate(report, Policy(fail_on=Severity.HIGH), baseline=baseline)
    assert gate.passed is True


def test_load_baseline_from_fingerprint_list(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(["abc", "def"]), encoding="utf-8")
    entries = load_baseline(path)
    assert set(entries) == {"abc", "def"}


def test_load_baseline_from_fingerprints_object(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"fingerprints": ["abc"]}), encoding="utf-8")
    assert set(load_baseline(path)) == {"abc"}


def test_load_baseline_from_results_report(tmp_path):
    fingerprint = make_finding().fingerprint
    path = tmp_path / "results.json"
    path.write_text(
        json.dumps(
            {
                "scanners": [
                    {
                        "scanner": "secrets",
                        "findings": [
                            {
                                "fingerprint": fingerprint,
                                "scanner": "secrets",
                                "ruleId": "PIPE-SEC-001",
                                "path": "app/settings.py",
                                "severity": "high",
                                "message": "test",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    entries = load_baseline(path)
    assert entries[fingerprint]["ruleId"] == "PIPE-SEC-001"


def test_load_baseline_rejects_unknown_shape(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"unexpected": []}), encoding="utf-8")
    with pytest.raises(PolicyError, match="no scanners or fingerprints"):
        load_baseline(path)


def test_load_baseline_rejects_invalid_json(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(PolicyError, match="not valid JSON"):
        load_baseline(path)


def test_load_baseline_rejects_missing_file(tmp_path):
    with pytest.raises(PolicyError, match="cannot read baseline"):
        load_baseline(tmp_path / "missing.json")


def test_compare_baseline_reports_new_fixed_and_existing():
    existing = make_finding(context="existing")
    new = make_finding(context="new")
    report = make_report(existing, new)
    baseline = {
        existing.fingerprint: {"fingerprint": existing.fingerprint},
        "removed-fingerprint": {"fingerprint": "removed-fingerprint"},
    }
    diff = compare_baseline(report, baseline)
    assert [finding.fingerprint for finding in diff.new] == [new.fingerprint]
    assert diff.counts == {"new": 1, "fixed": 1, "existing": 1}
    assert diff.baseline_total == 2
    assert diff.fixed[0]["fingerprint"] == "removed-fingerprint"
    assert report.baseline is diff


def test_write_baseline_roundtrip(tmp_path):
    finding = make_finding()
    report = make_report(finding)
    path = write_baseline(report, tmp_path / "baseline.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["tool"] == "pipelineguard"
    assert payload["fingerprints"] == [finding.fingerprint]
    assert payload["findings"][0]["ruleId"] == "PIPE-SEC-001"
    assert set(load_baseline(path)) == {finding.fingerprint}


def test_baseline_diff_to_dict():
    report = make_report(make_finding())
    diff = compare_baseline(report, {})
    payload = diff.to_dict()
    assert payload["counts"]["new"] == 1
    assert payload["baselineTotal"] == 0
    assert payload["new"][0]["ruleId"] == "PIPE-SEC-001"


def test_policy_file_is_loaded_from_repository(tmp_path: Path):
    write_tree(
        tmp_path,
        {
            "pipelineguard.yaml": "fail_on: low\nrequired_scanners: [secrets]\n",
        },
    )
    policy = load_policy(tmp_path / "pipelineguard.yaml")
    assert policy.fail_on is Severity.LOW
    assert policy.required_scanners == ["secrets"]
