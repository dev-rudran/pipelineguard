"""Assertions on the bundled example repositories."""

from __future__ import annotations

import json

from pipelineguard.models import ScanReport, Severity
from tests.support import ADVISORY_DB, CLEAN, VULNERABLE, contains_raw_secret, scan_named


def scan(scanner: str, root, **kwargs):
    return scan_named(scanner, root, **kwargs)


def rule_ids(result) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def test_vulnerable_repository_secret_findings():
    result = scan("secrets", VULNERABLE)
    assert result.error is None
    assert len(result.findings) == 11
    severities = {finding.severity for finding in result.findings}
    assert Severity.CRITICAL in severities
    assert Severity.HIGH in severities
    assert {
        "PIPE-SEC-001",
        "PIPE-SEC-002",
        "PIPE-SEC-003",
        "PIPE-SEC-008",
        "PIPE-SEC-010",
        "PIPE-SEC-018",
    } <= rule_ids(result)
    assert result.metadata["filesScanned"] >= 5


def test_vulnerable_repository_dependency_findings():
    result = scan(
        "deps",
        VULNERABLE,
        offline=True,
        advisory_db=ADVISORY_DB,
    )
    assert result.error is None
    vulnerable = [finding for finding in result.findings if finding.rule_id == "PIPE-DEP-001"]
    assert len(vulnerable) == 1
    finding = vulnerable[0]
    assert finding.package == "jinja2"
    assert finding.version == "2.11.2"
    assert "CVE-2020-28493" in finding.aliases
    assert finding.severity is Severity.HIGH
    assert result.metadata["auditSource"] == "advisory-db"


def test_vulnerable_repository_config_findings():
    result = scan("config", VULNERABLE)
    assert result.error is None
    assert len(result.findings) == 20
    assert {
        "PIPE-CFG-001",
        "PIPE-CFG-002",
        "PIPE-CFG-005",
        "PIPE-CFG-007",
        "PIPE-CFG-009",
        "PIPE-CFG-010",
        "PIPE-CFG-011",
        "PIPE-CFG-012",
        "PIPE-CFG-013",
        "PIPE-CFG-015",
        "PIPE-CFG-017",
        "PIPE-CFG-018",
        "PIPE-CFG-019",
    } <= rule_ids(result)


def test_vulnerable_repository_sbom_is_inventoried():
    result = scan("sbom", VULNERABLE)
    assert result.findings == []
    purls = {component.purl for component in result.components}
    assert "pkg:pypi/jinja2@2.11.2" in purls


def test_clean_repository_has_no_findings():
    for scanner in ("secrets", "licenses", "sbom", "config"):
        result = scan(scanner, CLEAN)
        assert result.findings == [], scanner
        assert result.error is None, scanner
    deps = scan("deps", CLEAN, offline=True, advisory_db=ADVISORY_DB)
    assert deps.findings == []
    assert deps.error is None


def test_example_findings_never_serialize_raw_secrets():
    report = ScanReport(target="examples/vulnerable-repo")
    for scanner in ("secrets", "deps", "config"):
        result = scan(scanner, VULNERABLE, offline=True, advisory_db=ADVISORY_DB)
        report.results.append(result)
    payload = json.dumps(report.to_dict(), default=str)
    assert contains_raw_secret(payload) == []


def test_examples_do_not_contain_stub_markers():
    for root in (VULNERABLE, CLEAN):
        for path in root.rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8", errors="ignore").lower()
                assert "todo" not in text, path
                assert "not implemented" not in text, path
