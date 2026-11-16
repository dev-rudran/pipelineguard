"""Reporter tests for JSON, SARIF, Markdown, CycloneDX and console output."""

from __future__ import annotations

import datetime as dt
import json

import pytest

from pipelineguard.models import (
    Component,
    Finding,
    GateResult,
    ScannerResult,
    ScanReport,
    Severity,
)
from pipelineguard.report import console, cyclonedx, markdown, sarif
from pipelineguard.report import json as json_report
from tests.support import contains_raw_secret

FIXED_TIME = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)


def sample_finding(
    scanner: str = "secrets",
    rule_id: str = "PIPE-SEC-001",
    severity: Severity = Severity.HIGH,
    path: str = "app/settings.py",
    line: int = 3,
    message: str = "AWS access key ID is committed.",
    snippet: str = 'AWS_ACCESS_KEY_ID = "AKIA...T3V5"',
    context: str = "aws-access-key",
) -> Finding:
    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        title="Test finding",
        severity=severity,
        message=message,
        path=path,
        line=line,
        column=5,
        snippet=snippet,
        context=context,
        references=["https://example.com/advisory"],
        metadata={"remediation": "Rotate the credential."},
    )


def sample_report(*, passed: bool = False, skipped_config: bool = True) -> ScanReport:
    secrets = ScannerResult(scanner="secrets", elapsed=0.12)
    secrets.findings.append(sample_finding())
    secrets.metadata = {"filesScanned": 12, "skipped": 0}

    dependency = sample_finding(
        scanner="deps",
        rule_id="PIPE-DEP-001",
        severity=Severity.MEDIUM,
        path="requirements.txt",
        line=2,
        message="jinja2 2.11.3 is affected by CVE-2020-28493.",
        snippet="jinja2==2.11.3",
        context="cve-2020-28493",
    )
    dependency.package = "jinja2"
    dependency.version = "2.11.3"
    dependency.fixed_version = "3.1.4"
    dependency.aliases = ["CVE-2020-28493", "GHSA-xxxx"]
    deps = ScannerResult(scanner="deps", elapsed=0.2)
    deps.findings.append(dependency)
    deps.components = [
        Component(
            ecosystem="pypi",
            name="jinja2",
            version="2.11.3",
            license="BSD-3-Clause",
            source="requirements.txt",
            direct=True,
        )
    ]

    sbom = ScannerResult(scanner="sbom", elapsed=0.01)
    sbom.components = list(deps.components)

    config = ScannerResult(scanner="config", elapsed=0.0)
    if skipped_config:
        config.skipped = True
        config.skip_reason = "no Dockerfiles or workflows"

    report = ScanReport(
        target="repo",
        started_at=FIXED_TIME,
        finished_at=FIXED_TIME + dt.timedelta(seconds=1),
    )
    report.results = [secrets, deps, sbom, config]
    report.gate = GateResult(
        passed=passed,
        fail_on=Severity.HIGH,
        reasons=[] if passed else ["1 finding(s) at or above severity high"],
        counts={"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
    )
    return report


def test_json_report_has_expected_shape():
    report = sample_report()
    payload = json.loads(json_report.render(report))
    assert payload["tool"] == {"name": "pipelineguard", "version": "0.1.0"}
    assert payload["target"] == "repo"
    assert payload["startedAt"] == "2026-01-02T03:04:05Z"
    assert payload["finishedAt"] == "2026-01-02T03:04:06Z"
    assert payload["counts"] == {
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 0,
        "info": 0,
    }
    assert len(payload["scanners"]) == 4
    assert payload["gate"]["status"] == "fail"
    first = payload["scanners"][0]["findings"][0]
    assert first["ruleId"] == "PIPE-SEC-001"
    assert first["fingerprint"]
    assert first["snippet"].startswith("AWS_ACCESS_KEY_ID")


def test_json_report_excludes_suppressed_findings_by_default():
    report = sample_report()
    suppressed = sample_finding(rule_id="PIPE-SEC-018", context="suppressed")
    suppressed.suppressed_by = "allow[1]"
    suppressed.suppressed_reason = "test fixture"
    report.results[0].findings.append(suppressed)

    default = json.loads(json_report.render(report))
    assert default["suppressedCount"] == 1
    assert all(
        finding["ruleId"] != "PIPE-SEC-018" for finding in default["scanners"][0]["findings"]
    )

    included = json.loads(json_report.render(report, include_suppressed=True))
    rule_ids = [finding["ruleId"] for finding in included["scanners"][0]["findings"]]
    assert "PIPE-SEC-018" in rule_ids


def test_json_report_never_contains_raw_secrets():
    report = sample_report()
    rendered = json_report.render(report)
    assert contains_raw_secret(rendered) == []


def test_json_writer_creates_parent_directories(tmp_path):
    target = tmp_path / "nested" / "results.json"
    written = json_report.write(sample_report(), target)
    assert written == target
    assert json.loads(target.read_text(encoding="utf-8"))["target"] == "repo"


@pytest.mark.parametrize(
    "severity,level",
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ],
)
def test_sarif_level_mapping(severity, level):
    assert sarif.level_for(severity) == level


def test_sarif_document_is_valid_and_deterministic():
    report = sample_report()
    document = sarif.build(report)
    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "pipelineguard"
    assert run["tool"]["driver"]["version"] == "0.1.0"
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert rule_ids == sorted(rule_ids)
    assert rule_ids == ["PIPE-DEP-001", "PIPE-SEC-001"]
    assert len(run["results"]) == 2
    assert run["results"][0]["ruleId"] == "PIPE-DEP-001"
    assert run["results"][0]["level"] == "warning"
    assert run["results"][1]["level"] == "error"
    result = run["results"][1]
    assert result["partialFingerprints"]["pipelineguard/v1"] == report.findings()[0].fingerprint
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "app/settings.py"
    )
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    assert run["invocations"][0]["executionSuccessful"] is True
    assert sarif.render(report) == sarif.render(report)


def test_sarif_empty_report_has_no_results():
    report = ScanReport(target="empty", started_at=FIXED_TIME, finished_at=FIXED_TIME)
    report.gate = GateResult(passed=True, fail_on=Severity.HIGH)
    document = sarif.build(report)
    run = document["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_sarif_marks_scanner_errors_as_unsuccessful():
    report = sample_report()
    report.results[0].error = "parser failure"
    document = sarif.build(report)
    assert document["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_sarif_writer(tmp_path):
    target = tmp_path / "results.sarif"
    sarif.write(sample_report(), target)
    assert json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_markdown_contains_gate_and_findings():
    report = sample_report()
    rendered = markdown.render(report, artifacts=["results.json", "sbom.cdx.json"])
    assert rendered.startswith("<!-- pipelineguard -->")
    assert "## pipelineguard" in rendered
    assert "**Gate: FAILED**" in rendered
    assert "1 finding(s) at or above `high`" in rendered
    assert "PIPE-SEC-001" in rendered
    assert "PIPE-DEP-001" in rendered
    assert "### Artifacts" in rendered
    assert "- `results.json`" in rendered
    assert "### Gate reasons" in rendered
    assert contains_raw_secret(rendered) == []


def test_markdown_pass_verdict_and_skipped_scanner():
    report = sample_report(passed=True)
    rendered = markdown.render(report)
    assert "**Gate: PASSED**" in rendered
    assert "Skipped: no Dockerfiles or workflows" in rendered


def test_markdown_omits_extra_findings():
    report = sample_report()
    for index in range(5):
        report.results[0].findings.append(
            sample_finding(rule_id=f"PIPE-SEC-{index + 10:03d}", context=f"extra-{index}")
        )
    rendered = markdown.render(report, max_findings=2)
    assert "additional finding(s) omitted" in rendered


def test_markdown_escapes_table_cells():
    report = sample_report()
    report.results[0].findings[0].message = "bad | message <script>"
    rendered = markdown.render(report)
    assert "&#124;" in rendered
    assert "&lt;script&gt;" in rendered


def test_markdown_writer(tmp_path):
    target = tmp_path / "comment.md"
    markdown.write(sample_report(), target, artifacts=["results.json"])
    assert "## pipelineguard" in target.read_text(encoding="utf-8")


def test_console_quiet_failure():
    report = sample_report()
    rendered = console.render(report, color=False, quiet=True)
    assert rendered == ("pipelineguard: FAIL\n  - 1 finding(s) at or above severity high\n")


def test_console_quiet_pass():
    report = sample_report(passed=True)
    assert console.render(report, color=False, quiet=True) == "pipelineguard: PASS\n"


def test_console_renders_summary_and_findings_without_color():
    report = sample_report()
    rendered = console.render(report, color=False, stats=True)
    assert "\033[" not in rendered
    assert "pipelineguard 0.1.0  target: repo" in rendered
    assert "Summary" in rendered
    assert "Gate: FAIL" in rendered
    assert "PIPE-SEC-001" in rendered
    assert "filesScanned=12" in rendered
    assert "1 finding(s) at or above severity high" in rendered


def test_console_pass_line():
    report = sample_report(passed=True)
    rendered = console.render(report, color=False)
    assert "Gate: PASS" in rendered
    assert "Run finished in 1.00s with policy fail_on=high" in rendered


def test_console_reports_clean_scanner():
    report = sample_report(passed=True)
    report.results[1].findings = []
    rendered = console.render(report, color=False)
    assert "  clean" in rendered


def test_console_reports_errors_and_skips():
    report = sample_report(passed=True)
    report.results[1].error = "boom"
    rendered = console.render(report, color=False)
    assert "ERROR boom" in rendered
    assert "SKIPPED no Dockerfiles or workflows" in rendered


def test_console_omits_excess_findings(monkeypatch):
    report = sample_report()
    result = report.results[0]
    result.findings = [
        sample_finding(rule_id=f"PIPE-SEC-{index + 10:03d}", context=f"extra-{index}")
        for index in range(5)
    ]
    monkeypatch.setattr(console, "MAX_FINDINGS_PER_SCANNER", 2)
    rendered = console.render(report, color=False)
    assert "3 more finding(s) omitted" in rendered


def test_console_suppressed_count():
    report = sample_report()
    suppressed = sample_finding(rule_id="PIPE-SEC-018", context="suppressed")
    suppressed.suppressed_by = "allow[1]"
    report.results[0].findings.append(suppressed)
    rendered = console.render(report, color=False)
    assert "1 finding(s) suppressed by policy" in rendered


def test_cyclonedx_bom_is_deterministic():
    components = [
        Component(ecosystem="pypi", name="jinja2", version="3.1.4", license="BSD-3-Clause"),
        Component(ecosystem="npm", name="@scope/pkg", version="1.0.0", direct=False),
    ]
    first = cyclonedx.build_bom(components, target_name="repo", timestamp=FIXED_TIME)
    second = cyclonedx.build_bom(
        list(reversed(components)), target_name="repo", timestamp=FIXED_TIME
    )
    assert first == second
    assert first["bomFormat"] == "CycloneDX"
    assert first["specVersion"] == "1.5"
    assert first["serialNumber"].startswith("urn:uuid:")
    assert first["metadata"]["timestamp"] == "2026-01-02T03:04:05Z"
    assert [item["purl"] for item in first["components"]] == [
        "pkg:npm/%40scope/pkg@1.0.0",
        "pkg:pypi/jinja2@3.1.4",
    ]
    assert first["components"][1]["licenses"] == [{"license": {"id": "BSD-3-Clause"}}]
    assert first["dependencies"][0]["dependsOn"] == ["pkg:pypi/jinja2@3.1.4"]


def test_cyclonedx_handles_license_expressions_and_names():
    components = [
        Component(ecosystem="npm", name="a", version="1.0.0", license="MIT OR Apache-2.0"),
        Component(ecosystem="npm", name="b", version="1.0.0", license="Custom License Text"),
    ]
    bom = cyclonedx.build_bom(components, timestamp=FIXED_TIME)
    licenses = [item["licenses"][0] for item in bom["components"]]
    assert {"expression": "MIT OR Apache-2.0"} in licenses
    assert {"license": {"name": "Custom License Text"}} in licenses


def test_cyclonedx_empty_bom_has_no_dependencies():
    bom = cyclonedx.build_bom([], timestamp=FIXED_TIME)
    assert bom["components"] == []
    assert "dependencies" not in bom
    payload = json.loads(cyclonedx.to_json(bom))
    assert payload["metadata"]["component"]["name"] == "repository"


def test_cyclonedx_json_ends_with_newline():
    bom = cyclonedx.build_bom([], timestamp=FIXED_TIME)
    assert cyclonedx.to_json(bom).endswith("\n")


def test_cyclonedx_serial_changes_with_components():
    first = cyclonedx.build_bom(
        [Component(ecosystem="pypi", name="one", version="1.0.0")], timestamp=FIXED_TIME
    )
    second = cyclonedx.build_bom(
        [Component(ecosystem="pypi", name="two", version="1.0.0")], timestamp=FIXED_TIME
    )
    assert first["serialNumber"] != second["serialNumber"]
