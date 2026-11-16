"""SARIF 2.1.0 output for GitHub code scanning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .. import __version__
from ..models import Finding, ScanReport, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
REPOSITORY_URI = "%SRCROOT%"


def level_for(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _artifact_uri(path: str) -> str:
    normalized = path.replace("\\", "/").strip()
    if not normalized:
        return "."
    return quote(normalized, safe="/._-~")


def _rule(finding: Finding) -> dict[str, Any]:
    remediation = finding.metadata.get("remediation") if finding.metadata else None
    help_text = finding.message
    if remediation:
        help_text = f"{help_text}\n\nRemediation: {remediation}"
    rule: dict[str, Any] = {
        "id": finding.rule_id,
        "name": finding.title.replace(" ", ""),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.message},
        "defaultConfiguration": {"level": level_for(finding.severity)},
        "help": {"text": help_text},
        "properties": {
            "tags": ["security", finding.scanner],
            "precision": "medium",
            "problem.severity": level_for(finding.severity),
        },
    }
    if finding.references:
        rule["helpUri"] = finding.references[0]
    return rule


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": level_for(finding.severity),
        "message": {"text": finding.message},
        "partialFingerprints": {"pipelineguard/v1": finding.fingerprint},
        "properties": {
            "scanner": finding.scanner,
            "severity": finding.severity.value,
        },
    }
    if finding.snippet:
        result["properties"]["snippet"] = finding.snippet
    if finding.package:
        result["properties"]["package"] = finding.package
        result["properties"]["version"] = finding.version
        if finding.fixed_version:
            result["properties"]["fixedVersion"] = finding.fixed_version
    if finding.aliases:
        result["properties"]["aliases"] = finding.aliases
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": _artifact_uri(finding.path),
                "uriBaseId": REPOSITORY_URI,
            },
            "region": {
                "startLine": finding.line or 1,
                "startColumn": finding.column or 1,
                "endLine": finding.line or 1,
            },
        }
    }
    result["locations"] = [location]
    return result


def build(report: ScanReport) -> dict[str, Any]:
    findings = report.findings()
    ordered = sorted(
        findings,
        key=lambda item: (item.scanner, item.rule_id, item.path, item.line or 0, item.fingerprint),
    )
    rules: dict[str, dict[str, Any]] = {}
    for finding in ordered:
        rules.setdefault(finding.rule_id, _rule(finding))
    rule_ids = sorted(rules)
    index = {rule_id: position for position, rule_id in enumerate(rule_ids)}
    results = [_result(finding, index[finding.rule_id]) for finding in ordered]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "pipelineguard",
                "informationUri": "https://github.com/dev-rudran/pipelineguard",
                "version": __version__,
                "semanticVersion": __version__,
                "rules": [rules[rule_id] for rule_id in rule_ids],
            }
        },
        "originalUriBaseIds": {
            REPOSITORY_URI: {"uri": "file:///"},
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": all(result.error is None for result in report.results),
                "endTimeUtc": report.finished_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                if report.finished_at
                else "",
            }
        ],
        "properties": {
            "gate": report.gate.to_dict() if report.gate else None,
            "target": report.target,
        },
    }
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def render(report: ScanReport) -> str:
    return json.dumps(build(report), indent=2, ensure_ascii=False) + "\n"


def write(report: ScanReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(report), encoding="utf-8")
    return path
