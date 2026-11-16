"""Policy loading, allowances, baselines and gate evaluation."""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import (
    SEVERITY_ORDER,
    BaselineDiff,
    Finding,
    GateResult,
    ScanReport,
    Severity,
    StaleAllowance,
)

POLICY_FILENAME = "pipelineguard.yaml"
DEFAULT_FAIL_ON = Severity.HIGH
ALLOWED_KEYS = {
    "version",
    "fail_on",
    "required_scanners",
    "max_findings",
    "allow",
    "exclude_paths",
    "offline",
}
ALLOWED_ALLOW_KEYS = {
    "scanner",
    "fingerprint",
    "id",
    "rule",
    "file",
    "path",
    "reason",
    "expires",
}
SELECTOR_KEYS = ("fingerprint", "id", "rule", "file", "path")


class PolicyError(ValueError):
    """Raised when a policy file is invalid."""

    def __init__(self, errors: list[str] | str) -> None:
        self.errors = [errors] if isinstance(errors, str) else list(errors)
        super().__init__("; ".join(self.errors))


@dataclass
class Allowance:
    index: int
    scanner: str | None = None
    fingerprint: str | None = None
    rule_id: str | None = None
    file: str | None = None
    reason: str = ""
    expires: dt.date | None = None

    @property
    def expired(self) -> bool:
        return self.expires is not None and self.expires < dt.datetime.now(dt.timezone.utc).date()

    @property
    def label(self) -> str:
        selectors = []
        if self.scanner:
            selectors.append(f"scanner={self.scanner}")
        if self.fingerprint:
            selectors.append(f"fingerprint={self.fingerprint}")
        if self.rule_id:
            selectors.append(f"id={self.rule_id}")
        if self.file:
            selectors.append(f"file={self.file}")
        return ", ".join(selectors) or f"allowance #{self.index}"

    def matches(self, finding: Finding) -> bool:
        if self.scanner and finding.scanner != self.scanner:
            return False
        if self.fingerprint and finding.fingerprint != self.fingerprint:
            return False
        if self.rule_id and finding.rule_id != self.rule_id:
            return False
        return not (self.file and not _path_matches(finding.path, self.file))

    def selector_present(self) -> bool:
        return any(
            (
                self.scanner,
                self.fingerprint,
                self.rule_id,
                self.file,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"index": self.index}
        if self.scanner:
            payload["scanner"] = self.scanner
        if self.fingerprint:
            payload["fingerprint"] = self.fingerprint
        if self.rule_id:
            payload["id"] = self.rule_id
        if self.file:
            payload["file"] = self.file
        if self.reason:
            payload["reason"] = self.reason
        if self.expires:
            payload["expires"] = self.expires.isoformat()
        return payload

    def stale(self, reason: str) -> StaleAllowance:
        return StaleAllowance(index=self.index, reason=reason, entry=self.to_dict())


@dataclass
class Policy:
    fail_on: Severity | None = DEFAULT_FAIL_ON
    required_scanners: list[str] = field(default_factory=list)
    max_findings: dict[Severity, int] = field(default_factory=dict)
    allowances: list[Allowance] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    offline: bool = False
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "fail_on": self.fail_on.value if self.fail_on else "none",
            "required_scanners": list(self.required_scanners),
            "max_findings": {
                severity.value: value for severity, value in self.max_findings.items()
            },
            "allow": [allowance.to_dict() for allowance in self.allowances],
            "exclude_paths": list(self.exclude_paths),
            "offline": self.offline,
            "source": self.source,
        }


def default_policy() -> Policy:
    """Default when no policy file exists: fail on high, nothing required."""
    return Policy()


def load_policy(path: Path | None = None, required: bool = False) -> Policy:
    """Load a policy file, or return the default when it does not exist."""
    if path is None:
        return default_policy()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if required:
            raise PolicyError(f"policy file not found: {path}") from None
        return default_policy()
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML in {path}: {exc}") from exc
    if document is None:
        document = {}
    if not isinstance(document, dict):
        raise PolicyError(f"{path} must contain a mapping at the top level")
    policy = parse_policy(document, source=str(path))
    return policy


def parse_policy(document: dict[str, Any], source: str | None = None) -> Policy:
    errors: list[str] = []
    unknown = set(document) - ALLOWED_KEYS
    if unknown:
        errors.append(f"unknown policy keys: {', '.join(sorted(unknown))}")

    fail_on: Severity | None = DEFAULT_FAIL_ON
    raw_fail_on = document.get("fail_on", "high")
    if isinstance(raw_fail_on, str) and raw_fail_on.strip().lower() in {"none", "off", "false"}:
        fail_on = None
    else:
        try:
            fail_on = Severity.parse(str(raw_fail_on))
        except ValueError as exc:
            errors.append(str(exc))

    required = document.get("required_scanners") or []
    if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
        errors.append("required_scanners must be a list of scanner names")
        required = []
    else:
        required = [item.strip().lower() for item in required if item.strip()]
        known = _known_scanners()
        for name in required:
            if name not in known:
                errors.append(
                    f"unknown required scanner {name!r}; available: {', '.join(sorted(known))}"
                )

    max_findings: dict[Severity, int] = {}
    raw_max = document.get("max_findings") or {}
    if not isinstance(raw_max, dict):
        errors.append("max_findings must be a mapping of severity to integer")
    else:
        for key, value in raw_max.items():
            try:
                severity = Severity.parse(str(key))
            except ValueError as exc:
                errors.append(str(exc))
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                errors.append(f"max_findings.{key} must be a non-negative integer")
                continue
            max_findings[severity] = value

    allowances: list[Allowance] = []
    raw_allow = document.get("allow") or []
    if not isinstance(raw_allow, list):
        errors.append("allow must be a list of allowance mappings")
        raw_allow = []
    for index, entry in enumerate(raw_allow, start=1):
        allowance, entry_errors = _parse_allowance(index, entry)
        errors.extend(entry_errors)
        if allowance is not None:
            allowances.append(allowance)

    exclude_paths = document.get("exclude_paths") or []
    if not isinstance(exclude_paths, list) or any(
        not isinstance(item, str) for item in exclude_paths
    ):
        errors.append("exclude_paths must be a list of path globs")
        exclude_paths = []

    offline = document.get("offline", False)
    if not isinstance(offline, bool):
        errors.append("offline must be true or false")
        offline = False

    if errors:
        raise PolicyError(errors)
    return Policy(
        fail_on=fail_on,
        required_scanners=required,
        max_findings=max_findings,
        allowances=allowances,
        exclude_paths=[str(item) for item in exclude_paths],
        offline=offline,
        source=source,
    )


def _parse_allowance(index: int, entry: Any) -> tuple[Allowance | None, list[str]]:
    errors: list[str] = []
    if not isinstance(entry, dict):
        return None, [f"allow[{index}] must be a mapping"]
    unknown = set(entry) - ALLOWED_ALLOW_KEYS
    if unknown:
        errors.append(f"allow[{index}] has unknown keys: {', '.join(sorted(unknown))}")
    scanner = entry.get("scanner")
    if scanner is not None and not isinstance(scanner, str):
        errors.append(f"allow[{index}].scanner must be a string")
        scanner = None
    rule_id = entry.get("id", entry.get("rule"))
    if rule_id is not None and not isinstance(rule_id, str):
        errors.append(f"allow[{index}].id must be a string")
        rule_id = None
    fingerprint = entry.get("fingerprint")
    if fingerprint is not None and not isinstance(fingerprint, str):
        errors.append(f"allow[{index}].fingerprint must be a string")
        fingerprint = None
    file_value = entry.get("file", entry.get("path"))
    if file_value is not None and not isinstance(file_value, str):
        errors.append(f"allow[{index}].file must be a string")
        file_value = None
    reason = entry.get("reason") or ""
    if not isinstance(reason, str):
        errors.append(f"allow[{index}].reason must be a string")
        reason = ""

    expires: dt.date | None = None
    raw_expires = entry.get("expires")
    if raw_expires is not None:
        if isinstance(raw_expires, dt.datetime):
            expires = raw_expires.date()
        elif isinstance(raw_expires, dt.date):
            expires = raw_expires
        elif isinstance(raw_expires, str):
            try:
                expires = dt.date.fromisoformat(raw_expires.strip())
            except ValueError:
                errors.append(
                    f"allow[{index}].expires must be an ISO date (YYYY-MM-DD), got {raw_expires!r}"
                )
        else:
            errors.append(f"allow[{index}].expires must be an ISO date (YYYY-MM-DD)")

    allowance = Allowance(
        index=index,
        scanner=scanner.strip().lower() if isinstance(scanner, str) else None,
        fingerprint=fingerprint,
        rule_id=rule_id,
        file=file_value,
        reason=reason,
        expires=expires,
    )
    if not allowance.selector_present():
        errors.append(
            f"allow[{index}] needs at least one selector: scanner, fingerprint, id or file"
        )
    if not reason:
        errors.append(f"allow[{index}] needs a reason")
    return (allowance if not errors else None), errors


def _known_scanners() -> set[str]:
    from .scanners.base import available_scanners

    return set(available_scanners())


def _path_matches(path: str, pattern: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = pattern.replace("\\", "/")
    if fnmatch.fnmatch(normalized, candidate):
        return True
    if candidate.startswith("**/") and fnmatch.fnmatch(normalized, candidate[3:]):
        return True
    return normalized == candidate


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


def load_baseline(path: Path) -> dict[str, dict[str, Any]]:
    """Load a baseline from a results.json report or a simple fingerprint list."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"cannot read baseline {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"baseline {path} is not valid JSON: {exc}") from exc

    entries: dict[str, dict[str, Any]] = {}
    if isinstance(document, list):
        for item in document:
            if isinstance(item, str):
                entries[item] = {"fingerprint": item}
        return entries
    if not isinstance(document, dict):
        raise PolicyError(f"baseline {path} must be a results.json report or a list")

    fingerprints = document.get("fingerprints")
    if isinstance(fingerprints, list):
        for item in fingerprints:
            if isinstance(item, str):
                entries[item] = {"fingerprint": item}
        return entries

    scanners = document.get("scanners")
    if isinstance(scanners, list):
        for scanner in scanners:
            if not isinstance(scanner, dict):
                continue
            for finding in scanner.get("findings") or []:
                if not isinstance(finding, dict):
                    continue
                fingerprint = finding.get("fingerprint")
                if not isinstance(fingerprint, str):
                    continue
                entries[fingerprint] = {
                    "fingerprint": fingerprint,
                    "scanner": finding.get("scanner"),
                    "ruleId": finding.get("ruleId"),
                    "path": finding.get("path"),
                    "severity": finding.get("severity"),
                    "message": str(finding.get("message") or "")[:200],
                }
        return entries
    raise PolicyError(f"baseline {path} has no scanners or fingerprints list")


def compare_baseline(report: ScanReport, baseline: dict[str, dict[str, Any]]) -> BaselineDiff:
    current = report.findings()
    current_by_fingerprint = {finding.fingerprint: finding for finding in current}
    new = [finding for finding in current if finding.fingerprint not in baseline]
    existing = [finding for finding in current if finding.fingerprint in baseline]
    fixed = [
        dict(entry)
        for fingerprint, entry in baseline.items()
        if fingerprint not in current_by_fingerprint
    ]
    fixed.sort(key=lambda item: str(item.get("fingerprint", "")))
    diff = BaselineDiff(new=new, fixed=fixed, existing=existing, baseline_total=len(baseline))
    report.baseline = diff
    return diff


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


def apply_allowances(report: ScanReport, policy: Policy) -> list[StaleAllowance]:
    """Mark findings covered by an unexpired allowance and report stale entries."""
    stale: list[StaleAllowance] = []
    for allowance in policy.allowances:
        if allowance.expired:
            stale.append(allowance.stale(f"expired on {allowance.expires}"))
            continue
        matched_any = False
        for finding in report.findings():
            if allowance.matches(finding):
                matched_any = True
                finding.suppressed_by = allowance.fingerprint or f"allow[{allowance.index}]"
                finding.suppressed_reason = allowance.reason
        if not matched_any:
            stale.append(allowance.stale("does not match any current finding"))
    return stale


def evaluate(
    report: ScanReport, policy: Policy, baseline: BaselineDiff | None = None
) -> GateResult:
    """Apply allowances and evaluate the gate. Mutates findings' suppression state."""
    stale = apply_allowances(report, policy)

    considered: list[Finding] = []
    for result in report.results:
        for finding in result.findings:
            if finding.suppressed or _excluded_path(finding.path, policy.exclude_paths):
                continue
            considered.append(finding)

    if baseline is not None:
        new_fingerprints = {finding.fingerprint for finding in baseline.new}
        considered = [finding for finding in considered if finding.fingerprint in new_fingerprints]

    counts = {severity.value: 0 for severity in SEVERITY_ORDER}
    for finding in considered:
        counts[finding.severity.value] += 1

    reasons: list[str] = []
    threshold_violations: list[str] = []
    if policy.fail_on is not None:
        blockers = sum(
            count
            for severity, count in counts.items()
            if Severity.parse(severity).rank >= policy.fail_on.rank
        )
        if blockers:
            prefix = "new " if baseline is not None else ""
            reasons.append(
                f"{blockers} {prefix}finding(s) at or above severity {policy.fail_on.value}"
            )
            threshold_violations.append(f"fail_on={policy.fail_on.value}: {blockers} finding(s)")

    for severity, limit in sorted(
        policy.max_findings.items(), key=lambda item: item[0].rank, reverse=True
    ):
        count = counts.get(severity.value, 0)
        if count > limit:
            reasons.append(f"max_findings.{severity.value}: {count} > {limit}")
            threshold_violations.append(f"max_findings.{severity.value}: {count} > {limit}")

    present = {result.scanner for result in report.results}
    missing = [name for name in policy.required_scanners if name not in present]
    for name in missing:
        reasons.append(f"required scanner did not run: {name}")

    scanner_errors: list[str] = []
    for result in report.results:
        if result.error:
            scanner_errors.append(result.scanner)
            reasons.append(f"scanner '{result.scanner}' failed: {result.error}")

    suppressed = sum(
        1 for finding in report.findings(include_suppressed=True) if finding.suppressed
    )
    passed = not reasons
    gate = GateResult(
        passed=passed,
        fail_on=policy.fail_on,
        reasons=reasons,
        counts=counts,
        suppressed=suppressed,
        stale_allowances=stale,
        missing_scanners=missing,
        scanner_errors=scanner_errors,
        threshold_violations=threshold_violations,
    )
    report.gate = gate
    return gate


def _excluded_path(path: str, patterns: list[str]) -> bool:
    if not path:
        return False
    return any(_path_matches(path, pattern) for pattern in patterns)


def write_baseline(report: ScanReport, path: Path) -> Path:
    """Write a compact baseline file that can be committed."""
    entries = [
        {
            "fingerprint": finding.fingerprint,
            "scanner": finding.scanner,
            "ruleId": finding.rule_id,
            "path": finding.path,
            "severity": finding.severity.value,
            "message": finding.message[:200],
        }
        for finding in report.findings()
    ]
    payload = {
        "tool": "pipelineguard",
        "version": report.tool_version,
        "generatedAt": report.finished_at.isoformat() if report.finished_at else "",
        "fingerprints": [entry["fingerprint"] for entry in entries],
        "findings": entries,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path
