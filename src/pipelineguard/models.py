"""Core data model shared by scanners, policy, gate and reporters."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .util import fingerprint as fp


class Severity(str, Enum):
    """Severity ordered from least to most urgent."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:
            raise ValueError(
                f"unknown severity {value!r}; expected one of: "
                + ", ".join(severity.value for severity in cls)
            ) from exc

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

SEVERITY_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(moment: datetime | None) -> str:
    if moment is None:
        return ""
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class Component:
    """A software component discovered by a dependency parser."""

    ecosystem: str
    name: str
    version: str
    direct: bool = True
    license: str | None = None
    source: str = ""
    purl: str = ""

    def __post_init__(self) -> None:
        if not self.purl:
            self.purl = build_purl(self.ecosystem, self.name, self.version)

    @property
    def key(self) -> str:
        return f"{self.ecosystem.lower()}:{self.name.lower()}:{self.version}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "direct": self.direct,
            "license": self.license,
            "source": self.source,
            "purl": self.purl,
        }


_PURL_TYPES = {
    "pypi": "pypi",
    "npm": "npm",
    "golang": "golang",
    "cargo": "cargo",
}


def build_purl(ecosystem: str, name: str, version: str) -> str:
    """Build a package URL for the supported ecosystems."""
    from urllib.parse import quote

    purl_type = _PURL_TYPES.get(ecosystem.lower(), ecosystem.lower())
    namespace = ""
    local_name = name
    if purl_type == "pypi":
        local_name = name.lower().replace("_", "-")
    if purl_type == "npm" and name.startswith("@") and "/" in name:
        scope, local_name = name.split("/", 1)
        namespace = quote("@" + scope.lstrip("@"), safe="")
    encoded_name = quote(local_name, safe="._-")
    if purl_type == "golang":
        # Go module paths are case-sensitive and use slashes as namespace separators.
        encoded_name = quote(name, safe="/._-~")
    prefix = f"pkg:{purl_type}/"
    if namespace:
        prefix += namespace + "/"
    purl = prefix + encoded_name
    if version:
        purl += "@" + quote(version, safe="._-+~")
    return purl


@dataclass
class Finding:
    """A single issue. Never carries a raw secret; snippets are pre-redacted."""

    scanner: str
    rule_id: str
    title: str
    severity: Severity
    message: str
    path: str = ""
    line: int | None = None
    column: int | None = None
    snippet: str = ""
    context: str = field(default="", repr=False)
    commit: str | None = None
    package: str | None = None
    version: str | None = None
    fixed_version: str | None = None
    aliases: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""
    suppressed_by: str | None = None
    suppressed_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            self.severity = Severity.parse(str(self.severity))
        if not self.fingerprint:
            basis = self.context or self.snippet or self.message
            self.fingerprint = fp.fingerprint(self.scanner, self.rule_id, self.path, basis)

    @property
    def suppressed(self) -> bool:
        return self.suppressed_by is not None

    @property
    def is_actionable(self) -> bool:
        return not self.suppressed

    @property
    def location(self) -> str:
        if not self.path:
            return "<repository>"
        if self.line:
            return f"{self.path}:{self.line}"
        return self.path

    def to_dict(self, include_suppressed: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "scanner": self.scanner,
            "ruleId": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "fingerprint": self.fingerprint,
            "suppressed": self.suppressed,
        }
        if self.commit:
            payload["commit"] = self.commit
        if self.package:
            payload["package"] = {
                "name": self.package,
                "version": self.version,
                "fixedVersion": self.fixed_version,
            }
        if self.aliases:
            payload["aliases"] = list(self.aliases)
        if self.references:
            payload["references"] = list(self.references)
        if self.suppressed:
            payload["suppressedBy"] = self.suppressed_by
            payload["suppressedReason"] = self.suppressed_reason
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


@dataclass
class ScannerResult:
    """Outcome of a single scanner."""

    scanner: str
    findings: list[Finding] = field(default_factory=list)
    started_at: datetime = field(default_factory=utc_now)
    elapsed: float = 0.0
    error: str | None = None
    skipped: bool = False
    skip_reason: str = ""
    components: list[Component] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    @property
    def actionable(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.is_actionable]

    def counts(self, include_suppressed: bool = False) -> dict[str, int]:
        counts = {severity.value: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            if finding.suppressed and not include_suppressed:
                continue
            counts[finding.severity.value] += 1
        return counts

    def max_severity(self) -> Severity | None:
        actionable = self.actionable
        if not actionable:
            return None
        return max((finding.severity for finding in actionable), key=lambda sev: sev.rank)

    def to_dict(self, include_suppressed: bool = True) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "findings": [
                finding.to_dict(include_suppressed)
                for finding in self.findings
                if include_suppressed or not finding.suppressed
            ],
            "counts": self.counts(include_suppressed=include_suppressed),
            "elapsedSeconds": round(self.elapsed, 3),
            "error": self.error,
            "skipped": self.skipped,
            "skipReason": self.skip_reason,
            "componentCount": len(self.components),
            "metadata": self.metadata,
        }


@dataclass
class StaleAllowance:
    """An allowance that no longer matches anything or has expired."""

    index: int
    reason: str
    entry: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "reason": self.reason, "entry": self.entry}


@dataclass
class GateResult:
    """Verdict of evaluating a report against a policy."""

    passed: bool
    fail_on: Severity | None
    reasons: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    suppressed: int = 0
    stale_allowances: list[StaleAllowance] = field(default_factory=list)
    missing_scanners: list[str] = field(default_factory=list)
    scanner_errors: list[str] = field(default_factory=list)
    threshold_violations: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        if self.passed:
            return 0
        return 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "pass" if self.passed else "fail",
            "failOn": self.fail_on.value if self.fail_on else "none",
            "counts": self.counts,
            "suppressed": self.suppressed,
            "reasons": self.reasons,
            "missingScanners": self.missing_scanners,
            "scannerErrors": self.scanner_errors,
            "thresholdViolations": self.threshold_violations,
            "staleAllowances": [stale.to_dict() for stale in self.stale_allowances],
        }


@dataclass
class BaselineDiff:
    """Comparison of the current run against a stored baseline."""

    new: list[Finding] = field(default_factory=list)
    fixed: list[dict[str, Any]] = field(default_factory=list)
    existing: list[Finding] = field(default_factory=list)
    baseline_total: int = 0

    @property
    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "existing": len(self.existing),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "counts": self.counts,
            "baselineTotal": self.baseline_total,
            "new": [finding.to_dict() for finding in self.new],
            "fixed": [dict(item) for item in self.fixed],
            "existing": [finding.to_dict() for finding in self.existing],
        }


@dataclass
class ScanReport:
    """Full result of a scan run."""

    target: str
    tool_version: str = "0.1.0"
    started_at: datetime = field(default_factory=utc_now)
    finished_at: datetime | None = None
    results: list[ScannerResult] = field(default_factory=list)
    gate: GateResult | None = None
    policy_file: str | None = None
    baseline: BaselineDiff | None = None
    history_mode: bool = False
    staged_mode: bool = False

    @property
    def elapsed(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    def result(self, scanner: str) -> ScannerResult | None:
        for result in self.results:
            if result.scanner == scanner:
                return result
        return None

    def findings(self, include_suppressed: bool = False) -> list[Finding]:
        findings: list[Finding] = []
        for result in self.results:
            for finding in result.findings:
                if include_suppressed or not finding.suppressed:
                    findings.append(finding)
        return sorted(
            findings,
            key=lambda item: (
                -item.severity.rank,
                item.scanner,
                item.path,
                item.line or 0,
                item.rule_id,
            ),
        )

    def counts(self, include_suppressed: bool = False) -> dict[str, int]:
        counts = {severity.value: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings(include_suppressed=include_suppressed):
            counts[finding.severity.value] += 1
        return counts

    def total(self, include_suppressed: bool = False) -> int:
        return sum(self.counts(include_suppressed=include_suppressed).values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": "pipelineguard", "version": self.tool_version},
            "target": self.target,
            "startedAt": isoformat(self.started_at),
            "finishedAt": isoformat(self.finished_at),
            "elapsedSeconds": round(self.elapsed, 3),
            "historyMode": self.history_mode,
            "stagedMode": self.staged_mode,
            "counts": self.counts(),
            "suppressedCount": sum(
                1 for finding in self.findings(include_suppressed=True) if finding.suppressed
            ),
            "scanners": [result.to_dict() for result in self.results],
            "gate": self.gate.to_dict() if self.gate else None,
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "policyFile": self.policy_file,
        }

    def to_json(self) -> str:
        import json

        return json.dumps(self.to_dict(), indent=2, default=str)


def asdict_without_context(finding: Finding) -> dict[str, Any]:
    """Dataclass export that drops the internal fingerprint context."""
    data = dataclasses.asdict(finding)
    data.pop("context", None)
    return data
