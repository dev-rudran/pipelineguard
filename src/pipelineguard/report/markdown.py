"""Markdown report formatted for a pull request comment."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import __version__
from ..models import SEVERITY_ORDER, ScanReport, Severity
from ..util.text import escape_html

MAX_FINDINGS_PER_SCANNER = 50
MAX_MESSAGE = 300

LEVEL_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}


def _cell(value: str, limit: int = MAX_MESSAGE) -> str:
    text = value.replace("\n", " ").strip()
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return escape_html(text).replace("|", "&#124;")


def _status(result: Any) -> str:
    if result.error:
        return "error"
    if result.skipped:
        return "skipped"
    if not result.actionable:
        return "clean"
    return f"{len(result.actionable)} finding(s)"


def render(
    report: ScanReport,
    artifacts: list[str] | None = None,
    max_findings: int = MAX_FINDINGS_PER_SCANNER,
) -> str:
    gate = report.gate
    counts = gate.counts if gate else report.counts()
    fail_on = gate.fail_on.value if gate and gate.fail_on else "none"
    verdict = "PASSED" if gate and gate.passed else "FAILED"
    lines: list[str] = ["<!-- pipelineguard -->", "## pipelineguard", ""]

    if gate is None:
        lines.append("**Gate: not evaluated.**")
    elif gate.passed:
        lines.append(f"**Gate: {verdict}** with `fail_on: {fail_on}`.")
    elif gate.fail_on is None:
        lines.append(f"**Gate: {verdict}** - see gate reasons below.")
    else:
        index = [severity.value for severity in SEVERITY_ORDER].index(fail_on)
        blockers = sum(counts.get(severity.value, 0) for severity in SEVERITY_ORDER[: index + 1])
        lines.append(f"**Gate: {verdict}** - {blockers} finding(s) at or above `{fail_on}`.")
    lines.append("")

    lines.append("| Scanner | Critical | High | Medium | Low | Info | Status |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | --- |")
    for result in report.results:
        scanner_counts = result.counts()
        lines.append(
            "| {scanner} | {critical} | {high} | {medium} | {low} | {info} | {status} |".format(
                scanner=_cell(result.scanner, 40),
                critical=scanner_counts.get("critical", 0),
                high=scanner_counts.get("high", 0),
                medium=scanner_counts.get("medium", 0),
                low=scanner_counts.get("low", 0),
                info=scanner_counts.get("info", 0),
                status=_status(result),
            )
        )
    lines.append("")
    lines.append(
        "Totals: **{critical} critical**, **{high} high**, **{medium} medium**, "
        "**{low} low**, **{info} info**.".format(
            critical=counts.get("critical", 0),
            high=counts.get("high", 0),
            medium=counts.get("medium", 0),
            low=counts.get("low", 0),
            info=counts.get("info", 0),
        )
    )
    lines.append("")

    if gate and gate.reasons:
        lines.append("### Gate reasons")
        lines.append("")
        for reason in gate.reasons:
            lines.append(f"- {_cell(reason)}")
        lines.append("")

    if gate and gate.stale_allowances:
        lines.append("### Stale or expired allowances")
        lines.append("")
        for stale in gate.stale_allowances:
            lines.append(f"- Allowance #{stale.index}: {_cell(stale.reason)}")
        lines.append("")

    if report.baseline is not None:
        baseline = report.baseline
        lines.append("### Baseline")
        lines.append("")
        lines.append(
            f"{len(baseline.new)} new, {len(baseline.fixed)} fixed, "
            f"{len(baseline.existing)} existing finding(s) against a baseline of "
            f"{baseline.baseline_total}."
        )
        lines.append("")

    for result in report.results:
        findings = [finding for finding in result.findings if not finding.suppressed]
        summary = _status(result)
        lines.append("<details>")
        lines.append(
            f"<summary><strong>{escape_html(result.scanner)}</strong> - {escape_html(summary)}"
            f" ({result.elapsed:.2f}s)</summary>"
        )
        lines.append("")
        if result.error:
            lines.append(f"Scanner error: {_cell(result.error)}")
            lines.append("")
        if result.skipped:
            lines.append(f"Skipped: {_cell(result.skip_reason or 'not applicable')}")
            lines.append("")
        if findings:
            lines.append("| Severity | Rule | Location | Finding |")
            lines.append("| --- | --- | --- | --- |")
            for finding in findings[:max_findings]:
                location = finding.location
                lines.append(
                    f"| {LEVEL_LABEL[finding.severity]} | {_cell(finding.rule_id, 60)} | <code>{_cell(location, 200)}</code> | {_cell(finding.message)} |"
                )
            if len(findings) > max_findings:
                lines.append("")
                lines.append(f"{len(findings) - max_findings} additional finding(s) omitted.")
        elif not result.error and not result.skipped:
            lines.append("No findings.")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    if artifacts:
        lines.append("### Artifacts")
        lines.append("")
        for artifact in artifacts:
            lines.append(f"- `{_cell(artifact, 200)}`")
        lines.append("")

    lines.append(
        f"<sub>pipelineguard {__version__} - secrets, dependencies, SBOM and CI configuration "
        f"in one gate.</sub>"
    )
    return "\n".join(lines).rstrip() + "\n"


def write(
    report: ScanReport,
    path: Path,
    artifacts: list[str] | None = None,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(report, artifacts=artifacts), encoding="utf-8")
    return path
