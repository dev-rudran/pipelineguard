"""Human readable console output with optional ANSI color."""

from __future__ import annotations

from ..models import SEVERITY_ORDER, ScanReport, Severity

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
BRIGHT_RED = "\033[91m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GREY = "\033[90m"
GREEN = "\033[32m"

SEVERITY_COLOR = {
    Severity.CRITICAL: BRIGHT_RED,
    Severity.HIGH: RED,
    Severity.MEDIUM: YELLOW,
    Severity.LOW: CYAN,
    Severity.INFO: GREY,
}

MAX_FINDINGS_PER_SCANNER = 100


def _paint(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{RESET}" if enabled else text


def _pad(value: str, width: int, align: str = "left") -> str:
    if align == "right":
        return value.rjust(width)
    return value.ljust(width)


def render(
    report: ScanReport,
    color: bool = True,
    quiet: bool = False,
    stats: bool = False,
) -> str:
    gate = report.gate
    lines: list[str] = []
    if quiet:
        if gate is None:
            lines.append("pipelineguard: gate not evaluated")
        else:
            status = "PASS" if gate.passed else "FAIL"
            lines.append(f"pipelineguard: {status}")
            if not gate.passed:
                for reason in gate.reasons:
                    lines.append(f"  - {reason}")
        return "\n".join(lines) + "\n"

    lines.append(
        _paint(f"pipelineguard {report.tool_version}", BOLD, color) + f"  target: {report.target}"
    )
    if report.history_mode:
        lines.append(_paint("mode: workspace + git history", DIM, color))
    if report.staged_mode:
        lines.append(_paint("mode: staged changes only", DIM, color))
    lines.append("")

    for result in report.results:
        counts = result.counts()
        total = sum(counts.values())
        header = f"{result.scanner}  ({total} finding(s), {result.elapsed:.2f}s)"
        lines.append(_paint(header, BOLD, color))
        if result.error:
            lines.append(f"  {_paint('ERROR', RED, color)} {result.error}")
        elif result.skipped:
            lines.append(
                f"  {_paint('SKIPPED', GREY, color)} {result.skip_reason or 'not applicable'}"
            )
        if not result.findings:
            if not result.error and not result.skipped:
                lines.append(f"  {_paint('clean', GREEN, color)}")
        else:
            findings = [finding for finding in result.findings if not finding.suppressed]
            for finding in findings[:MAX_FINDINGS_PER_SCANNER]:
                severity_label = finding.severity.value.upper().ljust(8)
                colored = _paint(severity_label, SEVERITY_COLOR[finding.severity], color)
                lines.append(f"  {colored} {finding.rule_id:<14} {finding.location}")
                lines.append(f"           {finding.message}")
                if finding.snippet:
                    lines.append(f"           {_paint(finding.snippet, DIM, color)}")
            if len(findings) > MAX_FINDINGS_PER_SCANNER:
                lines.append(
                    f"           {len(findings) - MAX_FINDINGS_PER_SCANNER} more finding(s) omitted"
                )
            suppressed = [finding for finding in result.findings if finding.suppressed]
            if suppressed:
                lines.append(f"  {len(suppressed)} finding(s) suppressed by policy")
        if stats and result.metadata:
            details = ", ".join(
                f"{key}={value}"
                for key, value in sorted(result.metadata.items())
                if not isinstance(value, (list, dict))
            )
            if details:
                lines.append(f"  {_paint(details, DIM, color)}")
        lines.append("")

    counts = gate.counts if gate else report.counts()
    columns = ["Scanner", *[severity.value.capitalize() for severity in SEVERITY_ORDER], "Total"]
    rows: list[list[str]] = []
    for result in report.results:
        scanner_counts = result.counts()
        row = [result.scanner]
        row.extend(str(scanner_counts.get(severity.value, 0)) for severity in SEVERITY_ORDER)
        row.append(str(sum(scanner_counts.values())))
        rows.append(row)
    totals = ["Total"]
    totals.extend(str(counts.get(severity.value, 0)) for severity in SEVERITY_ORDER)
    totals.append(str(sum(counts.values())))

    widths = [len(column) for column in columns]
    for row in [*rows, totals]:
        widths = [max(width, len(value)) for width, value in zip(widths, row, strict=False)]

    lines.append(_paint("Summary", BOLD, color))
    header = (
        "  ".join(
            _pad(column, width) for column, width in zip(columns[:-1], widths[:-1], strict=False)
        )
        + "  "
        + _pad(columns[-1], widths[-1], "right")
    )
    lines.append(header)
    lines.append("  ".join("-" * width for width in widths))
    for row in rows:
        rendered = (
            "  ".join(
                _pad(value, width) for value, width in zip(row[:-1], widths[:-1], strict=False)
            )
            + "  "
            + _pad(row[-1], widths[-1], "right")
        )
        lines.append(rendered)
    lines.append("  ".join("-" * width for width in widths))
    rendered_totals = (
        "  ".join(
            _pad(value, width) for value, width in zip(totals[:-1], widths[:-1], strict=False)
        )
        + "  "
        + _pad(totals[-1], widths[-1], "right")
    )
    lines.append(_paint(rendered_totals, BOLD, color))
    lines.append("")

    if gate is None:
        lines.append(_paint("Gate: not evaluated", BOLD, color))
    elif gate.passed:
        lines.append(_paint("Gate: PASS", GREEN + BOLD, color))
    else:
        lines.append(_paint("Gate: FAIL", RED + BOLD, color))
        for reason in gate.reasons:
            lines.append(f"  - {reason}")
    if gate and gate.stale_allowances:
        for stale in gate.stale_allowances:
            lines.append(
                _paint(f"  warning: allowance #{stale.index} {stale.reason}", YELLOW, color)
            )
    lines.append(
        _paint(
            f"Run finished in {report.elapsed:.2f}s with policy fail_on="
            f"{gate.fail_on.value if gate and gate.fail_on else 'none'}",
            DIM,
            color,
        )
    )
    return "\n".join(lines) + "\n"
